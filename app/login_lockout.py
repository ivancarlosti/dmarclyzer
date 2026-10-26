"""Server-side account-login lockout.

Failed attempts are counted per username and, when a client address can be
determined without trusting a spoofable header, per client IP. The counters
live in the application database (see :class:`DatabaseAttemptStore`) so a new
browser session or a page reload cannot reset them.

The decision of *when* a counter locks is pure (:func:`evaluate_failure`).
Stores only load and save that result, which keeps the MariaDB adapter and
the in-memory adapter used by tests on the same rules.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from typing import NamedTuple

logger = logging.getLogger(__name__)

SUBJECT_USER = "user"
SUBJECT_IP = "ip"

# 7 days. Long enough for an operator to slow down guessing, short enough
# that a lock on the one configured username cannot last indefinitely.
MAX_LOCKOUT_SECONDS = 7 * 24 * 60 * 60
DEFAULT_LOCKOUT_SECONDS = 900


class Attempt(NamedTuple):
    """One subject's failure counter inside a single lockout window."""

    failures: int
    window_started: int
    locked_until: int | None


def evaluate_failure(
    current: Attempt | None,
    now: int,
    max_attempts: int,
    window: int,
) -> Attempt:
    """Return the counter after one more failed attempt at ``now``.

    Failures older than ``window`` are forgotten. Reaching ``max_attempts``
    locks the subject until ``now + window``. Further failures during an
    active lock do not extend it, so a client cannot hold the lock open by
    continuing to guess. An expired lock starts again at one failure.
    """
    if max_attempts < 1:
        max_attempts = 1
    if window < 1:
        window = 1

    if (
        current is not None
        and current.locked_until is not None
        and current.locked_until > now
    ):
        return current

    expired = (
        current is None
        or current.window_started + window <= now
        or (current.locked_until is not None and current.locked_until <= now)
    )
    if expired or current is None:
        return Attempt(
            failures=1,
            window_started=now,
            locked_until=(now + window) if max_attempts <= 1 else None,
        )

    failures = current.failures + 1
    locked_until = (now + window) if failures >= max_attempts else None
    return Attempt(
        failures=failures,
        window_started=current.window_started,
        locked_until=locked_until,
    )


def _key(kind: str, subject: str) -> tuple[str, str]:
    """Fit a counter identity into the ``login_attempts`` column widths."""
    return (str(kind)[:16], str(subject)[:255])


def username_subject(username) -> str:
    """Normalize a submitted username into a stable counter key.

    The configured account is a single secret compared in constant time, but
    the counter is keyed by whatever was typed. Unknown names therefore lock
    on the same schedule as the real one, and the response does not reveal
    which names exist. Matching is case-insensitive so ``Admin`` and ``admin``
    share a bucket; the password comparison itself stays case-sensitive.
    """
    if not isinstance(username, str):
        text = ""
    else:
        text = username.replace("\x00", "").strip().casefold()
    return text[:255]


def _normalize_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """Collapse an IPv4-mapped IPv6 address to IPv4 so keys stay stable."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _parse_ip(value: str | None):
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text.lower() == "unknown":
        return None
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1 and "." in text:
        text = text.split(":", 1)[0].strip()
    try:
        return _normalize_ip(ipaddress.ip_address(text))
    except ValueError:
        return None


def _is_routable_client(addr) -> bool:
    """True for a globally routable unicast address Streamlit saw directly.

    Private, loopback, link-local and documentation ranges are rejected here.
    Behind a reverse proxy the TCP peer is the proxy, which is almost always
    one of those, and treating it as the client would lock every user together.
    """
    return not (
        addr.is_multicast
        or addr.is_unspecified
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or not addr.is_global
    )


def _is_proxied_client(addr) -> bool:
    """True for an address a trusted proxy may report as the real client.

    Private addresses are allowed: users on a corporate LAN present one.
    Loopback, link-local, multicast and reserved addresses are not a client.
    """
    return not (
        addr.is_multicast
        or addr.is_unspecified
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
    )


def _trusted_networks(raw: str | None) -> tuple:
    if not isinstance(raw, str) or not raw.strip():
        return ()
    networks = []
    for index, item in enumerate(raw.split(","), start=1):
        item = item.strip()
        if not item:
            continue
        try:
            if "/" in item:
                networks.append(ipaddress.ip_network(item, strict=False))
            else:
                addr = ipaddress.ip_address(item)
                networks.append(
                    ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
                )
        except ValueError:
            # The entry itself is configuration and may be an address. Log
            # where it sat in the list, never its contents.
            logger.warning(
                "Ignoring invalid LOGIN_TRUSTED_PROXIES entry at position %s.",
                index,
            )
    return tuple(networks)


def _in_networks(addr, networks) -> bool:
    for network in networks:
        if addr.version != network.version:
            continue
        if addr in network:
            return True
    return False


def _forwarded_clients(header: str | None):
    if not isinstance(header, str) or not header.strip():
        return
    for part in header.split(","):
        addr = _parse_ip(part)
        if addr is not None:
            yield addr


def resolve_client_ip(
    peer: str | None,
    forwarded_for: str | None,
    trusted_proxies: str | None,
    real_ip: str | None = None,
) -> str | None:
    """Return the client IP to count, or None when it cannot be known safely.

    ``st.context.ip_address`` is the TCP peer (Starlette ``client.host``). It
    is not taken from ``X-Forwarded-For``. Those headers are client-controlled
    unless the peer itself is a proxy the operator listed in
    ``LOGIN_TRUSTED_PROXIES``.

    When the peer is trusted, the client is the rightmost forwarded address
    that is not itself a trusted proxy (the address the nearest trusted proxy
    actually observed). ``X-Real-IP`` is consulted only if that walk finds
    nothing. A peer that is not in the trusted list never contributes the
    header, so a direct client cannot pick a fresh bucket per guess.
    """
    networks = _trusted_networks(trusted_proxies)
    peer_addr = _parse_ip(peer)
    peer_is_trusted = peer_addr is not None and _in_networks(peer_addr, networks)

    if peer_is_trusted:
        for addr in reversed(list(_forwarded_clients(forwarded_for))):
            if not _is_proxied_client(addr) or _in_networks(addr, networks):
                continue
            return str(addr)
        real_addr = _parse_ip(real_ip)
        if (
            real_addr is not None
            and _is_proxied_client(real_addr)
            and not _in_networks(real_addr, networks)
        ):
            return str(real_addr)
        return None

    if peer_addr is None or not _is_routable_client(peer_addr):
        return None
    return str(peer_addr)


class MemoryAttemptStore:
    """Process-local store with the same rules as :class:`DatabaseAttemptStore`.

    Tests use it so the suite stays free of SQLAlchemy. Production login uses
    the database store; a fresh browser session still shares that database.
    """

    def __init__(self):
        self._rows: dict[tuple[str, str], Attempt] = {}
        self._lock = threading.Lock()

    def lock_expiry(self, kind: str, subject: str, now: int) -> int | None:
        kind, subject = _key(kind, subject)
        with self._lock:
            current = self._rows.get((kind, subject))
            if current is None or current.locked_until is None:
                return None
            if current.locked_until > now:
                return current.locked_until
            return None

    def record_failure(
        self,
        kind: str,
        subject: str,
        now: int,
        max_attempts: int,
        window: int,
    ) -> Attempt:
        kind, subject = _key(kind, subject)
        with self._lock:
            updated = evaluate_failure(
                self._rows.get((kind, subject)), now, max_attempts, window
            )
            self._rows[(kind, subject)] = updated
            return updated

    def clear(self, kind: str, subject: str) -> None:
        kind, subject = _key(kind, subject)
        with self._lock:
            self._rows.pop((kind, subject), None)


class DatabaseAttemptStore:
    """Persist lockout counters in the application's SQL database.

    A session is opened per call so concurrent Streamlit sessions cannot share
    a transaction. On MariaDB the row is locked with ``SELECT ... FOR UPDATE``
    so two overlapping failures cannot both read the same count. SQLite (used
    when exercising this class in tests) has no row locks; its writer lock
    serializes the transaction instead.
    """

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        self._schema_ready = False

    def _session(self):
        if self._session_factory is not None:
            return self._session_factory()
        from sqlalchemy.orm import sessionmaker

        from models import get_engine

        return sessionmaker(bind=get_engine())()

    def _ensure_schema(self) -> None:
        if self._schema_ready:
            return
        from models import LoginAttempt

        session = self._session()
        try:
            LoginAttempt.__table__.create(bind=session.get_bind(), checkfirst=True)
            session.commit()
            self._schema_ready = True
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _select(self, session, model, kind: str, subject: str, for_update: bool):
        query = session.query(model).filter_by(subject_kind=kind, subject=subject)
        if for_update:
            bind = session.get_bind()
            if bind is not None and getattr(bind.dialect, "name", "") != "sqlite":
                query = query.with_for_update()
        return query.one_or_none()

    @staticmethod
    def _to_attempt(row) -> Attempt | None:
        if row is None:
            return None
        locked = None if row.locked_until is None else int(row.locked_until)
        return Attempt(int(row.failures), int(row.window_started), locked)

    def lock_expiry(self, kind: str, subject: str, now: int) -> int | None:
        self._ensure_schema()
        kind, subject = _key(kind, subject)
        from models import LoginAttempt

        session = self._session()
        try:
            row = self._select(session, LoginAttempt, kind, subject, for_update=False)
            current = self._to_attempt(row)
            if current is None or current.locked_until is None:
                return None
            if current.locked_until > now:
                return current.locked_until
            return None
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def record_failure(
        self,
        kind: str,
        subject: str,
        now: int,
        max_attempts: int,
        window: int,
    ) -> Attempt:
        self._ensure_schema()
        kind, subject = _key(kind, subject)
        from sqlalchemy.exc import IntegrityError

        from models import LoginAttempt

        last_error: Exception | None = None
        for _ in range(2):
            session = self._session()
            try:
                row = self._select(
                    session, LoginAttempt, kind, subject, for_update=True
                )
                updated = evaluate_failure(
                    self._to_attempt(row), now, max_attempts, window
                )
                if row is None:
                    session.add(
                        LoginAttempt(
                            subject_kind=kind,
                            subject=subject,
                            failures=updated.failures,
                            window_started=updated.window_started,
                            locked_until=updated.locked_until,
                        )
                    )
                else:
                    row.failures = updated.failures
                    row.window_started = updated.window_started
                    row.locked_until = updated.locked_until
                session.commit()
                return updated
            except IntegrityError as exc:
                session.rollback()
                last_error = exc
                continue
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
        assert last_error is not None
        raise last_error

    def clear(self, kind: str, subject: str) -> None:
        self._ensure_schema()
        kind, subject = _key(kind, subject)
        from models import LoginAttempt

        session = self._session()
        try:
            session.query(LoginAttempt).filter_by(
                subject_kind=kind, subject=subject
            ).delete(synchronize_session=False)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
