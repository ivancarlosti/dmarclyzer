"""Security helpers shared by the fetcher, parser, models and dashboard.

This module intentionally imports **only the Python standard library** so the
helpers can be unit-tested without Streamlit, SQLAlchemy or pandas installed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import ipaddress
import os
import re
import secrets
import time
from datetime import datetime
from urllib.parse import urlsplit

__all__ = [
    "OversizedPayloadError",
    "bounded_read",
    "constant_time_equals",
    "derive_pkce_verifier",
    "env_int",
    "escape_html",
    "escape_markdown",
    "is_safe_hex_color",
    "is_safe_index_name",
    "is_valid_ip",
    "pkce_challenge",
    "quote_mailbox",
    "safe_int",
    "safe_timestamp",
    "sign_state",
    "truncate",
    "validate_issuer_url",
    "validate_mailbox",
    "validate_redirect_uri",
    "verify_state",
]

# Signed login states are short lived; the caller can lower the value but the
# upper bound keeps a stolen URL from being replayable for long.
STATE_TTL_SECONDS_DEFAULT = 300
STATE_TTL_SECONDS_MIN = 60
STATE_TTL_SECONDS_MAX = 3600
# Tolerated clock skew between the signer and the verifier.
_CLOCK_SKEW_SECONDS = 60
# 2100-01-01T00:00:00Z — report timestamps outside this range are nonsense.
_MAX_TIMESTAMP = 4102444800

_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_MARKDOWN_SPECIAL_RE = re.compile(r"([\\`*_{}\[\]()#+\-.!|>~])")
_INDEX_NAME_RE = re.compile(r"^[A-Za-z0-9_$]+$")


class OversizedPayloadError(ValueError):
    """Raised when an attachment/report exceeds the configured size budget."""


# ── Output encoding ─────────────────────────────────────────────────────────


def escape_html(value) -> str:
    """Escape *value* for safe interpolation into an HTML document."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def escape_markdown(value) -> str:
    """Escape Markdown control characters in untrusted report metadata."""
    if value is None:
        return ""
    return _MARKDOWN_SPECIAL_RE.sub(r"\\\1", str(value))


def is_safe_hex_color(value) -> bool:
    """Return True when *value* is a plain CSS hex colour (no CSS injection)."""
    return bool(value) and bool(_HEX_COLOR_RE.match(str(value)))


# ── Input coercion ──────────────────────────────────────────────────────────


def truncate(value, max_length: int = 255, default=None):
    """Coerce *value* to a string and cut it to the database column width."""
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    return text[:max_length]


def safe_int(value, default: int = 0, minimum: int | None = None,
             maximum: int | None = None) -> int:
    """Parse *value* as an int, returning *default* on failure.

    Successful parses are clamped into ``[minimum, maximum]`` so untrusted XML
    cannot inject out-of-range values (for example ``pct=999999``).
    """
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if minimum is not None and parsed < minimum:
        return minimum
    if maximum is not None and parsed > maximum:
        return maximum
    return parsed


def env_int(name: str, default: int, minimum: int | None = None,
            maximum: int | None = None) -> int:
    """Read an integer environment variable with clamping and a safe default."""
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    return safe_int(raw, default=default, minimum=minimum, maximum=maximum)


def safe_timestamp(value, default=None):
    """Convert a DMARC epoch value to a naive ``datetime`` safely.

    DMARC reports are stored as naive local datetimes throughout the app; the
    only guarantees required here are that the value is numeric, in range and
    cannot raise ``OverflowError``/``OSError`` and abort the whole fetch cycle.
    """
    try:
        timestamp = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if timestamp < 0 or timestamp > _MAX_TIMESTAMP:
        return default
    try:
        return datetime.fromtimestamp(timestamp)
    except (OverflowError, OSError, ValueError):
        return default


def is_valid_ip(value) -> bool:
    """Return True when *value* is a real IPv4/IPv6 address (not a hostname)."""
    if value is None:
        return False
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def constant_time_equals(candidate, expected) -> bool:
    """Compare two secrets without leaking their contents through timing."""
    if candidate is None or expected is None:
        return False
    return hmac.compare_digest(
        str(candidate).encode("utf-8"), str(expected).encode("utf-8")
    )


# ── URL validation ──────────────────────────────────────────────────────────


def validate_issuer_url(url, allow_insecure: bool = False) -> bool:
    """Validate an OIDC issuer base URL.

    HTTPS is required unless *allow_insecure* is explicitly enabled (loopback
    development only). Credentials in the URL are always rejected because they
    would be logged or rendered in the login link.
    """
    if not url:
        return False
    try:
        parsed = urlsplit(str(url))
    except ValueError:
        return False
    if parsed.username or parsed.password:
        return False
    if parsed.query or parsed.fragment:
        return False
    if not parsed.netloc:
        return False
    if parsed.scheme == "https":
        return True
    return bool(allow_insecure and parsed.scheme == "http")


def validate_redirect_uri(uri, allow_insecure: bool = False) -> bool:
    """Validate the OAuth2 redirect URI configured for the client."""
    if not uri:
        return False
    try:
        parsed = urlsplit(str(uri))
    except ValueError:
        return False
    if not parsed.netloc:
        return False
    if parsed.scheme == "https":
        return True
    return bool(allow_insecure and parsed.scheme == "http")


# ── IMAP mailbox handling ───────────────────────────────────────────────────


def validate_mailbox(name) -> str:
    """Validate an IMAP mailbox name.

    Rejects CR/LF/NUL so a misconfigured value cannot terminate the IMAP
    command and inject a second one.
    """
    if not isinstance(name, str):
        raise ValueError("mailbox name must be a string")
    name = name.strip()
    if not name or len(name) > 255:
        raise ValueError("mailbox name must be 1-255 characters")
    if any(char in name for char in ("\r", "\n", "\0")):
        raise ValueError("mailbox name contains control characters")
    return name


def quote_mailbox(name) -> str:
    """Return a quoted, escaped IMAP mailbox string ready for `imaplib`."""
    validated = validate_mailbox(name)
    escaped = validated.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# ── Bounded reads ───────────────────────────────────────────────────────────


def bounded_read(fileobj, max_bytes: int) -> bytes:
    """Read at most *max_bytes* from *fileobj*, raising if it is larger.

    Decompresses incrementally, so a compression bomb cannot force the process
    to allocate the full uncompressed payload before being rejected.
    """
    if max_bytes <= 0:
        raise OversizedPayloadError("size limit must be positive")
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = fileobj.read(min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise OversizedPayloadError(
            f"payload exceeds the {max_bytes} byte limit"
        )
    return data


# ── Signed OIDC state + PKCE ────────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _state_signature(secret: str, payload: str) -> bytes:
    return hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).digest()


def sign_state(secret: str, ttl_seconds: int = STATE_TTL_SECONDS_DEFAULT,
               now: int | None = None, nonce: str | None = None) -> str:
    """Create a signed, timestamped OIDC ``state`` value.

    Format: ``<issued-at>.<nonce>.<hmac>``. The timestamp lets the verifier
    reject stale callbacks; the nonce provides uniqueness and is also used to
    derive the PKCE code verifier.
    """
    if not secret:
        raise ValueError("an HMAC secret is required to sign OIDC state")
    issued_at = int(time.time() if now is None else now)
    state_nonce = nonce or secrets.token_urlsafe(24)
    if "." in state_nonce or not state_nonce:
        raise ValueError("invalid state nonce")
    payload = f"{issued_at}.{state_nonce}"
    return f"{payload}.{_b64url_encode(_state_signature(secret, payload))}"


def verify_state(secret: str, state, ttl_seconds: int = STATE_TTL_SECONDS_DEFAULT,
                 now: int | None = None) -> str | None:
    """Validate a signed OIDC ``state`` and return its nonce (or ``None``)."""
    if not secret or not state:
        return None
    parts = str(state).split(".")
    if len(parts) != 3:
        return None
    issued_raw, state_nonce, signature_raw = parts
    try:
        issued_at = int(issued_raw)
        provided_signature = _b64url_decode(signature_raw)
    except (TypeError, ValueError, binascii.Error):
        return None
    if not state_nonce or "." in state_nonce:
        return None
    expected_signature = _state_signature(secret, f"{issued_at}.{state_nonce}")
    if not hmac.compare_digest(expected_signature, provided_signature):
        return None
    current = int(time.time() if now is None else now)
    if issued_at > current + _CLOCK_SKEW_SECONDS:
        return None
    if current - issued_at > max(int(ttl_seconds), 0):
        return None
    return state_nonce


def derive_pkce_verifier(secret: str, state_nonce: str) -> str:
    """Derive a deterministic PKCE verifier from the signed-state nonce.

    The verifier must be available again when the provider redirects back, but
    Streamlit discards ``session_state`` on a full-page navigation. Deriving it
    from the HMAC secret plus the *already validated* nonce keeps PKCE working
    without server-side storage, while an attacker cannot compute it.
    """
    if not secret or not state_nonce:
        raise ValueError("secret and nonce are required for PKCE derivation")
    digest = hmac.new(
        secret.encode("utf-8"),
        f"pkce.{state_nonce}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def pkce_challenge(verifier: str) -> str:
    """Return the S256 PKCE challenge for *verifier*."""
    if not verifier:
        raise ValueError("a PKCE verifier is required")
    return _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def is_safe_index_name(name) -> bool:
    """Return True when an SQL identifier is safe to interpolate."""
    return bool(name) and bool(_INDEX_NAME_RE.match(str(name)))
