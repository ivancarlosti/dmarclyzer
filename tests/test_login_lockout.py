"""Server-side account-login lockout.

The suite stays on the standard library. ``MemoryAttemptStore`` exercises the
rules Streamlit actually calls; ``DatabaseAttemptStore`` runs the same
scenarios against SQLite when SQLAlchemy is installed, which is the adapter
that talks to MariaDB in production.
"""

import os
import sys
import types
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"
    ),
)

streamlit_stub = types.ModuleType("streamlit")
streamlit_stub.session_state = {}
streamlit_stub.query_params = {}
streamlit_stub.error = lambda *args, **kwargs: None
streamlit_stub.markdown = lambda *args, **kwargs: None
streamlit_stub.title = lambda *args, **kwargs: None
streamlit_stub.caption = lambda *args, **kwargs: None
streamlit_stub.rerun = lambda *args, **kwargs: None
streamlit_stub.columns = lambda spec: []
streamlit_stub.stop = lambda *args, **kwargs: None
streamlit_stub.html = lambda *args, **kwargs: None


class _FakeContext:
    def __init__(self, cookies=None, headers=None):
        self.cookies = dict(cookies or {})
        self.headers = dict(headers or {})
        self.ip_address = None


streamlit_stub.context = _FakeContext()
sys.modules.setdefault("streamlit", streamlit_stub)

try:  # pragma: no cover - depends on the environment
    import requests  # noqa: F401
except ImportError:  # pragma: no cover
    requests_stub = types.ModuleType("requests")

    class _RequestException(Exception):
        pass

    requests_stub.RequestException = _RequestException
    requests_stub.Session = object
    sys.modules.setdefault("requests", requests_stub)

import auth  # noqa: E402
import login_lockout  # noqa: E402

LOCKOUT = "Too many failed sign-in attempts. Try again later."
INVALID = "Invalid credentials."
UNAVAILABLE = "Sign-in is temporarily unavailable. Please try again."

_ACCOUNT_ENV = {
    "AUTH_METHOD": "account",
    "ACCOUNT_LOGIN": "admin",
    "ACCOUNT_PASSWORD": "correct-horse",
    "LOGIN_MAX_ATTEMPTS": "3",
    "LOGIN_LOCKOUT_SECONDS": "900",
}


class _Clock:
    def __init__(self, now=1_700_000_000):
        self.now = now

    def __call__(self):
        return self.now


class _Context:
    def __init__(self, ip=None, headers=None, cookies=None):
        self.ip_address = ip
        self.headers = {} if headers is None else dict(headers)
        self.cookies = {} if cookies is None else dict(cookies)


class _Widget:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _has_sqlalchemy():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        return False
    return True


class _LockoutScenarios:
    """Behavioral checks shared by the memory store and the database store."""

    def setUp(self):
        self.store = self.make_store()
        self.clock = _Clock()
        self.env = dict(_ACCOUNT_ENV)
        auth._login_attempt_store = self.store

    def tearDown(self):
        auth._login_attempt_store = None

    def make_store(self):
        raise NotImplementedError

    def _submit(self, session_state, username, password, ip=None, headers=None, env=None):
        errors = []
        answers = [username, password]
        cursor = {"i": 0}

        def text_input(*args, **kwargs):
            index = cursor["i"]
            cursor["i"] += 1
            return answers[index]

        context = _Context(ip=ip, headers=headers)
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.dict(
                    os.environ, self.env if env is None else env, clear=True
                )
            )
            stack.enter_context(mock.patch.object(auth, "_now", self.clock))
            stack.enter_context(
                mock.patch.object(auth.st, "session_state", session_state)
            )
            stack.enter_context(mock.patch.object(auth.st, "context", context))
            stack.enter_context(
                mock.patch.object(
                    auth.st, "columns", return_value=(_Widget(), _Widget(), _Widget())
                )
            )
            stack.enter_context(
                mock.patch.object(auth.st, "form", return_value=_Widget(), create=True)
            )
            stack.enter_context(
                mock.patch.object(auth.st, "text_input", side_effect=text_input, create=True)
            )
            stack.enter_context(
                mock.patch.object(
                    auth.st, "form_submit_button", return_value=True, create=True
                )
            )
            stack.enter_context(
                mock.patch.object(auth.st, "subheader", lambda *args, **kwargs: None, create=True)
            )
            stack.enter_context(
                mock.patch.object(auth.st, "error", side_effect=errors.append)
            )
            stack.enter_context(
                mock.patch.object(auth.st, "rerun", lambda *args, **kwargs: None)
            )
            auth.require_auth()
        return errors

    def test_lockout_persists_across_a_fresh_session(self):
        attacked = {}
        for _ in range(2):
            errors = self._submit(attacked, "admin", "wrong")
            self.assertEqual(errors, [INVALID])
        errors = self._submit(attacked, "admin", "wrong")
        self.assertEqual(errors, [LOCKOUT])

        # A brand-new browser session that explicitly says "not locked" and
        # "zero attempts" must still be refused, including with the right
        # password. Those flags are what used to live only in session_state.
        fresh = {
            auth.ATTEMPTS_SESSION_KEY: 0,
            auth.LOCKED_SESSION_KEY: False,
        }
        errors = self._submit(fresh, "admin", "correct-horse")
        self.assertEqual(errors, [LOCKOUT])
        self.assertNotIn(auth.AUTHENTICATED_KEY, fresh)
        self.assertFalse(fresh[auth.LOCKED_SESSION_KEY])
        self.assertEqual(fresh[auth.ATTEMPTS_SESSION_KEY], 0)

    def test_lockout_expires_after_the_window(self):
        for _ in range(3):
            self._submit({}, "admin", "wrong")

        self.clock.now += 900
        fresh = {}
        errors = self._submit(fresh, "admin", "correct-horse")
        self.assertEqual(errors, [])
        self.assertIs(fresh[auth.AUTHENTICATED_KEY], True)
        self.assertEqual(fresh[auth.EMAIL_SESSION_KEY], "admin")

    def test_lockout_resets_on_successful_login(self):
        self._submit({}, "admin", "wrong")
        self._submit({}, "admin", "wrong")
        signed_in = {}
        errors = self._submit(signed_in, "admin", "correct-horse")
        self.assertEqual(errors, [])
        self.assertIs(signed_in[auth.AUTHENTICATED_KEY], True)

        # Each attempt below uses its own session dict. The counter that
        # resets is the one in the store; two further failures must not lock.
        for _ in range(2):
            errors = self._submit({}, "admin", "wrong")
            self.assertEqual(errors, [INVALID])
        errors = self._submit({}, "admin", "wrong")
        self.assertEqual(errors, [LOCKOUT])


class MemoryLoginLockoutTests(_LockoutScenarios, unittest.TestCase):
    def make_store(self):
        return login_lockout.MemoryAttemptStore()

    def test_unknown_username_locks_like_the_real_one_and_does_not_block_it(self):
        intruder = self._submit({}, "intruder", "wrong")
        real = self._submit({}, "admin", "wrong-password")
        self.assertEqual(intruder, [INVALID])
        self.assertEqual(real, [INVALID])

        for _ in range(2):
            self._submit({}, "intruder", "wrong")
        locked = self._submit({}, "intruder", "correct-horse")
        self.assertEqual(locked, [LOCKOUT])

        fresh = {}
        errors = self._submit(fresh, "admin", "correct-horse")
        self.assertEqual(errors, [])
        self.assertIs(fresh[auth.AUTHENTICATED_KEY], True)

    def test_username_bucket_is_case_insensitive(self):
        self._submit({}, "Admin", "wrong")
        self._submit({}, "ADMIN", "wrong")
        errors = self._submit({}, "admin", "wrong")
        self.assertEqual(errors, [LOCKOUT])

    def test_overlong_username_is_counted_without_failing_the_request(self):
        name = "u" * 500
        self._submit({}, name, "wrong")
        self._submit({}, name, "wrong")
        errors = self._submit({}, name + "more", "wrong")
        # The stored key is truncated, so the extra suffix shares the bucket.
        self.assertEqual(errors, [LOCKOUT])

    def test_public_peer_is_counted_and_forwarded_header_is_ignored(self):
        for i in range(3):
            self._submit(
                {},
                f"user{i}",
                "wrong",
                ip="8.8.8.8",
                headers={"X-Forwarded-For": f"198.51.100.{i}"},
            )
        errors = self._submit(
            {},
            "someone-else",
            "wrong",
            ip="8.8.8.8",
            headers={"X-Forwarded-For": "1.1.1.1"},
        )
        self.assertEqual(errors, [LOCKOUT])

    def test_private_peer_and_spoofed_header_do_not_lock_other_users(self):
        for _ in range(3):
            self._submit(
                {},
                "intruder",
                "wrong",
                ip="10.0.0.5",
                headers={"X-Forwarded-For": "8.8.8.8"},
            )
        fresh = {}
        errors = self._submit(
            fresh,
            "admin",
            "correct-horse",
            ip="10.0.0.5",
            headers={"X-Forwarded-For": "1.1.1.1"},
        )
        self.assertEqual(errors, [])
        self.assertIs(fresh[auth.AUTHENTICATED_KEY], True)

    def test_trusted_proxy_counts_the_rightmost_untrusted_client(self):
        env = dict(self.env, LOGIN_TRUSTED_PROXIES="10.0.0.0/8")
        for _ in range(3):
            self._submit(
                {},
                "intruder",
                "wrong",
                ip="10.0.0.5",
                headers={"X-Forwarded-For": "1.2.3.4, 8.8.8.8"},
                env=env,
            )

        spoofed_prefix = {}
        errors = self._submit(
            spoofed_prefix,
            "admin",
            "correct-horse",
            ip="10.0.0.5",
            headers={"X-Forwarded-For": "9.9.9.9, 8.8.8.8"},
            env=env,
        )
        self.assertEqual(errors, [LOCKOUT])
        self.assertNotIn(auth.AUTHENTICATED_KEY, spoofed_prefix)

        other_client = {}
        errors = self._submit(
            other_client,
            "admin",
            "correct-horse",
            ip="10.0.0.5",
            headers={"X-Forwarded-For": "1.1.1.1"},
            env=env,
        )
        self.assertEqual(errors, [])
        self.assertIs(other_client[auth.AUTHENTICATED_KEY], True)

    def test_recaptcha_failure_does_not_increment_or_clear_the_counter(self):
        env = dict(self.env, RECAPTCHA_CLIENTSECRET="secret")
        session = {}
        with mock.patch.object(auth, "_verify_recaptcha", return_value=False) as verify:
            errors = self._submit(session, "admin", "correct-horse", env=env)
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(errors, ["reCAPTCHA verification failed. Please try again."])
        self.assertNotIn(auth.AUTHENTICATED_KEY, session)

        with mock.patch.object(auth, "_verify_recaptcha", return_value=True) as verify:
            errors = self._submit({}, "admin", "wrong", env=env)
        self.assertEqual(verify.call_count, 0)
        self.assertEqual(errors, [INVALID])

        errors = self._submit({}, "admin", "wrong")
        self.assertEqual(errors, [INVALID])
        errors = self._submit({}, "admin", "wrong")
        self.assertEqual(errors, [LOCKOUT])

    def test_locked_username_is_refused_before_accepting_the_password(self):
        calls = []

        def compare(candidate, expected):
            calls.append(candidate)
            return candidate == expected

        self.store.record_failure(
            login_lockout.SUBJECT_USER,
            login_lockout.username_subject("admin"),
            self.clock.now,
            1,
            900,
        )
        session = {}
        with mock.patch.object(auth, "constant_time_equals", side_effect=compare):
            errors = self._submit(session, "admin", "correct-horse")
        self.assertEqual(calls, ["admin", "correct-horse"])
        self.assertEqual(errors, [LOCKOUT])
        self.assertNotIn(auth.AUTHENTICATED_KEY, session)

    def test_store_outage_fails_closed_without_signing_in(self):
        class _Broken:
            def lock_expiry(self, *args, **kwargs):
                raise RuntimeError("database offline")

            def record_failure(self, *args, **kwargs):
                raise RuntimeError("database offline")

            def clear(self, *args, **kwargs):
                raise RuntimeError("database offline")

        auth._login_attempt_store = _Broken()
        session = {}
        errors = self._submit(session, "admin", "correct-horse")
        self.assertEqual(errors, [UNAVAILABLE])
        self.assertNotIn(auth.AUTHENTICATED_KEY, session)

    def test_clear_failure_after_a_good_password_still_signs_in(self):
        class _ClearFails(login_lockout.MemoryAttemptStore):
            def clear(self, *args, **kwargs):
                raise RuntimeError("delete failed")

        auth._login_attempt_store = _ClearFails()
        session = {}
        errors = self._submit(session, "admin", "correct-horse")
        self.assertEqual(errors, [])
        self.assertIs(session[auth.AUTHENTICATED_KEY], True)


@unittest.skipUnless(_has_sqlalchemy(), "SQLAlchemy is not installed")
class DatabaseLoginLockoutTests(_LockoutScenarios, unittest.TestCase):
    def make_store(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from models import Base

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        self.addCleanup(engine.dispose)
        self.Session = sessionmaker(bind=engine)
        self.assertIn("login_attempts", Base.metadata.tables)
        return login_lockout.DatabaseAttemptStore(session_factory=self.Session)

    def test_counter_survives_a_new_store_bound_to_the_same_database(self):
        subject = login_lockout.username_subject("admin")
        now = self.clock.now
        for _ in range(3):
            self.store.record_failure(
                login_lockout.SUBJECT_USER, subject, now, 3, 900
            )
        other = login_lockout.DatabaseAttemptStore(session_factory=self.Session)
        self.assertEqual(
            other.lock_expiry(login_lockout.SUBJECT_USER, subject, now),
            now + 900,
        )
        other.clear(login_lockout.SUBJECT_USER, subject)
        self.assertIsNone(
            self.store.lock_expiry(login_lockout.SUBJECT_USER, subject, now)
        )


class PolicyTests(unittest.TestCase):
    def test_failures_accumulate_until_the_window_then_reset(self):
        first = login_lockout.evaluate_failure(None, 1_000, 3, 10)
        second = login_lockout.evaluate_failure(first, 1_009, 3, 10)
        self.assertEqual(second.failures, 2)
        self.assertIsNone(second.locked_until)

        locked = login_lockout.evaluate_failure(second, 1_009, 3, 10)
        self.assertEqual(locked.failures, 3)
        self.assertEqual(locked.locked_until, 1_019)

        held = login_lockout.evaluate_failure(locked, 1_018, 3, 10)
        self.assertEqual(held, locked)

        restarted = login_lockout.evaluate_failure(locked, 1_019, 3, 10)
        self.assertEqual(restarted.failures, 1)
        self.assertIsNone(restarted.locked_until)
        self.assertEqual(restarted.window_started, 1_019)

    def test_username_subject_normalizes_without_growing_past_the_column(self):
        self.assertEqual(
            login_lockout.username_subject(" Admin "),
            login_lockout.username_subject("admin"),
        )
        self.assertEqual(login_lockout.username_subject("a\x00b"), "ab")
        self.assertEqual(login_lockout.username_subject(None), "")
        self.assertEqual(login_lockout.username_subject("   "), "")
        self.assertEqual(len(login_lockout.username_subject("u" * 500)), 255)


class ClientIpTests(unittest.TestCase):
    def test_globally_routable_peer_is_used_and_forwarded_header_is_not(self):
        self.assertEqual(
            login_lockout.resolve_client_ip(
                "8.8.8.8", "1.1.1.1", None, real_ip="9.9.9.9"
            ),
            "8.8.8.8",
        )

    def test_mapped_ipv6_peer_collapses_to_ipv4(self):
        self.assertEqual(
            login_lockout.resolve_client_ip("::ffff:8.8.8.8", None, None),
            "8.8.8.8",
        )

    def test_expanded_ipv6_is_stored_in_canonical_form(self):
        self.assertEqual(
            login_lockout.resolve_client_ip(
                "2001:4860:4860:0:0:0:0:8888", None, None
            ),
            "2001:4860:4860::8888",
        )

    def test_private_loopback_and_multicast_peers_are_not_clients(self):
        for peer in ("10.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", None, ""):
            self.assertIsNone(
                login_lockout.resolve_client_ip(peer, "8.8.8.8", None),
                peer,
            )

    def test_trusted_proxy_keeps_the_rightmost_untrusted_address(self):
        resolved = login_lockout.resolve_client_ip(
            "10.0.0.5",
            "1.2.3.4, 8.8.8.8, 10.0.0.5",
            "10.0.0.0/8",
            real_ip="9.9.9.9",
        )
        self.assertEqual(resolved, "8.8.8.8")

    def test_trusted_proxy_falls_back_to_x_real_ip(self):
        self.assertEqual(
            login_lockout.resolve_client_ip(
                "10.0.0.5", None, "10.0.0.0/8", real_ip="1.1.1.1"
            ),
            "1.1.1.1",
        )

    def test_unlisted_peer_does_not_become_trusted_because_the_header_says_so(self):
        self.assertEqual(
            login_lockout.resolve_client_ip(
                "8.8.8.8", "1.1.1.1", "10.0.0.0/8"
            ),
            "8.8.8.8",
        )

    def test_invalid_proxy_entry_is_ignored(self):
        self.assertEqual(
            login_lockout.resolve_client_ip(
                "10.0.0.5", "8.8.8.8", "not-a-cidr, 10.0.0.0/99, 10.0.0.0/8"
            ),
            "8.8.8.8",
        )

    def test_bracketed_ipv6_and_ipv4_port_are_parsed(self):
        self.assertEqual(
            login_lockout.resolve_client_ip(
                "10.0.0.5",
                "[2001:4860:4860::8888]:443",
                "10.0.0.0/8",
            ),
            "2001:4860:4860::8888",
        )
        self.assertEqual(
            login_lockout.resolve_client_ip("8.8.8.8:443", None, None),
            "8.8.8.8",
        )

    def test_header_reader_accepts_streamlit_style_mapping(self):
        class _Headers:
            def __init__(self, data):
                self._data = dict(data)

            def __getitem__(self, key):
                return self._data[key]

        headers = _Headers({"X-Forwarded-For": " 8.8.8.8 "})
        self.assertEqual(auth._header_value(headers, "x-forwarded-for"), "8.8.8.8")
        self.assertIsNone(auth._header_value(headers, "x-real-ip"))


if __name__ == "__main__":
    unittest.main()
