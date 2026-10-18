"""Regression tests for ``app/security.py``.

These tests intentionally use only the standard library so they can run in CI
before the third-party dependencies are installed.
"""

import base64
import hashlib
import io
import os
import sys
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"
    ),
)

import security  # noqa: E402  (path setup must happen first)


class EscapingTests(unittest.TestCase):
    def test_escape_html_removes_markup(self):
        escaped = security.escape_html('<script>alert("x")</script>')
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&quot;", escaped)

    def test_escape_html_handles_none(self):
        self.assertEqual(security.escape_html(None), "")

    def test_escape_markdown_neutralises_syntax(self):
        escaped = security.escape_markdown("**bold** [link](x) `<code>`")
        self.assertNotIn("**", escaped)
        self.assertIn("\\*", escaped)
        self.assertIn("\\[", escaped)
        self.assertIn("\\`", escaped)

    def test_escape_markdown_handles_none(self):
        self.assertEqual(security.escape_markdown(None), "")

    def test_safe_hex_colours(self):
        for value in ("#fff", "#ffffff", "#AABBCC", "#11223344"):
            self.assertTrue(security.is_safe_hex_color(value), value)
        for value in ("red", "#fff;background:url(x)", "url(x)", "", None):
            self.assertFalse(security.is_safe_hex_color(value), value)


class CoercionTests(unittest.TestCase):
    def test_truncate(self):
        self.assertEqual(security.truncate("  abc  ", 2), "ab")
        self.assertIsNone(security.truncate("   "))
        self.assertEqual(security.truncate(None, default="fallback"), "fallback")

    def test_safe_int(self):
        self.assertEqual(security.safe_int("42"), 42)
        self.assertEqual(security.safe_int("abc", default=7), 7)
        self.assertEqual(
            security.safe_int("999", default=0, minimum=0, maximum=100), 100
        )
        self.assertEqual(security.safe_int("-5", minimum=0), 0)
        self.assertEqual(security.safe_int(None, default=3), 3)

    def test_safe_timestamp(self):
        self.assertEqual(security.safe_timestamp("0"), datetime.fromtimestamp(0))
        self.assertIsNone(security.safe_timestamp("not-a-number"))
        self.assertIsNone(security.safe_timestamp("999999999999999"))
        self.assertIsNone(security.safe_timestamp("-1"))
        self.assertIsNone(security.safe_timestamp(None))

    def test_env_int(self):
        with mock.patch.dict(os.environ, {"X_TEST_INT": "12"}):
            self.assertEqual(security.env_int("X_TEST_INT", 1), 12)
        with mock.patch.dict(os.environ, {"X_TEST_INT": "nope"}):
            self.assertEqual(security.env_int("X_TEST_INT", 5), 5)
        with mock.patch.dict(os.environ, {"X_TEST_INT": "0"}):
            self.assertEqual(security.env_int("X_TEST_INT", 5, minimum=1), 1)
        with mock.patch.dict(os.environ, {"X_TEST_INT": ""}):
            self.assertEqual(security.env_int("X_TEST_INT", 5), 5)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(security.env_int("X_TEST_INT", 9), 9)

    def test_constant_time_equals(self):
        self.assertTrue(security.constant_time_equals("secret", "secret"))
        self.assertFalse(security.constant_time_equals("Secret", "secret"))
        self.assertFalse(security.constant_time_equals("", "secret"))
        self.assertFalse(security.constant_time_equals(None, None))

    def test_is_valid_ip(self):
        self.assertTrue(security.is_valid_ip("192.0.2.1"))
        self.assertTrue(security.is_valid_ip("2001:db8::1"))
        self.assertFalse(security.is_valid_ip("example.com"))
        self.assertFalse(security.is_valid_ip(None))

    def test_index_name_validation(self):
        self.assertTrue(security.is_safe_index_name("report_id"))
        self.assertFalse(security.is_safe_index_name("x`; DROP TABLE reports"))
        self.assertFalse(security.is_safe_index_name(""))


class SignedStateTests(unittest.TestCase):
    SECRET = "unit-test-secret"
    ISSUED = 1_700_000_000

    def test_roundtrip(self):
        state = security.sign_state(
            self.SECRET, ttl_seconds=300, now=self.ISSUED, nonce="abc123"
        )
        self.assertEqual(
            security.verify_state(
                self.SECRET, state, ttl_seconds=300, now=self.ISSUED + 10
            ),
            "abc123",
        )

    def test_signature_is_required(self):
        state = security.sign_state(self.SECRET, now=self.ISSUED, nonce="abc123")
        tampered = state[:-2] + ("AA" if not state.endswith("AA") else "BB")
        self.assertIsNone(
            security.verify_state(
                self.SECRET, tampered, ttl_seconds=300, now=self.ISSUED + 10
            )
        )
        self.assertIsNone(
            security.verify_state(
                "different-secret", state, ttl_seconds=300, now=self.ISSUED + 10
            )
        )

    def test_timestamp_is_authenticated(self):
        state = security.sign_state(self.SECRET, now=self.ISSUED, nonce="abc123")
        _, nonce, signature = state.split(".")
        forged = f"{self.ISSUED + 9999}.{nonce}.{signature}"
        self.assertIsNone(
            security.verify_state(
                self.SECRET, forged, ttl_seconds=300, now=self.ISSUED + 10
            )
        )

    def test_expired_and_future_states_rejected(self):
        state = security.sign_state(
            self.SECRET, ttl_seconds=60, now=self.ISSUED, nonce="abc123"
        )
        self.assertEqual(
            security.verify_state(
                self.SECRET, state, ttl_seconds=60, now=self.ISSUED + 60
            ),
            "abc123",
        )
        self.assertIsNone(
            security.verify_state(
                self.SECRET, state, ttl_seconds=60, now=self.ISSUED + 61
            )
        )
        self.assertIsNone(
            security.verify_state(
                self.SECRET, state, ttl_seconds=60, now=self.ISSUED - 120
            )
        )

    def test_malformed_states(self):
        for value in ("", None, "a.b", "a.b.c.d", "x.y.z", "1..abc"):
            self.assertIsNone(security.verify_state(self.SECRET, value))

    def test_signing_requires_secret(self):
        with self.assertRaises(ValueError):
            security.sign_state("", now=self.ISSUED)

    def test_pkce_is_deterministic_and_s256(self):
        verifier = security.derive_pkce_verifier(self.SECRET, "nonce-value")
        self.assertEqual(
            verifier, security.derive_pkce_verifier(self.SECRET, "nonce-value")
        )
        self.assertNotEqual(
            verifier, security.derive_pkce_verifier(self.SECRET, "other-nonce")
        )
        self.assertGreaterEqual(len(verifier), 43)
        self.assertLessEqual(len(verifier), 128)

        expected = (
            base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            )
            .decode("ascii")
            .rstrip("=")
        )
        self.assertEqual(security.pkce_challenge(verifier), expected)

    def test_pkce_requires_inputs(self):
        with self.assertRaises(ValueError):
            security.derive_pkce_verifier("", "nonce")
        with self.assertRaises(ValueError):
            security.pkce_challenge("")


class UrlValidationTests(unittest.TestCase):
    def test_issuer_urls(self):
        self.assertTrue(security.validate_issuer_url("https://sso.example.com"))
        self.assertFalse(security.validate_issuer_url("http://sso.example.com"))
        self.assertTrue(
            security.validate_issuer_url("http://localhost:8080", allow_insecure=True)
        )
        self.assertFalse(
            security.validate_issuer_url("https://user:pass@sso.example.com")
        )
        self.assertFalse(security.validate_issuer_url("https://sso.example.com?x=1"))
        self.assertFalse(security.validate_issuer_url(""))
        self.assertFalse(security.validate_issuer_url("javascript:alert(1)"))

    def test_redirect_uri(self):
        self.assertTrue(security.validate_redirect_uri("https://dmarc.example.com/"))
        self.assertFalse(security.validate_redirect_uri("javascript:alert(1)"))
        self.assertFalse(security.validate_redirect_uri("http://dmarc.example.com/"))
        self.assertTrue(
            security.validate_redirect_uri(
                "http://localhost:8080/", allow_insecure=True
            )
        )


class MailboxTests(unittest.TestCase):
    def test_quoting(self):
        self.assertEqual(security.quote_mailbox("INBOX"), '"INBOX"')
        self.assertEqual(security.quote_mailbox('My "Folder"'), '"My \\"Folder\\""')
        self.assertEqual(security.quote_mailbox("a\\b"), '"a\\\\b"')

    def test_rejects_control_characters_and_empty_names(self):
        for value in (
            "INBOX\r\nA1 DELETE",
            "bad\nname",
            "bad\x00name",
            "",
            "   ",
            "x" * 256,
        ):
            with self.assertRaises(ValueError, msg=repr(value)):
                security.validate_mailbox(value)
        with self.assertRaises(ValueError):
            security.validate_mailbox(None)


class BoundedReadTests(unittest.TestCase):
    def test_reads_within_limit(self):
        self.assertEqual(security.bounded_read(io.BytesIO(b"abc"), 3), b"abc")

    def test_rejects_payload_over_limit(self):
        with self.assertRaises(security.OversizedPayloadError):
            security.bounded_read(io.BytesIO(b"abcd"), 3)

    def test_rejects_non_positive_limit(self):
        with self.assertRaises(security.OversizedPayloadError):
            security.bounded_read(io.BytesIO(b""), 0)


if __name__ == "__main__":
    unittest.main()
