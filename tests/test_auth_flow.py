"""Tests for the OIDC configuration and code-exchange logic in ``auth.py``.

Streamlit is replaced with a tiny in-process stub so the suite stays
dependency-free; ``requests`` is stubbed as well when it is not installed.
"""

import os
import sys
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"
    ),
)

# ── Minimal Streamlit stub (must exist before importing auth) ───────────────
streamlit_stub = types.ModuleType("streamlit")
streamlit_stub.session_state = {}
streamlit_stub.query_params = {}
streamlit_stub.error = lambda *args, **kwargs: None
streamlit_stub.markdown = lambda *args, **kwargs: None
streamlit_stub.title = lambda *args, **kwargs: None
streamlit_stub.caption = lambda *args, **kwargs: None
streamlit_stub.rerun = lambda *args, **kwargs: None
streamlit_stub.columns = lambda spec: []
sys.modules.setdefault("streamlit", streamlit_stub)

# ── Minimal requests stub for CI environments without dependencies ─────────
try:  # pragma: no cover - depends on the environment
    import requests  # noqa: F401
except ImportError:  # pragma: no cover
    requests_stub = types.ModuleType("requests")

    class _RequestException(Exception):
        pass

    requests_stub.RequestException = _RequestException
    requests_stub.Session = object
    sys.modules["requests"] = requests_stub

import auth  # noqa: E402
import security  # noqa: E402

BASE_ENV = {
    "KEYCLOAK_BASE_URL": "https://sso.example.com",
    "KEYCLOAK_REALM": "dmarc",
    "KEYCLOAK_CLIENT_ID": "dmarclyzer",
    "KEYCLOAK_CLIENT_SECRET": "client-secret",
    "KEYCLOAK_REDIRECT_URI": "https://dmarc.example.com/",
    "KEYCLOAK_EMAIL_ACCOUNT": "allowed@example.com, Second@Example.com",
    "AUTH_STATE_SECRET": "state-signing-secret",
}


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON payload")
        return self._payload


class _FakeSession:
    def __init__(self, token_response, userinfo_response=None):
        self.token_response = token_response
        self.userinfo_response = userinfo_response

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def post(self, *args, **kwargs):
        return self.token_response

    def get(self, *args, **kwargs):
        return self.userinfo_response


class OidcConfigTests(unittest.TestCase):
    def test_complete_configuration_is_accepted(self):
        with mock.patch.dict(os.environ, BASE_ENV, clear=True):
            settings = auth._oidc_settings()
            self.assertEqual(auth._oidc_config_errors(settings), [])
            self.assertEqual(
                settings["allowed_emails"],
                ["allowed@example.com", "second@example.com"],
            )

    def test_empty_allow_list_fails_closed(self):
        env = dict(BASE_ENV, KEYCLOAK_EMAIL_ACCOUNT="")
        with mock.patch.dict(os.environ, env, clear=True):
            errors = auth._oidc_config_errors(auth._oidc_settings())
            self.assertIn("KEYCLOAK_EMAIL_ACCOUNT", errors)
            self.assertIsNone(auth.get_keycloak_url())

    def test_missing_state_secret_fails_closed(self):
        env = dict(BASE_ENV, AUTH_STATE_SECRET="")
        with mock.patch.dict(os.environ, env, clear=True):
            errors = auth._oidc_config_errors(auth._oidc_settings())
            self.assertIn("AUTH_STATE_SECRET", errors)

    def test_insecure_issuer_rejected_by_default(self):
        env = dict(BASE_ENV, KEYCLOAK_BASE_URL="http://sso.example.com")
        with mock.patch.dict(os.environ, env, clear=True):
            errors = auth._oidc_config_errors(auth._oidc_settings())
            self.assertIn("KEYCLOAK_BASE_URL", errors)

    def test_insecure_issuer_allowed_explicitly(self):
        env = dict(
            BASE_ENV,
            KEYCLOAK_BASE_URL="http://localhost:8080",
            KEYCLOAK_REDIRECT_URI="http://localhost:8080/",
            ALLOW_INSECURE_IDP="true",
        )
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(auth._oidc_config_errors(auth._oidc_settings()), [])

    def test_authorization_url_binds_state_and_pkce(self):
        with mock.patch.dict(os.environ, BASE_ENV, clear=True):
            url = auth.get_keycloak_url()

        self.assertIsNotNone(url)
        parsed = urlsplit(url)
        self.assertEqual(parsed.path, "/realms/dmarc/protocol/openid-connect/auth")
        params = parse_qs(parsed.query)
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["scope"], ["openid email profile"])
        self.assertEqual(params["redirect_uri"], ["https://dmarc.example.com/"])

        nonce = security.verify_state(
            BASE_ENV["AUTH_STATE_SECRET"], params["state"][0]
        )
        self.assertIsNotNone(nonce)
        self.assertEqual(params["nonce"], [nonce])
        verifier = security.derive_pkce_verifier(
            BASE_ENV["AUTH_STATE_SECRET"], nonce
        )
        self.assertEqual(
            security.pkce_challenge(verifier), params["code_challenge"][0]
        )


class OidcExchangeTests(unittest.TestCase):
    @staticmethod
    def _settings():
        with mock.patch.dict(os.environ, BASE_ENV, clear=True):
            return auth._oidc_settings()

    @staticmethod
    def _session(token_response, userinfo_response=None):
        return _FakeSession(token_response, userinfo_response)

    def _exchange(self, session):
        with mock.patch.object(auth, "_http_session", return_value=session):
            return auth._exchange_code_for_email(self._settings(), "code", "verifier")

    def test_allowed_email_is_returned_lowercased(self):
        session = self._session(
            _FakeResponse(payload={"access_token": "token", "token_type": "Bearer"}),
            _FakeResponse(
                payload={"email": "Allowed@Example.com", "email_verified": True}
            ),
        )
        self.assertEqual(self._exchange(session), "allowed@example.com")

    def test_email_not_on_allow_list_is_rejected(self):
        session = self._session(
            _FakeResponse(payload={"access_token": "token", "token_type": "Bearer"}),
            _FakeResponse(
                payload={"email": "attacker@example.com", "email_verified": True}
            ),
        )
        self.assertIsNone(self._exchange(session))

    def test_unverified_email_is_rejected(self):
        session = self._session(
            _FakeResponse(payload={"access_token": "token", "token_type": "Bearer"}),
            _FakeResponse(
                payload={"email": "allowed@example.com", "email_verified": False}
            ),
        )
        self.assertIsNone(self._exchange(session))

    def test_non_bearer_token_is_rejected(self):
        session = self._session(
            _FakeResponse(payload={"access_token": "token", "token_type": "mac"}),
            _FakeResponse(payload={"email": "allowed@example.com"}),
        )
        self.assertIsNone(self._exchange(session))

    def test_missing_access_token_is_rejected(self):
        session = self._session(_FakeResponse(payload={"token_type": "Bearer"}))
        self.assertIsNone(self._exchange(session))

    def test_provider_error_response_is_handled(self):
        session = self._session(_FakeResponse(status_code=400, text="invalid_grant"))
        self.assertIsNone(self._exchange(session))

    def test_non_json_userinfo_is_rejected(self):
        session = self._session(
            _FakeResponse(payload={"access_token": "token", "token_type": "Bearer"}),
            _FakeResponse(payload=None),
        )
        self.assertIsNone(self._exchange(session))

    def test_userinfo_without_email_is_rejected(self):
        session = self._session(
            _FakeResponse(payload={"access_token": "token", "token_type": "Bearer"}),
            _FakeResponse(payload={"sub": "abc"}),
        )
        self.assertIsNone(self._exchange(session))


if __name__ == "__main__":
    unittest.main()
