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
streamlit_stub.stop = lambda *args, **kwargs: None
streamlit_stub.html = lambda *args, **kwargs: None


class _FakeContext:
    """Minimal stand-in for ``st.context`` (cookies/headers from the handshake)."""

    def __init__(self, cookies=None, headers=None):
        self.cookies = dict(cookies or {})
        self.headers = dict(headers or {})


streamlit_stub.context = _FakeContext()
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
            _FakeResponse(
                payload={
                    "access_token": "token",
                    "token_type": "Bearer",
                    "id_token": "id-token-value",
                }
            ),
            _FakeResponse(
                payload={"email": "Allowed@Example.com", "email_verified": True}
            ),
        )
        result = self._exchange(session)
        self.assertEqual(result.email, "allowed@example.com")
        self.assertEqual(result.id_token, "id-token-value")

    def test_missing_id_token_is_tolerated(self):
        session = self._session(
            _FakeResponse(payload={"access_token": "token", "token_type": "Bearer"}),
            _FakeResponse(
                payload={"email": "allowed@example.com", "email_verified": True}
            ),
        )
        result = self._exchange(session)
        self.assertEqual(result.email, "allowed@example.com")
        self.assertIsNone(result.id_token)

    def test_non_string_id_token_is_ignored(self):
        session = self._session(
            _FakeResponse(
                payload={
                    "access_token": "token",
                    "token_type": "Bearer",
                    "id_token": 12345,
                }
            ),
            _FakeResponse(
                payload={"email": "allowed@example.com", "email_verified": True}
            ),
        )
        self.assertIsNone(self._exchange(session).id_token)

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


class LogoutUrlTests(unittest.TestCase):
    def test_logout_url_targets_keycloak_endpoint(self):
        with mock.patch.dict(os.environ, BASE_ENV, clear=True):
            url = auth.get_keycloak_logout_url("id-token-value")

        self.assertIsNotNone(url)
        parsed = urlsplit(url)
        self.assertEqual(parsed.path, "/realms/dmarc/protocol/openid-connect/logout")
        params = parse_qs(parsed.query)
        self.assertEqual(params["client_id"], ["dmarclyzer"])
        self.assertEqual(params["id_token_hint"], ["id-token-value"])
        self.assertEqual(
            params["post_logout_redirect_uri"], ["https://dmarc.example.com/"]
        )

    def test_id_token_hint_is_optional(self):
        with mock.patch.dict(os.environ, BASE_ENV, clear=True):
            url = auth.get_keycloak_logout_url()

        self.assertIsNotNone(url)
        self.assertNotIn("id_token_hint", parse_qs(urlsplit(url).query))

    def test_logout_does_not_require_login_only_settings(self):
        env = {
            key: value
            for key, value in BASE_ENV.items()
            if key not in {"KEYCLOAK_EMAIL_ACCOUNT", "AUTH_STATE_SECRET"}
        }
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNotNone(auth.get_keycloak_logout_url("id-token-value"))

    def test_unusable_redirect_uri_is_dropped_but_logout_still_works(self):
        env = dict(BASE_ENV, KEYCLOAK_REDIRECT_URI="http://dmarc.example.com/")
        with mock.patch.dict(os.environ, env, clear=True):
            url = auth.get_keycloak_logout_url("id-token-value")

        self.assertIsNotNone(url)
        params = parse_qs(urlsplit(url).query)
        self.assertNotIn("post_logout_redirect_uri", params)
        self.assertEqual(params["id_token_hint"], ["id-token-value"])

    def test_missing_client_id_yields_no_url(self):
        env = dict(BASE_ENV, KEYCLOAK_CLIENT_ID="")
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNone(auth.get_keycloak_logout_url("id-token-value"))

    def test_insecure_issuer_yields_no_url(self):
        env = dict(BASE_ENV, KEYCLOAK_BASE_URL="http://sso.example.com")
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNone(auth.get_keycloak_logout_url("id-token-value"))


class LogoutTests(unittest.TestCase):
    @staticmethod
    def _session_state():
        return {
            auth.AUTHENTICATED_KEY: True,
            auth.EMAIL_SESSION_KEY: "allowed@example.com",
            auth.ID_TOKEN_SESSION_KEY: "id-token-value",
            auth.STATE_SESSION_KEY: "signed-state",
            auth.ATTEMPTS_SESSION_KEY: 2,
            auth.LOCKED_SESSION_KEY: True,
            "recaptcha_token": "token",
            "unrelated": "kept",
        }

    def test_keycloak_logout_returns_provider_url_and_clears_state(self):
        session_state = self._session_state()
        query_params = {"code": "auth-code", "state": "signed-state"}
        env = dict(BASE_ENV, AUTH_METHOD="keycloak")
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(auth.st, "session_state", session_state),
            mock.patch.object(auth.st, "query_params", query_params),
        ):
            url = auth.logout()

        self.assertIsNotNone(url)
        params = parse_qs(urlsplit(url).query)
        self.assertEqual(params["id_token_hint"], ["id-token-value"])
        self.assertEqual(
            params["post_logout_redirect_uri"], ["https://dmarc.example.com/"]
        )
        self.assertEqual(session_state, {"unrelated": "kept"})
        self.assertEqual(query_params, {})

    def test_keycloak_logout_without_id_token_still_returns_url(self):
        session_state = self._session_state()
        session_state.pop(auth.ID_TOKEN_SESSION_KEY)
        env = dict(BASE_ENV, AUTH_METHOD="keycloak")
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(auth.st, "session_state", session_state),
        ):
            url = auth.logout()

        self.assertIsNotNone(url)
        self.assertNotIn("id_token_hint", parse_qs(urlsplit(url).query))
        self.assertNotIn(auth.EMAIL_SESSION_KEY, session_state)

    def test_account_logout_only_clears_state(self):
        session_state = self._session_state()
        env = dict(BASE_ENV, AUTH_METHOD="account")
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(auth.st, "session_state", session_state),
        ):
            url = auth.logout()

        self.assertIsNone(url)
        self.assertNotIn(auth.AUTHENTICATED_KEY, session_state)
        self.assertNotIn(auth.ID_TOKEN_SESSION_KEY, session_state)


class KeycloakCallbackTests(unittest.TestCase):
    def test_id_token_is_stored_in_session_state(self):
        env = dict(BASE_ENV, AUTH_METHOD="keycloak")
        with mock.patch.dict(os.environ, env, clear=True):
            settings = auth._oidc_settings()
        signed_state = security.sign_state(
            settings["state_secret"],
            ttl_seconds=settings["ttl"],
            nonce="nonce",
        )
        query = {"code": "auth-code", "state": signed_state}
        session_state = {}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(auth.st, "session_state", session_state),
            mock.patch.object(auth, "_query_value", side_effect=query.get),
            mock.patch.object(
                auth,
                "_exchange_code_for_email",
                return_value=auth._LoginResult(
                    email="allowed@example.com", id_token="id-token-value"
                ),
            ),
        ):
            self.assertTrue(auth.authenticate_keycloak())

        self.assertIs(session_state[auth.AUTHENTICATED_KEY], True)
        self.assertEqual(session_state[auth.EMAIL_SESSION_KEY], "allowed@example.com")
        self.assertEqual(session_state[auth.ID_TOKEN_SESSION_KEY], "id-token-value")


class SessionCookieTests(unittest.TestCase):
    """The signed cookie keeps a session alive across full page reloads."""

    @staticmethod
    def _cookies(email="allowed@example.com", ttl=60, now=None, auth_method="account"):
        token = security.sign_auth_session(
            BASE_ENV["AUTH_STATE_SECRET"],
            email,
            ttl_seconds=ttl,
            now=now,
            audience=auth._session_audience(auth_method),
        )
        return {auth.SESSION_COOKIE_NAME: token}

    def _run(self, env, cookies, session_state=None, **patches):
        session_state = {} if session_state is None else session_state
        context = _FakeContext(cookies=cookies)
        stack = (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(auth.st, "session_state", session_state),
            mock.patch.object(auth.st, "context", context),
        )
        with stack[0], stack[1], stack[2], mock.patch.object(
            auth, "_run_javascript"
        ) as run_js:
            for name, patcher in patches.items():
                patcher.start()
                self.addCleanup(patcher.stop)
            return auth.require_auth(), session_state, run_js

    def test_valid_cookie_restores_an_account_session(self):
        env = dict(BASE_ENV, AUTH_METHOD="account")
        allowed, session_state, run_js = self._run(env, self._cookies())

        self.assertTrue(allowed)
        self.assertIs(session_state[auth.AUTHENTICATED_KEY], True)
        self.assertEqual(session_state[auth.EMAIL_SESSION_KEY], "allowed@example.com")
        # The restored session renews the cookie for the next refresh.
        run_js.assert_called_once()
        self.assertIn(auth.SESSION_COOKIE_NAME, run_js.call_args.args[0])

    def test_valid_cookie_restores_a_keycloak_session(self):
        env = dict(BASE_ENV, AUTH_METHOD="keycloak")
        allowed, session_state, _ = self._run(
            env, self._cookies(auth_method="keycloak")
        )

        self.assertTrue(allowed)
        self.assertEqual(session_state[auth.EMAIL_SESSION_KEY], "allowed@example.com")

    def test_cookie_is_bound_to_its_auth_method(self):
        env = dict(BASE_ENV, AUTH_METHOD="account")
        allowed, session_state, _ = self._run(
            env,
            self._cookies(auth_method="keycloak"),
            _render_account_login=mock.patch.object(
                auth, "_render_account_login", return_value=False
            ),
        )

        self.assertFalse(allowed)
        self.assertNotIn(auth.AUTHENTICATED_KEY, session_state)

    def test_cookie_for_a_removed_email_is_rejected(self):
        env = dict(BASE_ENV, AUTH_METHOD="keycloak")
        allowed, session_state, _ = self._run(
            env,
            self._cookies("revoked@example.com", auth_method="keycloak"),
            get_keycloak_url=mock.patch.object(auth, "get_keycloak_url", return_value=None),
        )

        self.assertFalse(allowed)
        self.assertNotIn(auth.AUTHENTICATED_KEY, session_state)

    def test_expired_cookie_is_rejected(self):
        env = dict(BASE_ENV, AUTH_METHOD="account")
        allowed, session_state, _ = self._run(
            env,
            self._cookies(ttl=60, now=0),
            _render_account_login=mock.patch.object(
                auth, "_render_account_login", return_value=False
            ),
        )

        self.assertFalse(allowed)
        self.assertNotIn(auth.AUTHENTICATED_KEY, session_state)

    def test_tampered_cookie_is_rejected(self):
        env = dict(BASE_ENV, AUTH_METHOD="account")
        token = security.sign_auth_session(
            "a-different-secret", "allowed@example.com", ttl_seconds=60
        )
        allowed, session_state, _ = self._run(
            env,
            {auth.SESSION_COOKIE_NAME: token},
            _render_account_login=mock.patch.object(
                auth, "_render_account_login", return_value=False
            ),
        )

        self.assertFalse(allowed)
        self.assertNotIn(auth.AUTHENTICATED_KEY, session_state)

    def test_provider_callback_wins_over_a_stale_cookie(self):
        env = dict(BASE_ENV, AUTH_METHOD="keycloak")
        allowed, session_state, _ = self._run(
            env,
            self._cookies(auth_method="keycloak"),
            _query_value=mock.patch.object(
                auth, "_query_value", side_effect=lambda name: "auth-code" if name == "code" else None
            ),
            authenticate_keycloak=mock.patch.object(
                auth, "authenticate_keycloak", return_value=False
            ),
        )

        self.assertFalse(allowed)
        self.assertNotIn(auth.AUTHENTICATED_KEY, session_state)

    def test_persistence_can_be_disabled(self):
        env = dict(BASE_ENV, AUTH_METHOD="account", AUTH_SESSION_TTL_SECONDS="0")
        session_state = {
            auth.AUTHENTICATED_KEY: True,
            auth.EMAIL_SESSION_KEY: "allowed@example.com",
        }
        context = _FakeContext()
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(auth.st, "session_state", session_state),
            mock.patch.object(auth.st, "context", context),
            mock.patch.object(auth, "_run_javascript") as run_js,
        ):
            self.assertTrue(auth.require_auth())

        run_js.assert_not_called()
        self.assertNotIn(auth.SESSION_COOKIE_SENT_KEY, session_state)

    def test_cookie_is_ignored_when_persistence_is_disabled(self):
        env = dict(BASE_ENV, AUTH_METHOD="account", AUTH_SESSION_TTL_SECONDS="0")
        allowed, session_state, _ = self._run(
            env,
            self._cookies(),
            _render_account_login=mock.patch.object(
                auth, "_render_account_login", return_value=False
            ),
        )

        self.assertFalse(allowed)
        self.assertNotIn(auth.AUTHENTICATED_KEY, session_state)

    def test_clear_script_expires_the_cookie(self):
        env = {"ALLOW_INSECURE_IDP": "true"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(auth.st, "context", _FakeContext()),
        ):
            script = auth.session_cookie_clear_js()

        self.assertIn(auth.SESSION_COOKIE_NAME, script)
        self.assertIn("Max-Age=0", script)
        self.assertIn("Path=/", script)
        self.assertNotIn("Secure", script)

    def test_secure_attribute_follows_the_request_scheme(self):
        cases = [
            ({"origin": "https://dmarc.example.com"}, True),
            ({"origin": "http://localhost:8501"}, False),
            ({"x-forwarded-proto": "https, http"}, True),
            ({"x-forwarded-proto": "http"}, False),
        ]
        for headers, expected in cases:
            context = _FakeContext(headers=headers)
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(auth.st, "context", context),
            ):
                script = auth.session_cookie_clear_js()
            self.assertEqual("Secure" in script, expected, repr(headers))


if __name__ == "__main__":
    unittest.main()
