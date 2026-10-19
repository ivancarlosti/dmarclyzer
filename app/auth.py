"""Authentication for DMARClyzer (``none`` / ``account`` / ``keycloak``).

The Keycloak flow is implemented directly against the OIDC endpoints; Authlib
is intentionally **not** used. Security properties and the rationale behind
the signed ``state`` / derived PKCE verifier are documented in
``plans/2026-10-18-security-audit-and-remediation.md``.
"""

from __future__ import annotations

import logging
import os
import secrets
import urllib.parse
from typing import NamedTuple

import requests
import streamlit as st

from security import (
    STATE_TTL_SECONDS_MAX,
    STATE_TTL_SECONDS_MIN,
    constant_time_equals,
    derive_pkce_verifier,
    env_int,
    escape_html,
    pkce_challenge,
    sign_state,
    validate_issuer_url,
    validate_redirect_uri,
    verify_state,
)

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = (10, 15)
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"

AUTHENTICATED_KEY = "authenticated"
EMAIL_SESSION_KEY = "auth_email"
ID_TOKEN_SESSION_KEY = "auth_id_token"
STATE_SESSION_KEY = "_oidc_state"
ATTEMPTS_SESSION_KEY = "_login_attempts"
LOCKED_SESSION_KEY = "_login_locked"

_SCOPE = "openid email profile"


class _LoginResult(NamedTuple):
    """Verified login identity plus the ID token needed for logout."""

    email: str
    id_token: str | None = None


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").strip()


def _env_flag(name: str) -> bool:
    return _env(name).lower() in {"1", "true", "yes", "on"}


def _query_value(name: str):
    """Return a single query-string value, or None."""
    try:
        value = st.query_params.get(name)
    except Exception:  # pragma: no cover - defensive, Streamlit internal API
        logger.debug("Unable to read query parameter %r", name, exc_info=True)
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _clear_query_params():
    try:
        st.query_params.clear()
    except Exception:  # pragma: no cover - defensive, Streamlit internal API
        logger.debug("Unable to clear query parameters", exc_info=True)


def _fail(message: str, detail: str | None = None):
    """Show a generic error to the user and log the real reason server-side."""
    if detail:
        logger.warning("Authentication failure: %s", detail)
    st.error(message)
    _clear_query_params()
    return False


def _http_session() -> requests.Session:
    """Return a short-lived session that ignores ~/.netrc and proxy env vars.

    ``trust_env=False`` keeps the OIDC client from leaking credentials through
    a crafted ``.netrc`` entry (CVE-2024-47081 class) and makes behaviour
    deterministic inside containers.
    """
    session = requests.Session()
    session.trust_env = False
    return session


def _endpoint(base: str, realm: str, suffix: str) -> str:
    return (
        f"{base}/realms/{urllib.parse.quote(realm, safe='')}"
        f"/protocol/openid-connect/{suffix}"
    )


def _oidc_settings() -> dict:
    return {
        "base": _env("KEYCLOAK_BASE_URL").rstrip("/"),
        "realm": _env("KEYCLOAK_REALM"),
        "client_id": _env("KEYCLOAK_CLIENT_ID"),
        "client_secret": _env("KEYCLOAK_CLIENT_SECRET"),
        "redirect_uri": _env("KEYCLOAK_REDIRECT_URI"),
        "state_secret": _env("AUTH_STATE_SECRET"),
        "allowed_emails": [
            item.strip().lower()
            for item in _env("KEYCLOAK_EMAIL_ACCOUNT").split(",")
            if item.strip()
        ],
        "allow_insecure": _env_flag("ALLOW_INSECURE_IDP"),
        "ttl": env_int(
            "AUTH_STATE_TTL_SECONDS",
            300,
            minimum=STATE_TTL_SECONDS_MIN,
            maximum=STATE_TTL_SECONDS_MAX,
        ),
    }


def _oidc_config_errors(settings: dict) -> list[str]:
    """Return the list of settings that make a safe OIDC flow impossible."""
    allow_insecure = settings["allow_insecure"]
    errors: list[str] = []
    if not validate_issuer_url(settings["base"], allow_insecure):
        errors.append("KEYCLOAK_BASE_URL")
    if not settings["realm"]:
        errors.append("KEYCLOAK_REALM")
    if not settings["client_id"]:
        errors.append("KEYCLOAK_CLIENT_ID")
    if not settings["client_secret"]:
        errors.append("KEYCLOAK_CLIENT_SECRET")
    if not validate_redirect_uri(settings["redirect_uri"], allow_insecure):
        errors.append("KEYCLOAK_REDIRECT_URI")
    if not settings["state_secret"]:
        errors.append("AUTH_STATE_SECRET")
    if not settings["allowed_emails"]:
        # Fail closed: an empty allow-list used to grant every realm user access.
        errors.append("KEYCLOAK_EMAIL_ACCOUNT")
    return errors


def get_keycloak_url() -> str | None:
    """Build the authorization URL and remember the signed state.

    Returns ``None`` when the configuration is incomplete or unsafe.
    """
    settings = _oidc_settings()
    if _oidc_config_errors(settings):
        return None

    nonce = secrets.token_urlsafe(24)
    state = sign_state(
        settings["state_secret"], ttl_seconds=settings["ttl"], nonce=nonce
    )
    verifier = derive_pkce_verifier(settings["state_secret"], nonce)
    st.session_state[STATE_SESSION_KEY] = state

    params = {
        "client_id": settings["client_id"],
        "response_type": "code",
        "redirect_uri": settings["redirect_uri"],
        "scope": _SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    auth_url = _endpoint(settings["base"], settings["realm"], "auth")
    return f"{auth_url}?{urllib.parse.urlencode(params)}"


def get_keycloak_logout_url(id_token: str | None = None) -> str | None:
    """Build the RP-Initiated Logout URL that ends the Keycloak SSO session.

    ``post_logout_redirect_uri`` is always sent so the browser returns to the
    dashboard. Keycloak validates it against the client's post-logout redirect
    URIs (falling back to the valid redirect URIs when that field is empty)
    **before** it terminates the session, so ``KEYCLOAK_REDIRECT_URI`` must be
    accepted by the client.

    Only the settings needed to reach the endpoint are required: a user whose
    session is live must stay able to sign out even if the login allow-list or
    ``AUTH_STATE_SECRET`` is changed in the meantime. An unusable redirect URI
    is dropped rather than blocking the sign-out, because terminating the
    provider session matters more than the landing page.
    """
    settings = _oidc_settings()
    if (
        not validate_issuer_url(settings["base"], settings["allow_insecure"])
        or not settings["realm"]
        or not settings["client_id"]
    ):
        logger.warning(
            "Cannot build a Keycloak logout URL: OIDC configuration is incomplete."
        )
        return None

    params = {"client_id": settings["client_id"]}
    redirect_uri = settings["redirect_uri"]
    if redirect_uri and validate_redirect_uri(redirect_uri, settings["allow_insecure"]):
        params["post_logout_redirect_uri"] = redirect_uri
    else:
        logger.warning(
            "KEYCLOAK_REDIRECT_URI is not usable as a post-logout redirect; "
            "signing out will end on the Keycloak logout page."
        )
    if id_token:
        params["id_token_hint"] = id_token

    logout_endpoint = _endpoint(settings["base"], settings["realm"], "logout")
    return f"{logout_endpoint}?{urllib.parse.urlencode(params)}"


def _exchange_code_for_email(
    settings: dict, code: str, verifier: str
) -> _LoginResult | None:
    """Exchange an authorization code and return the verified, allowed identity.

    The ID token is kept because RP-Initiated Logout needs it as
    ``id_token_hint``; without it Keycloak cannot reliably identify (and
    therefore terminate) the browser's SSO session.
    """
    token_url = _endpoint(settings["base"], settings["realm"], "token")
    userinfo_url = _endpoint(settings["base"], settings["realm"], "userinfo")
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings["redirect_uri"],
        "client_id": settings["client_id"],
        "code_verifier": verifier,
    }

    try:
        with _http_session() as session:
            token_response = session.post(
                token_url,
                data=token_data,
                auth=(settings["client_id"], settings["client_secret"]),
                headers={"Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if token_response.status_code != 200:
                logger.warning(
                    "Token endpoint returned HTTP %s: %r",
                    token_response.status_code,
                    token_response.text[:500],
                )
                return None
            try:
                tokens = token_response.json()
            except ValueError:
                logger.warning("Token endpoint returned a non-JSON response.")
                return None
            if not isinstance(tokens, dict):
                logger.warning("Token endpoint returned an unexpected payload.")
                return None

            access_token = tokens.get("access_token")
            token_type = str(tokens.get("token_type", "")).lower()
            if (
                not isinstance(access_token, str)
                or not access_token
                or token_type != "bearer"
            ):
                logger.warning("Token response did not contain a Bearer access token.")
                return None

            id_token = tokens.get("id_token")
            if not isinstance(id_token, str) or not id_token.strip():
                # Public clients and some providers omit it; logout then falls
                # back to Keycloak's logout confirmation screen.
                id_token = None

            userinfo_response = session.get(
                userinfo_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if userinfo_response.status_code != 200:
                logger.warning(
                    "Userinfo endpoint returned HTTP %s", userinfo_response.status_code
                )
                return None
            try:
                userinfo = userinfo_response.json()
            except ValueError:
                logger.warning("Userinfo endpoint returned a non-JSON response.")
                return None
    except requests.RequestException as exc:
        logger.error("OIDC request failed (%s)", type(exc).__name__)
        return None

    if not isinstance(userinfo, dict):
        logger.warning("Userinfo endpoint returned an unexpected payload.")
        return None

    email = userinfo.get("email")
    if not isinstance(email, str) or not email.strip():
        logger.warning("Userinfo response did not contain an email address.")
        return None
    email = email.strip().lower()

    verified = userinfo.get("email_verified", True)
    if verified is False or (isinstance(verified, str) and verified.lower() == "false"):
        logger.warning("Rejected login for an unverified email address.")
        return None

    if email not in settings["allowed_emails"]:
        logger.warning("Rejected login for %r (not in KEYCLOAK_EMAIL_ACCOUNT).", email)
        return None

    return _LoginResult(email=email, id_token=id_token)


def authenticate_keycloak():
    """Run the Keycloak authorization-code flow, returning True on success."""
    settings = _oidc_settings()
    errors = _oidc_config_errors(settings)
    if errors:
        logger.error("OIDC is enabled but misconfigured: %s", ", ".join(errors))
        st.error(
            "SSO is enabled but not configured correctly. Contact your administrator."
        )
        return False

    provider_error = _query_value("error")
    if provider_error:
        logger.warning(
            "Identity provider returned error=%r description=%r",
            provider_error,
            _query_value("error_description"),
        )
        return _fail("The identity provider rejected the sign-in request.")

    code = _query_value("code")
    if code:
        state = _query_value("state")
        nonce = verify_state(
            settings["state_secret"], state, ttl_seconds=settings["ttl"]
        )
        if nonce is None:
            return _fail(
                "Your sign-in link is invalid or has expired. Please sign in again."
            )

        expected_state = st.session_state.get(STATE_SESSION_KEY)
        if expected_state and not constant_time_equals(expected_state, state):
            return _fail(
                "Your sign-in session does not match this request. Please sign in again."
            )

        try:
            verifier = derive_pkce_verifier(settings["state_secret"], nonce)
        except ValueError:
            return _fail("Your sign-in link is invalid. Please sign in again.")

        result = _exchange_code_for_email(settings, str(code), verifier)
        if not result:
            return _fail(
                "Sign-in failed. Please try again or contact your administrator."
            )

        st.session_state[AUTHENTICATED_KEY] = True
        st.session_state[EMAIL_SESSION_KEY] = result.email
        if result.id_token:
            st.session_state[ID_TOKEN_SESSION_KEY] = result.id_token
        st.session_state.pop(STATE_SESSION_KEY, None)
        _clear_query_params()
        st.rerun()
        return True

    login_url = get_keycloak_url()
    if not login_url:
        st.error(
            "SSO is enabled but not configured correctly. Contact your administrator."
        )
        return False

    st.markdown(
        f'''
        <div style="display:flex; justify-content:center; align-items:center; height:50vh;">
            <a href="{escape_html(login_url)}" target="_self" style="display:inline-block;padding:15px 30px;background-color:#4CAF50;color:white;text-decoration:none;border-radius:4px;font-weight:bold;font-size:18px;">
                Login with Keycloak SSO
            </a>
        </div>
        ''',
        unsafe_allow_html=True,
    )
    return False


def _recaptcha_token() -> str | None:
    token = _query_value("g-recaptcha-response")
    if not token:
        token = st.session_state.get("recaptcha_token")
    return token if isinstance(token, str) and token.strip() else None


def _verify_recaptcha(secret: str) -> bool:
    """Verify a reCAPTCHA token server-side; fails closed on any error."""
    token = _recaptcha_token()
    if not token:
        logger.warning("reCAPTCHA is configured but no verification token was sent.")
        return False
    try:
        with _http_session() as session:
            response = session.post(
                RECAPTCHA_VERIFY_URL,
                data={"secret": secret, "response": token},
                timeout=REQUEST_TIMEOUT,
            )
        if response.status_code != 200:
            logger.error("reCAPTCHA verification returned HTTP %s", response.status_code)
            return False
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.error("reCAPTCHA verification failed (%s)", type(exc).__name__)
        return False

    success = isinstance(payload, dict) and payload.get("success") is True
    if not success:
        logger.warning(
            "reCAPTCHA rejected the login attempt: %r",
            payload.get("error-codes") if isinstance(payload, dict) else None,
        )
    return success


def _render_account_login():
    configured_login = _env("ACCOUNT_LOGIN")
    configured_password = _env("ACCOUNT_PASSWORD")
    if not configured_login or not configured_password:
        logger.error(
            "AUTH_METHOD=account but ACCOUNT_LOGIN/ACCOUNT_PASSWORD are not both set."
        )
        st.error("Account sign-in is enabled but not configured. Access denied.")
        return False

    max_attempts = env_int("LOGIN_MAX_ATTEMPTS", 5, minimum=1, maximum=100)
    if st.session_state.get(LOCKED_SESSION_KEY):
        st.error(
            "Too many failed sign-in attempts. Restart your browser session and try again."
        )
        return False

    site_key = _env("RECAPTCHA_CLIENTID")
    captcha_secret = _env("RECAPTCHA_CLIENTSECRET")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if site_key:
            st.caption("reCAPTCHA is enabled — provide the verification token.")
            st.text_input("reCAPTCHA token", key="recaptcha_token", type="password")

        with st.form("login_form"):
            st.subheader("Secure Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign In")

            if submitted:
                # Evaluate both comparisons so timing does not reveal which
                # half of the credential pair was wrong.
                username_ok = constant_time_equals(username, configured_login)
                password_ok = constant_time_equals(password, configured_password)

                if username_ok and password_ok:
                    if captcha_secret and not _verify_recaptcha(captcha_secret):
                        st.error("reCAPTCHA verification failed. Please try again.")
                        return False
                    st.session_state[AUTHENTICATED_KEY] = True
                    st.session_state[ATTEMPTS_SESSION_KEY] = 0
                    st.rerun()
                else:
                    attempts = int(st.session_state.get(ATTEMPTS_SESSION_KEY, 0)) + 1
                    st.session_state[ATTEMPTS_SESSION_KEY] = attempts
                    if attempts >= max_attempts:
                        st.session_state[LOCKED_SESSION_KEY] = True
                        logger.warning(
                            "Account login locked after %s failed attempts.", attempts
                        )
                        st.error(
                            "Too many failed sign-in attempts. Restart your browser session to try again."
                        )
                    else:
                        logger.warning(
                            "Failed account login attempt (%s/%s).", attempts, max_attempts
                        )
                        st.error("Invalid credentials.")
    return False


def logout() -> str | None:
    """Clear local authentication state and return the Keycloak logout URL.

    Clearing ``st.session_state`` alone is not a real sign-out: the Keycloak
    SSO cookie stays valid, so the next authorization request signed the user
    straight back in. For ``AUTH_METHOD=keycloak`` the returned URL performs
    RP-Initiated Logout at the provider and must be opened in the browser.
    """
    id_token = st.session_state.get(ID_TOKEN_SESSION_KEY)
    logout_url = None
    if (_env("AUTH_METHOD", "none") or "none").lower() == "keycloak":
        logout_url = get_keycloak_logout_url(
            id_token if isinstance(id_token, str) else None
        )

    for key in (
        AUTHENTICATED_KEY,
        EMAIL_SESSION_KEY,
        ID_TOKEN_SESSION_KEY,
        STATE_SESSION_KEY,
        ATTEMPTS_SESSION_KEY,
        LOCKED_SESSION_KEY,
        "recaptcha_token",
    ):
        st.session_state.pop(key, None)
    _clear_query_params()
    return logout_url


def require_auth():
    auth_method = (_env("AUTH_METHOD", "none") or "none").lower()

    if auth_method == "none":
        return True

    if st.session_state.get(AUTHENTICATED_KEY, False):
        return True

    # We want to clear whitespace to make it look clean like the main app
    hide_st_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        .block-container {
            padding-top: 2rem !important;
        }
        </style>
    """
    st.markdown(hide_st_style, unsafe_allow_html=True)

    st.title("🛡️ Authentication Required")

    if auth_method == "account":
        return _render_account_login()

    if auth_method == "keycloak":
        return authenticate_keycloak()

    logger.error("Unknown AUTH_METHOD %r configured.", auth_method)
    st.error(f"Unknown AUTH_METHOD '{escape_html(auth_method)}' configured.")
    return False
