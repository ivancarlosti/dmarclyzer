# Security Audit & Remediation — DMARClyzer

- **Date:** 2026-10-18
- **Scope:** `authlib` JWS signature bypass, CVE-2024-36039, full dependency +
  application-level security review of the DMARClyzer codebase.
- **Status:** Implemented in this change set.
- **Method:** static review, OSV/NVD advisories, PyPI release metadata, and
  dependency-free regression tests (all retrieved on 2026-10-18).

---

## 1. Executive summary

Two vulnerabilities were explicitly requested for review:

| Requested item | Verdict |
|----------------|---------|
| **Authlib signature bypass** (CVE-2026-27962 / GHSA-wvwj-cvrp-7pv5) | **Not exploitable in DMARClyzer.** `authlib` was pinned to `1.3.0` in `requirements.txt` but **is not imported anywhere**. The OIDC flow is hand-written with `requests` and never trusts an unverified ID token — identity comes from the provider's `/userinfo` endpoint over TLS. The finding is a vulnerable-pin/scanner issue, not a live bypass. Fixed by **removing the unused dependency** and correcting the README. |
| **CVE-2024-36039** (PyMySQL SQL injection via `escape_dict`) | **Present in the dependency tree, not reachable in current code.** All database access uses SQLAlchemy ORM expressions plus static `text()` DDL; no attacker-controlled dictionary keys reach `pymysql.escape_dict()`. Fixed by upgrading to `PyMySQL==1.2.3` (fixed upstream in 1.1.1). |

Beyond those, the review found and fixed several real application-level issues,
the most important being **stored XSS through DMARC report fields**, **missing
OIDC `state`/PKCE protection**, **fail-open SSO authorization**, and
**decompression bombs in the IMAP attachment extractor**.

---

## 2. Dependency findings

| Package | Before | Advisory | Exploitable today? | After |
|---------|--------|----------|--------------------|-------|
| `authlib` | 1.3.0 | **CVE-2026-27962** / GHSA-wvwj-cvrp-7pv5 — JWS JWK header injection → signature verification bypass (CVSS 3.1 9.1, CWE-347). Versions `<= 1.6.8` affected, fixed in `1.6.9`. | No — never imported. | **Removed** |
| `PyMySQL` | 1.1.0 | **CVE-2024-36039** — SQL injection via unescaped keys in `escape_dict()` (fixed 1.1.1). | No — no dict-style parameter binding with untrusted keys. | **1.2.3** |
| `requests` | 2.31.0 | CVE-2024-35195 (`Session` keeps `verify=False` on pooled connections, fixed 2.32.0); CVE-2024-47081 (`.netrc` credential leak via crafted URLs, fixed 2.32.4); CVE-2026-25645 (`extract_zipped_paths()` temp-file reuse, fixed 2.33.0). | Partially — `auth.py` used default `trust_env=True`. | **2.34.2** |
| `streamlit` | `>=1.35.0` (unpinned) | CVE-2024-42474 (Windows path traversal, 1.37.0); CVE-2026-33682 / GHSA-7p48-42j8-8846 (Windows SSRF + NTLM hash exposure, 1.54.0); CVE-2026-10804 (weak cache hash, 1.53.1). | Windows-only issues do not apply to the Linux image, but the unbounded range allowed drift onto vulnerable builds. | **1.66.0** |
| `python-dotenv` | 1.0.1 | CVE-2026-28684 — symlink following in `set_key()` allows arbitrary file overwrite (fixed 1.2.2). | No — never imported (`env_file` in Compose is used instead). | **Removed** |
| `pandas` | 2.2.1 | None affecting this version. | — | **2.2.3** (patch) |
| `SQLAlchemy` | 2.0.29 | None affecting this version. | — | **2.0.55** (patch) |
| `xmltodict` | 0.13.0 | None affecting this version. Entity expansion is disabled by default (`disable_entities=True`); we now pass it explicitly. | — | **0.15.1** |
| `plotly` | `>=5.18.0` | None affecting this version. | — | **5.24.1** (last 5.x) |

> Patch-level upgrades were deliberately chosen for pandas / SQLAlchemy /
> xmltodict / plotly to avoid unrelated breaking changes in a security release.

---

## 3. Application findings and fixes

### High

1. **Stored XSS in dashboard HTML rendering.**
   `st.markdown(..., unsafe_allow_html=True)` interpolated values originating
   from inbound DMARC XML (`org_name`, `domain`, policy `p`) and from
   reverse-DNS PTR records (`host_name`). A malicious or compromised reporting
   organization could inject markup into `domains.py`, `components.py`
   (`metric_card`, `section_header`, `source_badge`, `status_indicator`) and
   execute JavaScript in the dashboard origin.
   **Fix:** `app/security.py::escape_html()` applied to every interpolated
   value, hex-colour validation for CSS values, and Markdown escaping for the
   Reports tab headings.

2. **OIDC login had no CSRF/`state` protection, no PKCE, no timeouts and leaked
   provider responses.**
   `authenticate_keycloak()` exchanged whatever `?code=` was supplied.
   **Fix:** HMAC-signed, TTL-bound `state` (`AUTH_STATE_SECRET`), PKCE `S256`
   with a verifier derived from the signed state (survives the Streamlit
   session reset caused by the redirect), `nonce`, 10 s connect / 15 s read
   timeouts, `allow_redirects=False` on token/userinfo calls, and
   `requests.Session(trust_env=False)` to avoid `.netrc` lookups. Users see
   generic errors; detailed diagnostics are logged server-side only.

3. **Fail-open SSO authorization.**
   When `KEYCLOAK_EMAIL_ACCOUNT` was empty, every authenticated user of the
   realm received full access.
   **Fix:** the allow-list is now **required** for `AUTH_METHOD=keycloak`
   (comma-separated addresses supported); `email_verified=false` is rejected;
   incomplete configuration refuses login with an explicit message.

4. **Account login weaknesses.**
   Non-constant-time `==` comparison, empty credentials accepted when both env
   vars were unset, no brute-force protection, and reCAPTCHA was decorative
   (an informational banner that was never verified).
   **Fix:** `hmac.compare_digest`, configuration validated before login is
   offered, per-session attempt counter with lockout
   (`LOGIN_MAX_ATTEMPTS`, default 5), and server-side reCAPTCHA verification
   when `RECAPTCHA_CLIENTSECRET` is configured (fails closed without a token).

5. **No logout / session invalidation.**
   **Fix:** `auth.logout()` plus a "Sign out" sidebar button; clears
   `authenticated`, OIDC state, attempt counters and query parameters.

### Medium

6. **Decompression and attachment bombs** (`fetcher.py`): `ZipFile.read()` and
   `GzipFile.read()` were unbounded. **Fix:** `MAX_ATTACHMENT_MB` (25),
   `MAX_XML_MB` (10), `MAX_ARCHIVE_UNCOMPRESSED_MB` (50) and
   `MAX_ZIP_ENTRIES` (10) enforced with bounded reads that abort as soon as a
   limit is crossed.
7. **Global socket timeout mutation** (`parser.py`): `socket.setdefaulttimeout(1.0)`
   was never restored, silently affecting database and IMAP sockets.
   **Fix:** the previous value is restored in `finally`, reverse-DNS results are
   cached per process, and `ipaddress` validation runs before any lookup.
8. **Malformed-report DoS / report suppression** (`parser.py`): raw `int()` /
   `datetime.fromtimestamp()` on untrusted XML, unbounded strings rejected by
   MySQL column limits, and a globally unique `report_id` (RFC 7489 scopes
   uniqueness to reporter + ID). **Fix:** safe numeric/timestamp parsing,
   truncation to column widths, XML size cap, explicit
   `disable_entities=True`, dedupe and unique key on
   `(report_id, org_name, domain)` with a guarded online migration.
9. **IMAP connection leak and mailbox-name injection** (`fetcher.py`): the
   connection was only closed on the success path and folder names were
   interpolated into IMAP commands. **Fix:** `try/finally` close/logout and
   strict validation + quoting of every mailbox name (CR/LF/NUL rejected).
10. **Database URL built by string interpolation** (`models.py`): passwords
    containing `@`, `:` or `/` broke the URL and could leak into logs.
    **Fix:** `sqlalchemy.URL.create()`, optional `DB_SSL_CA` TLS,
    `pool_pre_ping`/`pool_recycle`, and a loud warning when the default
    password is used.
11. **Container hardening** (`Dockerfile`): ran as root and shipped `gcc` +
    `default-libmysqlclient-dev`, which PyMySQL does not need.
    **Fix:** pinned `python:3.11-slim-bookworm`, no build toolchain,
    unprivileged uid 10001, healthcheck, explicit XSRF/CORS settings.
12. **No dependency scanning or tests in CI.** **Fix:** new
    `.github/workflows/security.yml` runs `pip-audit --no-deps --strict`
    (push, PR, weekly cron) and the unit test suite.

### Low

13. Login link `href` built from environment values without HTML escaping →
    escaped.
14. XML entity handling is now explicit rather than relying on library defaults.
15. Bare `int()` on environment values (`FETCH_INTERVAL`, `IMAP_PORT`,
    `REPORT_RETENTION_DAYS`) → `env_int()` with clamping.
16. README listed Authlib as the SSO stack and python-dotenv as a dependency →
    corrected.

---

## 4. Changed files

| File | Change |
|------|--------|
| `plans/2026-10-18-security-audit-and-remediation.md` | This document. |
| `app/security.py` | **New.** Stdlib-only helpers: HTML/Markdown escaping, truncation, bounded integer/timestamp parsing, constant-time comparison, signed OIDC state, PKCE derivation, mailbox validation/quoting, bounded reads, safe hex colours. |
| `app/auth.py` | Rewritten OIDC/account authentication. Public API (`require_auth`) preserved; `logout()` added. |
| `app/parser.py` | Size/entity limits, safe parsing, truncation, single transaction, reverse-DNS timeout restore + cache, composite report identity. |
| `app/fetcher.py` | Archive/attachment limits, TLS context, quoted mailbox names, guaranteed logout, bounded extraction. |
| `app/models.py` | `URL.create()`, optional DB TLS, pool settings, composite unique key + guarded migration, safer env parsing. |
| `app/main.py` | Env-driven Streamlit port/address, XSRF/CORS flags, startup warning for `AUTH_METHOD=none`. |
| `app/dashboard/components.py` | HTML escaping + colour validation. |
| `app/dashboard/domains.py` | HTML escaping for domain/policy values. |
| `app/dashboard/reports.py` | Markdown escaping for report metadata. |
| `app/dashboard/main.py` | Sign-out button, calls `auth.logout()`. |
| `requirements.txt` | Removed `authlib` + `python-dotenv`; pinned patched versions. |
| `Dockerfile` | Non-root, no compiler toolchain, healthcheck, pinned base. |
| `docker/docker-compose.yml` | `no-new-privileges`, drop all capabilities, healthcheck. |
| `docker/.env.example` | Template entries for the new settings. |
| `app/.streamlit/config.toml` | **New.** XSRF/CORS/headless/upload limit. |
| `.gitignore`, `.dockerignore` | **New.** Also stops tracking `__pycache__` bytecode that was previously committed. |
| `.github/workflows/security.yml` | **New.** pip-audit + unit tests. |
| `tests/test_security.py`, `tests/test_archive_limits.py`, `tests/test_auth_flow.py` | **New.** Dependency-free regression tests (escaping, signed state/PKCE, mailbox quoting, size limits, OIDC allow-list). |
| `README.md` | Corrected dependency table, documented new settings and security posture. |

---

## 5. New / changed configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUTH_STATE_SECRET` | — (**required** for `keycloak`) | HMAC key for signed OIDC `state` / derived PKCE verifier. Generate with `openssl rand -hex 32` (Python is not required). Rotating it invalidates in-flight logins only. |
| `AUTH_STATE_TTL_SECONDS` | `300` | Maximum age of a signed login state (60–3600). |
| `KEYCLOAK_EMAIL_ACCOUNT` | — (**required** for `keycloak`) | Comma-separated allow-list of email addresses. |
| `ALLOW_INSECURE_IDP` | `false` | Allow `http://` issuer/redirect URLs (loopback development only). |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed account logins per browser session before lockout. |
| `MAX_ATTACHMENT_MB` | `25` | Maximum size of a single mail attachment. |
| `MAX_XML_MB` | `10` | Maximum size of a single XML report (after decompression). |
| `MAX_ARCHIVE_UNCOMPRESSED_MB` | `50` | Total uncompressed budget per archive. |
| `MAX_ZIP_ENTRIES` | `10` | Maximum XML entries read from a single ZIP. |
| `DB_PORT` | `3306` | Database port. |
| `DB_SSL_CA` | — | CA bundle path; enables TLS to MariaDB when set. |

---

## 6. Breaking changes / migration notes

1. `AUTH_METHOD=keycloak` now **requires** `KEYCLOAK_EMAIL_ACCOUNT` (comma list
   allowed) and `AUTH_STATE_SECRET`. Without them, login is refused with an
   explicit configuration error. This is intentional fail-closed behaviour.
2. `AUTH_METHOD=account` refuses empty credentials; after
   `LOGIN_MAX_ATTEMPTS` failures the session is locked until it is restarted.
3. If `RECAPTCHA_CLIENTSECRET` is set, a verification token is required —
   previously reCAPTCHA was never checked. Deployments that set only
   `RECAPTCHA_CLIENTID` are unaffected.
4. `authlib` and `python-dotenv` were removed. No code imported them.
5. On first start, `init_db()` drops a legacy single-column unique index on
   `reports.report_id` (if present) and adds
   `uq_reports_identity (report_id, org_name, domain)`. Failures are logged and
   non-fatal; the application continues with the old index.
6. Streamlit `1.66.0` supports the `width="stretch"` argument already used by
   the dashboard, so no code changes were required for the upgrade.

---

## 7. Verification performed

```bash
# Static checks
python -m compileall -q app tests

# Unit tests (stdlib only, no third-party dependencies required)
python -m unittest discover -s tests -v

# Dependency audit
pip-audit -r requirements.txt --no-deps --strict

# Container
docker compose -f docker/docker-compose.yml config
docker build -t dmarclyzer:audit .
```

Manual checks:

- `<script>alert(1)</script>` in a report `org_name` / `domain` renders as text.
- Callback with a missing, tampered or expired `state` is rejected.
- Callback without `KEYCLOAK_EMAIL_ACCOUNT` is rejected (fail closed).
- A ZIP with an oversized XML member is rejected without loading it fully.
- Container runs as uid 10001 and has no package build tooling.

### Actual results (2026-10-18)

- `python -m compileall -q app tests` — clean.
- `python -m unittest discover -s tests -v` — **48 tests, all passing**.
- `pip-audit -r requirements.txt --no-deps --strict` (run inside the built
  image) — **"No known vulnerabilities found"**.
- OSV `querybatch` against all seven pinned versions — no advisories.
- `docker build` — succeeded; `id` reports `uid=10001(app)`; all application
  modules (`security`, `models`, `parser`, `fetcher`, `auth`, `main`) import.
- Parser integration check (SQLite-backed): duplicate reports are skipped,
  the same `report_id` from two different reporters is stored twice, and
  `pct=150` is clamped to `100`.
- `docker compose config` — valid, with `cap_drop: [ALL]`,
  `no-new-privileges:true` and the healthcheck applied.


---

## 8. Residual risks (documented, not fully fixable here)

- **Login CSRF without a server-side session cookie.** Streamlit does not expose
  an API to mint HttpOnly session cookies, so OIDC `state` is bound to an
  HMAC-signed, short-lived token instead of a browser cookie. This prevents
  tampered/replayed/forged callbacks and authorization-code injection, but it
  cannot cryptographically bind the callback to the browser that started the
  flow. For internet-facing deployments, terminate authentication at an
  authenticating reverse proxy (oauth2-proxy, Traefik forward-auth, Authelia)
  and keep `AUTH_METHOD=none` only inside the trusted network.
- **Transport security is delegated to the reverse proxy.** The container
  serves plain HTTP on port 8080 and must be published through HTTPS.
- **DMARC XML content is still third-party data.** It is now escaped and size
  limited, but it remains untrusted input; treat dashboard output accordingly.
- **`AUTH_METHOD=none` remains the default** for backwards compatibility. A
  startup warning is logged when it is active.
- **Account lockout is per Streamlit browser session.** It raises the cost of
  online guessing, but a client that discards its session cookie starts over;
  use proxy-level rate limiting for internet-facing deployments.


---

## 9. References

- CVE-2026-27962 / GHSA-wvwj-cvrp-7pv5 — Authlib JWS JWK header injection
- CVE-2024-36039 — PyMySQL `escape_dict` SQL injection
- CVE-2024-35195, CVE-2024-47081, CVE-2026-25645 — Requests
- CVE-2024-42474, CVE-2026-33682, CVE-2026-10804 — Streamlit
- CVE-2026-28684 — python-dotenv
- RFC 7515 §4.1.3 / §5.2 — JWS `jwk` header MUST NOT be used as a key source
- RFC 7489 §7.2 — `Report-ID` uniqueness is scoped to the reporting organization
- RFC 7636 — Proof Key for Code Exchange (PKCE)
- OWASP ASVS v4.0.3 — V5.3 (output encoding), V3.1 (session management),
  V2.10 (service authentication)
