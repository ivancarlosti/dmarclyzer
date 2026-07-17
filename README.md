# DMARClyzer

🛡️ **Modern DMARC Aggregate Report Analyzer**

A unified, robust Python + Streamlit dashboard for ingesting, parsing, and visualizing DMARC aggregate reports — inspired by the dmarcian.com experience. Connects to your own MariaDB instance.

<!-- buttons -->
[![Stars](https://img.shields.io/github/stars/ivancarlosti/dmarclyzer?label=⭐%20Stars&color=gold&style=flat)](https://github.com/ivancarlosti/dmarclyzer/stargazers)
[![Watchers](https://img.shields.io/github/watchers/ivancarlosti/dmarclyzer?label=Watchers&style=flat&color=red)](https://github.com/sponsors/ivancarlosti)
[![Forks](https://img.shields.io/github/forks/ivancarlosti/dmarclyzer?label=Forks&style=flat&color=ff69b4)](https://github.com/sponsors/ivancarlosti)
[![Downloads](https://img.shields.io/github/downloads/ivancarlosti/dmarclyzer/total?label=Downloads&color=success)](https://github.com/ivancarlosti/dmarclyzer/releases)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/ivancarlosti/dmarclyzer?label=Activity)](https://github.com/ivancarlosti/dmarclyzer/pulse)
[![GitHub Issues](https://img.shields.io/github/issues/ivancarlosti/dmarclyzer?label=Issues&color=orange)](https://github.com/ivancarlosti/dmarclyzer/issues)  
[![License](https://img.shields.io/github/license/ivancarlosti/dmarclyzer?label=License)](LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/ivancarlosti/dmarclyzer?label=Last%20Commit)](https://github.com/ivancarlosti/dmarclyzer/commits)
[![Security](https://img.shields.io/badge/Security-View%20Here-purple)](https://github.com/ivancarlosti/dmarclyzer/security)
[![Code of Conduct](https://img.shields.io/badge/Code%20of%20Conduct-2.1-4baaaa)](https://github.com/ivancarlosti/dmarclyzer?tab=coc-ov-file)
<!-- endbuttons -->

---

## Features

### 📥 Automated Report Ingestion
- **IMAP Polling Daemon** — Continuously connects to your IMAP inbox (configurable interval, default every 5 minutes), detects unread emails, and extracts DMARC aggregate XML attachments.
- **Multi-format Extraction** — Supports `.zip`, `.gz`, and raw `.xml` attachments. Handles nested archives automatically.
- **Message Management** — Optionally moves processed emails to success/failure folders and marks originals for deletion. Keeps your inbox clean.
- **Deduplication** — Each `report_id` is stored uniquely — re-ingesting the same report is safely skipped.

### 🔬 Comprehensive Parsing
- **Full XML Schema Support** — Parses `report_metadata`, `policy_published`, individual `record` entries, `auth_results` (DKIM & SPF), `policy_evaluated` disposition, and policy override reasons.
- **Reverse DNS Resolution** — Resolves each sending IP's hostname at parse time for enriched source analysis.
- **Granular Auth Tracking** — Stores DKIM selectors, domains, and results; SPF domains and results — all linked to individual records.

### 📊 Rich Dashboard (4 Tabs)

#### 📊 Overview
- **DMARC Compliance Gauge** — Interactive Plotly gauge (0-100%) with color zones showing overall email authentication health.
- **Key Metric Cards** — Total messages, DMARC pass rate, unique sending IPs in clean KPI tiles.
- **Volume Over Time** — Stacked area chart of daily email volume colored by DMARC disposition (none/quarantine/reject).
- **Disposition Donut** — Proportional breakdown of how receivers are handling your mail.
- **DKIM vs SPF Alignment** — Side-by-side grouped bar comparing pass/fail rates per protocol.
- **Policy Distribution** — Stacked bar chart showing DMARC policy modes (p=none/quarantine/reject) across all domains.
- **Quick Stats Footer** — DKIM pass rate, SPF pass rate, forwarded mail count, failing mail count.

#### 🔍 Sources
- **Source Classification** — Every sending IP categorized into 4 buckets:
  - ✅ **Compliant** — DKIM & SPF both aligned, DMARC passing
  - ↗️ **Forwarded** — SPF broken (typical of mailing lists) but DKIM intact
  - ⚠️ **DKIM Issue** — DKIM failing while SPF passes (misconfiguration)
  - ❌ **Failing** — Both DKIM & SPF failing (potential threats)
- **Category Summary Cards** — Volume and percentage per category at a glance.
- **Top 10 Sending IPs** — Horizontal bar chart of highest-volume sources, color-coded by category.
- **Forwarded Mail Analysis** — Dedicated view of forwarders where SPF breaks but DKIM survives.
- **DKIM/SPF Alignment Matrix** — Heatmap showing message distribution across all 4 alignment combinations.

#### 🌐 Domains
- **Domain Metric Cards** — Per-domain cards showing volume, DMARC pass rate, DKIM %, SPF %, policy, and unique IP count. Cards are color-coded (green border = healthy ≥70%).
- **Domain Comparison Table** — Sortable table with all domain metrics side-by-side.
- **Policy Distribution by Domain** — Grouped bar chart of p=none/quarantine/reject per domain.
- **Policy Adoption Timeline** — Line chart tracking policy changes over time per domain (≤5 domains), faceted bar chart (6-10 domains), or aggregated view (>10 domains).

#### 📋 Reports
- **Master Report List** — Filterable table of every ingested DMARC report with columns: Start Date, End Date, Domain, Reporting Organization, Report ID, Messages.
- **IP-Level Drill-down** — Click any report row to expand the full IP inspection array with 12 columns: IP Address, Hostname, Message Count, Disposition, Reason, DKIM Domain, DKIM Auth, SPF Domain, SPF Auth, DKIM Alignment, SPF Alignment, DMARC Pass/Fail.
- **Auth Result Integration** — DKIM and SPF auth results are joined per record from the `auth_results` table, showing exactly which domains and selectors were validated.

### 🔐 Flexible Authentication
Three auth modes configurable via environment variable:

| Mode | Description |
|------|-------------|
| `none` | No authentication (default, open access) |
| `account` | Username/password login with optional ReCaptcha support |
| `keycloak` | OpenID Connect SSO via Keycloak with email restriction |

### 🌐 Reverse Proxy Ready
- Configurable `PORT` and `DOMAIN` environment variables for seamless integration behind Nginx, Traefik, Caddy, or any reverse proxy.
- Internal container port always `8080`.

### 🗄️ External Database
- Connects to **your own MariaDB** instance (localhost, remote, or containerized).
- Three normalized tables auto-created on first run: `reports` (metadata + policy), `records` (IP-level data), `auth_results` (DKIM/SPF validation details).
- Automatic schema migration for existing databases.
- `host.docker.internal` support for connecting to MariaDB running on the Docker host.

---

## Architecture

```
┌───────────────────────┐      ┌─────────────────────────┐
│    Docker Container    │      │   Your MariaDB Instance  │
│                        │      │   (external, user-owned) │
│  ┌──────────────────┐  │      │                         │
│  │   dmarclyzer_app │  │      │  ┌───────────────────┐  │
│  │                  │  │ SQL  │  │ reports            │  │
│  │  ┌────────────┐  │  │─────►│  │ records            │  │
│  │  │ IMAP Fetch │  │  │      │  │ auth_results       │  │
│  │  │ (fetcher)  │  │  │      │  └───────────────────┘  │
│  │  └─────┬──────┘  │  │      └─────────────────────────┘
│  │        │         │  │
│  │  ┌─────▼──────┐  │  │
│  │  │ XML Parse  │  │  │
│  │  │ (parser)   │  │  │
│  │  └─────┬──────┘  │  │
│  │        │         │  │
│  │  ┌─────▼──────┐  │  │
│  │  │ Streamlit  │──┼──┼──► Port 8080
│  │  │ Dashboard  │  │  │    (configurable)
│  │  └────────────┘  │  │
│  └──────────────────┘  │
└───────────────────────┘
```

### Project Structure

```
dmarclyzer/
├── app/
│   ├── main.py                  # Entry point: starts fetcher thread + Streamlit
│   ├── fetcher.py               # IMAP polling + attachment extraction
│   ├── parser.py                # XML parsing + MariaDB insertion
│   ├── models.py                # SQLAlchemy ORM models + DB init
│   ├── auth.py                  # Authentication (none/account/keycloak)
│   └── dashboard/               # Dashboard package (9 modules)
│       ├── __init__.py          # Package init
│       ├── main.py              # Tab navigation + sidebar + session state
│       ├── overview.py          # Overview tab (gauge, KPIs, charts)
│       ├── sources.py           # Sources tab (classification, alignment)
│       ├── domains.py           # Domains tab (per-domain metrics, policies)
│       ├── reports.py           # Reports tab (master list + IP drill-down)
│       ├── queries.py           # Shared SQL queries (10+ cached functions)
│       ├── components.py        # Reusable widgets (gauges, badges, headers)
│       └── styles.py            # Color palette, CSS, Plotly theme
├── docker/
│   ├── docker-compose.yml       # Single-service container stack
│   └── .env                     # Configuration template
├── Dockerfile                   # Python 3.11-slim image
├── requirements.txt             # Python dependencies
├── LICENSE                      # MIT License
└── README.md                    # This file
```

---

## Setup Instructions

### Prerequisites
- Docker & Docker Compose installed
- **A running MariaDB instance** (local, remote, or containerized) — DMARClyzer does not bundle a database
- An IMAP inbox that receives DMARC aggregate reports (e.g., `dmarc@yourdomain.com`)

### 1. Configure Environment

Navigate into the `docker` directory and edit the `.env` file with your credentials:

```bash
cd docker
nano .env
```

**Required settings:**
```env
# IMAP Connection
IMAP_SERVER=imap.example.com
IMAP_PORT=993
IMAP_USER=dmarc@example.com
IMAP_PASSWORD=your_imap_password
IMAP_FOLDER=INBOX

# Database (point to your external MariaDB)
DB_HOST=host.docker.internal
DB_NAME=dmarc
DB_USER=dmarcuser
DB_PASSWORD=dmarcpass

# Web Server
PORT=8080
```

**Optional settings:**
```env
# Message management after processing (leave blank to skip)
IMAP_MOVE_FOLDER=processed
IMAP_MOVE_FOLDER_ERR=error

# Polling interval in seconds (default: 300 = 5 minutes)
FETCH_INTERVAL=300

# Authentication (see Authentication Options section)
AUTH_METHOD=none
```

### 2. Start the Application

```bash
docker compose up -d
```

This starts the DMARClyzer container which will connect to your external MariaDB instance.

> **Note:** If your MariaDB runs on the Docker host (localhost), use `DB_HOST=host.docker.internal` in `.env`. The `docker-compose.yml` includes `extra_hosts` to resolve this automatically.

### 3. Access the Dashboard

Navigate to `http://localhost:8080` (or your configured `PORT`).

On first launch, the dashboard will auto-refresh up to 3 times while waiting for the initial IMAP fetch cycle to complete. Once reports are ingested, the full dashboard renders.

---

## Environment Variables Reference

### IMAP Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMAP_SERVER` | Yes | — | IMAP server hostname |
| `IMAP_PORT` | No | `993` | IMAP port (SSL) |
| `IMAP_USER` | Yes | — | IMAP login username/email |
| `IMAP_PASSWORD` | Yes | — | IMAP login password |
| `IMAP_FOLDER` | No | `INBOX` | Mailbox folder to monitor |
| `IMAP_MOVE_FOLDER` | No | — | Move successfully processed emails here |
| `IMAP_MOVE_FOLDER_ERR` | No | — | Move failed emails here |
| `FETCH_INTERVAL` | No | `300` | Seconds between IMAP poll cycles |

### Database Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_HOST` | No | `host.docker.internal` | MariaDB hostname or IP |
| `DB_NAME` | No | `dmarc` | Database name |
| `DB_USER` | No | `dmarcuser` | Database user |
| `DB_PASSWORD` | No | `dmarcpass` | Database password |

### Web Server & Proxy

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `8080` | Host port mapping for the dashboard |
| `DOMAIN` | No | — | Public domain for reverse proxy reference |

### Authentication

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTH_METHOD` | No | `none` | `none`, `account`, or `keycloak` |
| `ACCOUNT_LOGIN` | No | — | Username for `account` auth |
| `ACCOUNT_PASSWORD` | No | — | Password for `account` auth |
| `RECAPTCHA_CLIENTID` | No | — | ReCaptcha site key (account auth) |
| `RECAPTCHA_CLIENTSECRET` | No | — | ReCaptcha secret (account auth) |
| `KEYCLOAK_BASE_URL` | No | — | Keycloak server URL |
| `KEYCLOAK_REALM` | No | — | Keycloak realm name |
| `KEYCLOAK_CLIENT_ID` | No | — | Keycloak client ID |
| `KEYCLOAK_CLIENT_SECRET` | No | — | Keycloak client secret |
| `KEYCLOAK_REDIRECT_URI` | No | — | OAuth2 redirect URI |
| `KEYCLOAK_EMAIL_ACCOUNT` | No | — | Restrict access to this email |

---

## Authentication Options

### None (Default)
```env
AUTH_METHOD=none
```
Dashboard is publicly accessible. No login required.

### Account (Username/Password)
```env
AUTH_METHOD=account
ACCOUNT_LOGIN=admin
ACCOUNT_PASSWORD=your_secure_password
```
Simple form-based login. Optionally add ReCaptcha by setting `RECAPTCHA_CLIENTID` and `RECAPTCHA_CLIENTSECRET`.

### Keycloak (SSO)
```env
AUTH_METHOD=keycloak
KEYCLOAK_BASE_URL=https://sso.example.com
KEYCLOAK_REALM=YourRealm
KEYCLOAK_CLIENT_ID=dmarclyzer
KEYCLOAK_CLIENT_SECRET=your_client_secret
KEYCLOAK_REDIRECT_URI=https://dmarclyzer.example.com/
KEYCLOAK_EMAIL_ACCOUNT=you@example.com
```
OpenID Connect flow with optional email restriction. Redirects to Keycloak login, exchanges authorization code for tokens, and verifies user info.

---

## Reverse Proxy

DMARClyzer works seamlessly behind Nginx, Traefik, Caddy, or any reverse proxy:

1. Set `PORT` in `.env` to your desired host port (container internally uses `8080`).
2. Point your reverse proxy upstream to `localhost:<PORT>`.
3. Optionally set `DOMAIN` for proxy configuration references.

**Example Nginx config:**
```nginx
server {
    listen 443 ssl;
    server_name dmarclyzer.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Data Flow

1. **Fetch** — [`fetcher.py`](app/fetcher.py) connects to IMAP via SSL, searches for unseen messages, extracts `.zip`/`.gz`/`.xml` attachments, and moves processed messages to configured folders.
2. **Parse** — [`parser.py`](app/parser.py) uses `xmltodict` to parse the DMARC aggregate XML schema, resolves reverse DNS for each IP, and inserts normalized data into MariaDB via SQLAlchemy ORM.
3. **Store** — Data lands in 3 tables:
   - `reports` — One row per DMARC report (metadata + published policy)
   - `records` — One row per IP/source in each report (disposition, alignment, count)
   - `auth_results` — DKIM/SPF validation details linked to records
4. **Visualize** — Streamlit dashboard queries MariaDB with cached aggregation queries (300s TTL), renders Plotly interactive charts, and provides filterable drill-down tables.

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Python 3.11 |
| Dashboard | Streamlit ≥1.35 |
| Charts | Plotly ≥5.18 |
| Database | MariaDB (external, user-provided) |
| ORM | SQLAlchemy 2.0 |
| DB Driver | PyMySQL |
| IMAP | Python stdlib `imaplib` |
| XML Parsing | xmltodict |
| Auth (SSO) | Authlib + Requests |
| Containerization | Docker + Docker Compose |

---

## Troubleshooting

**Dashboard shows "No DMARC reports found":**
- Verify IMAP credentials in `.env` are correct.
- Check that your DMARC reporting email address is receiving aggregate XML reports.
- Wait for the first fetch cycle (default 5 minutes) — the dashboard auto-refreshes up to 3 times.
- Check container logs: `docker compose logs dmarclyzer_app`

**IMAP connection fails:**
- Ensure `IMAP_SERVER` and `IMAP_PORT` are correct (port 993 is standard for IMAPS).
- For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833) and set `IMAP_FOLDER` carefully (Gmail labels are case-sensitive).
- Verify the email account has IMAP access enabled.

**Dashboard loads but charts are empty:**
- Adjust the date range filter in the sidebar — it defaults to the last 7 days.
- Ensure at least one Domain and one Organization are selected in the sidebar filters.
- Click "Refresh Data" in the sidebar to clear the query cache.

**Port conflict:**
- Change `PORT` in `.env` to an available port (e.g., `8081`).

---

## Sample Screenshots

<img width="1234" height="887" alt="image" src="https://github.com/user-attachments/assets/8840ea10-0696-4952-a397-7a7e66908d70" />
<img width="1265" height="763" alt="image" src="https://github.com/user-attachments/assets/5c6c44c2-546c-4757-ac09-b1a7a2c5800a" />
*Overview tab — DMARC Compliance Overview, Email Volume Over Time, Disposition Distribution, DKIM vs SPF Alignment, DMARC Policy Distribution*

<img width="1038" height="580" alt="image" src="https://github.com/user-attachments/assets/94e206c9-bbad-4b45-a573-cc53bff477f2" />
<img width="1042" height="740" alt="image" src="https://github.com/user-attachments/assets/34230b26-89f8-4470-a6b9-d18254c16ab2" />
*Sources tab — Source Classification, All Sending Sources, Top 10 Sending IPs, Forwarded Mail Analysis, DKIM/SPF Alignment Matrix*

<img width="1075" height="877" alt="image" src="https://github.com/user-attachments/assets/4c56d1a7-a955-43a1-8aae-95b4f22220ea" />
*Domains tab — Domain Overview, Domain Comparison, Policy Distribution by Domain, Policy Adoption Timeline*

<img width="992" height="807" alt="image" src="https://github.com/user-attachments/assets/ce1b4b0a-8147-4991-be34-f801ce675f26" />
*Reports tab — Available DMARC Reports*

<!-- footer -->
---

## 🧑‍💻 Consulting and Technical Support

* For personal support and queries, please submit a new issue to have it addressed.
* For commercial related questions, please [**contact me**][ivancarlos] for consulting costs.

[cc]: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-code-of-conduct-to-your-project
[contributing]: https://docs.github.com/en/articles/setting-guidelines-for-repository-contributors
[security]: https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository
[support]: https://docs.github.com/en/articles/adding-support-resources-to-your-project
[it]: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository#configuring-the-template-chooser
[prt]: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/creating-a-pull-request-template-for-your-repository
[funding]: https://docs.github.com/en/articles/displaying-a-sponsor-button-in-your-repository
[ivancarlos]: https://ivancarlos.me
