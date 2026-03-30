# DMARClyzer

🛡️ **Modern DMARC Aggregate Report Analyzer**
Replaces old web stacks with a unified, robust Python + Streamlit dashboard and a MariaDB backend.

<!-- buttons -->

<!-- endbuttons -->

## Features
- **Automated IMAP Polling**: Continuously fetches and extracts `.zip`, `.gz`, and `.xml` DMARC aggregate reports from your inbox.
- **Robust Parsing**: Thoroughly processes aggregate data including IP disposition, DKIM, and SPF validation metrics.
- **Beautiful Dashboard**: A zero-config Streamlit dashboard providing at-a-glance health metrics for your sending domains.

## Setup Instructions

1. **Configure Environment:**
   Navigate into the `docker` directory and adjust the template environment variables:
   ```bash
   cd docker
   cp .env .env.local
   # Edit .env.local with your real IMAP credentials, DB passwords, and target Port
   ```

2. **Start the Application:**
   Boot up the Python parsing daemon, Streamlit dashboard, and MariaDB container:
   ```bash
   docker compose --env-file .env.local up -d --build
   ```

3. **Access the Dashboard:**
   Navigate your web browser to `http://localhost:8080` (or whichever `PORT` you configured in your `.env.local`).

## Reverse Proxy Options
This application natively supports being securely routed behind a reverse proxy like Nginx or Traefik.  
To set it up:
1. Ensure the `PORT` in your `.env.local` accurately maps to your reverse proxy's upstream route (the container internally exposes `8080`).
2. Utilize the `DOMAIN` variable within `.env.local` to formally set your URL for proxy routing references (like Nginx Proxy Manager configurations).

---

*(Single Sign-On (SSO) Support is planned for future releases.)*

<!-- footer -->
