# DMARClyzer

🛡️ **Modern DMARC Aggregate Report Analyzer**
Replaces old web stacks with a unified, robust Python + Streamlit dashboard and a MariaDB backend.

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
[![GitHub Sponsors](https://img.shields.io/github/sponsors/ivancarlosti?label=GitHub%20Sponsors&color=ffc0cb)][sponsor]
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00)][buymeacoffee]
[![Patreon](https://img.shields.io/badge/Patreon-f96854)][patreon]
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
---

## 🧑‍💻 Consulting and technical support
* For personal support and queries, please submit a new issue to have it addressed.
* For commercial related questions, please [**contact me**][ivancarlos] for consulting costs. 

| 🩷 Project support |
| :---: |
If you found this project helpful, consider [**buying me a coffee**][buymeacoffee]
|Thanks for your support, it is much appreciated!|

[cc]: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-code-of-conduct-to-your-project
[contributing]: https://docs.github.com/en/articles/setting-guidelines-for-repository-contributors
[security]: https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository
[support]: https://docs.github.com/en/articles/adding-support-resources-to-your-project
[it]: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository#configuring-the-template-chooser
[prt]: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/creating-a-pull-request-template-for-your-repository
[funding]: https://docs.github.com/en/articles/displaying-a-sponsor-button-in-your-repository
[ivancarlos]: https://ivancarlos.me
[buymeacoffee]: https://buymeacoffee.com/ivancarlos
[patreon]: https://www.patreon.com/ivancarlos
[paypal]: https://icc.gg/donate
[sponsor]: https://github.com/sponsors/ivancarlosti
