# Dashboard screenshots

The PNG files in this directory are real captures of the Streamlit dashboard
running against **synthetic DMARC data**. They are used by the project README
and contain no production, customer or personal data:

- every monitored domain uses the reserved `.example` TLD;
- every sender IP comes from an RFC 5737 documentation range
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`);
- reporter organization names are real mailbox providers, but the report IDs,
  message counts and hostnames are fabricated.

The fixtures are deterministic for a given seed and day, so the images can be
regenerated instead of manually edited.

## Gallery

| File | View |
| :--- | :--- |
| `overview-summary.png` | Overview — compliance gauge, KPI cards, email volume over time |
| `overview-details.png` | Overview — disposition donut, DKIM/SPF alignment, policy distribution |
| `sources-summary.png` | Sources — classification cards and all sending sources |
| `sources-details.png` | Sources — top 10 IPs, forwarded mail analysis, alignment matrix |
| `domains-summary.png` | Domains — per-domain cards and comparison table |
| `domains-policies.png` | Domains — comparison table, policy distribution and adoption timeline |
| `reports-list.png` | Reports — available DMARC reports |
| `reports-detail.png` | Reports — selected report with IP-level drill-down |

All captures use a 1600 × 1000 viewport at device scale factor 1.

## Regenerate

### Prerequisites

- Python 3.11 or newer
- Docker with a reachable daemon (the script starts a disposable
  `mariadb:11.4` container)
- Google Chrome or Chromium, **or** a Playwright-managed Chromium build
- Linux, macOS or Windows with a shell; the script was written and validated
  on Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r scripts/requirements-screenshots.txt

# Optional: only needed when no system Chrome/Chromium is installed
python -m playwright install chromium

python scripts/generate_screenshots.py
```

The command creates or replaces the eight PNG files in this directory. It
prints each file's dimensions and size and fails if a capture is missing,
smaller than 10 KiB, or not exactly the requested viewport size.

### What the script does

1. Starts a throwaway MariaDB container on a free loopback port.
2. Runs `scripts/seed_demo_data.py`, which creates 14 days of synthetic
   reports for four `.example` domains and four reporter organizations.
3. Starts the dashboard with `AUTH_METHOD=none` on another free loopback port.
4. Opens the dashboard with Playwright, switches through all four tabs, and
   captures the summary and detail views.
5. Stops Streamlit and removes the database container, even when a capture
   fails.

### Options

| Option | Default | Purpose |
| :--- | :--- | :--- |
| `--output DIR` | `docs/screenshots` | Directory for the PNG files |
| `--seed N` | `42` | Seed for the synthetic data generator |
| `--days N` | `14` | Days of historical reports to create |
| `--viewport WxH` | `1600x1000` | Browser viewport and required PNG size |
| `--headed` | off | Show the browser while capturing (needs a display) |
| `--keep` | off | Leave Streamlit and MariaDB running for debugging |

`--keep` prints the dashboard URL, the database port and the cleanup command.
The container is named `dmarclyzer-shots-<pid>`.

### Changing the fixture data

Edit `scripts/seed_demo_data.py` to adjust domains, reporter organizations,
sender pools, policy schedules or message volumes. `generate_screenshots.py`
always calls the seeder with `--reset`, which replaces the demo rows. For a
manual run, pass `--reset` yourself; without it the seeder refuses to touch a
database that already contains reports. Use a disposable database only and
never point the seeder at production.

## Troubleshooting

**`docker was not found` / `The Docker daemon is not reachable`**  
Start Docker and confirm `docker info` succeeds for the current user.

**`Could not launch Chromium`**  
Install Google Chrome/Chromium, or run
`python -m playwright install chromium`. The script prefers a system Chrome
installation and falls back to Playwright's bundled Chromium.

**The Reports drill-down capture fails**  
Streamlit renders the report table with Glide Data Grid, whose selection
controls live on a canvas. `select_report_row()` clicks a small set of
element-relative coordinates and verifies that the "Report from …" heading
appeared. If a future Streamlit version changes the grid layout, update those
coordinates. The script intentionally fails instead of saving a screenshot
without the drill-down.

**Charts are empty or clipped**  
Re-run the script; it scrolls through each tab to force Plotly to mount every
chart. If the issue persists, try `--headed` to observe the browser and check
the Streamlit log path printed by the script.

**Port conflicts**  
None of the default ports are hard-coded: both the database and Streamlit use
ephemeral loopback ports. A conflict therefore indicates another process
racing for the same port; simply rerun.
