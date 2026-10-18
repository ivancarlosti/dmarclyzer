#!/usr/bin/env python3
"""Generate the README screenshots from a real, seeded Streamlit instance.

The script starts a disposable MariaDB container, seeds it with synthetic
DMARC data (``scripts/seed_demo_data.py``), launches the dashboard on a free
loopback port, captures each documented view with Playwright, and shuts
everything down again.

Prerequisites:
    pip install -r requirements.txt -r scripts/requirements-screenshots.txt
    docker (or podman with a docker-compatible CLI)
    Google Chrome, Chromium, or a Playwright-managed Chromium build

Examples:
    python scripts/generate_screenshots.py
    python scripts/generate_screenshots.py --keep --headed
    python scripts/generate_screenshots.py --viewport 1440x900 --seed 7

The generated images contain no production data: every domain uses the
reserved ``.example`` TLD and every IP is from an RFC 5737 documentation range.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
DEFAULT_OUTPUT = ROOT / "docs" / "screenshots"
DB_IMAGE = "mariadb:11.4"
DB_NAME = "dmarc"
DB_USER = "dmarcuser"
DB_PASSWORD = "dmarcpass"

# Keep screenshots visually clean without changing the application itself.
SCREENSHOT_CSS = """
#MainMenu, footer, header[data-testid="stHeader"],
[data-testid="stToolbar"], [data-testid="stDecoration"],
[data-testid="stStatusWidget"], [data-testid="stAppDeployButton"] {
    display: none !important;
}
html { scrollbar-width: none; }
::-webkit-scrollbar { width: 0 !important; height: 0 !important; }
"""


def log(message: str) -> None:
    print(f"[screenshots] {message}", flush=True)


def free_port() -> int:
    """Reserve a free localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_http(url: str, timeout: float = 60.0) -> None:
    """Wait until *url* returns a successful HTTP response."""
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if 200 <= response.status < 400:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def wait_for_db(port: int, timeout: float = 90.0) -> None:
    """Wait for MariaDB to accept connections."""
    import pymysql

    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            connection = pymysql.connect(
                host="127.0.0.1",
                port=port,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                connect_timeout=3,
            )
            connection.close()
            return
        except pymysql.err.OperationalError as exc:
            last_error = str(exc)
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for MariaDB on port {port}: {last_error}")


def start_database(port: int, container: str) -> None:
    """Start a disposable MariaDB container mapped to *port*."""
    subprocess.run(
        ["docker", "rm", "-f", container],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    log(f"Starting {DB_IMAGE} as {container} on 127.0.0.1:{port}")
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            container,
            "-e",
            f"MARIADB_ROOT_PASSWORD={DB_PASSWORD}",
            "-e",
            f"MARIADB_DATABASE={DB_NAME}",
            "-e",
            f"MARIADB_USER={DB_USER}",
            "-e",
            f"MARIADB_PASSWORD={DB_PASSWORD}",
            "-p",
            f"127.0.0.1:{port}:3306",
            DB_IMAGE,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    try:
        wait_for_db(port)
    except Exception:
        stop_database(container)
        raise


def stop_database(container: str) -> None:
    subprocess.run(
        ["docker", "rm", "-f", container],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def seed_database(port: int, days: int, seed: int) -> None:
    env = os.environ.copy()
    env.update(
        DB_HOST="127.0.0.1",
        DB_PORT=str(port),
        DB_NAME=DB_NAME,
        DB_USER=DB_USER,
        DB_PASSWORD=DB_PASSWORD,
    )
    log(f"Seeding {days} days of synthetic reports (seed={seed})")
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "seed_demo_data.py"),
            "--reset",
            "--days",
            str(days),
            "--seed",
            str(seed),
        ],
        env=env,
        check=True,
    )


def start_app(port: int, db_port: int) -> tuple[subprocess.Popen, Path]:
    """Launch Streamlit with auth disabled and the demo database configured."""
    log_path = Path(tempfile.gettempdir()) / f"dmarclyzer-streamlit-{os.getpid()}.log"
    env = os.environ.copy()
    env.update(
        DB_HOST="127.0.0.1",
        DB_PORT=str(db_port),
        DB_NAME=DB_NAME,
        DB_USER=DB_USER,
        DB_PASSWORD=DB_PASSWORD,
        AUTH_METHOD="none",
        PYTHONPATH=str(APP_DIR),
    )
    for key in ("DB_SSL_CA", "IMAP_HOST", "IMAP_USER", "IMAP_PASSWORD"):
        env.pop(key, None)

    log(f"Starting Streamlit on http://127.0.0.1:{port} (log: {log_path})")
    log_handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            "dashboard/main.py",
            "--server.address",
            "127.0.0.1",
            "--server.port",
            str(port),
            "--server.headless=true",
            "--server.fileWatcherType=none",
            "--browser.gatherUsageStats=false",
        ],
        cwd=APP_DIR,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    process._dmarclyzer_log_handle = log_handle  # type: ignore[attr-defined]

    try:
        wait_http(f"http://127.0.0.1:{port}/_stcore/health", timeout=90)
    except Exception:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        raise RuntimeError(f"Streamlit failed to start. Last log lines:\n{tail}")
    return process, log_path


def stop_app(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        with suppress(ProcessLookupError):
            os.killpg(os.getpgid(process.pid), 15)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(os.getpgid(process.pid), 9)
            process.wait(timeout=5)
    handle = getattr(process, "_dmarclyzer_log_handle", None)
    if handle is not None:
        handle.close()



def find_chrome() -> str | None:
    for name in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ):
        path = shutil.which(name)
        if path:
            return path
    return None


def scroll_to_top(page) -> None:
    page.evaluate(
        """() => {
            const main = document.querySelector('[data-testid="stMain"]')
                || document.querySelector('section.main');
            if (main) main.scrollTop = 0;
            window.scrollTo(0, 0);
        }"""
    )
    page.wait_for_timeout(400)


def scroll_to(page, locator, offset: int = 90) -> None:
    """Scroll *locator* into view and leave *offset* pixels above it."""
    locator.scroll_into_view_if_needed(timeout=15000)
    page.wait_for_timeout(250)
    locator.evaluate(
        """(el, offset) => {
            const main = document.querySelector('[data-testid="stMain"]')
                || document.querySelector('section.main');
            const delta = el.getBoundingClientRect().top - offset;
            if (main) {
                main.scrollTop += delta;
            } else {
                window.scrollBy(0, delta);
            }
        }""",
        offset,
    )
    page.wait_for_timeout(700)


def force_render(page) -> None:
    """Scroll through the page so Streamlit/Plotly mount every section."""
    height = page.evaluate(
        """() => {
            const main = document.querySelector('[data-testid="stMain"]')
                || document.querySelector('section.main');
            return Math.max(
                main ? main.scrollHeight : 0,
                document.body.scrollHeight,
                document.documentElement.scrollHeight
            );
        }"""
    )
    for y in range(0, int(height), 600):
        page.evaluate(
            """(y) => {
                const main = document.querySelector('[data-testid="stMain"]')
                    || document.querySelector('section.main');
                if (main) main.scrollTop = y;
                window.scrollTo(0, y);
            }""",
            y,
        )
        page.wait_for_timeout(120)
    scroll_to_top(page)
    page.wait_for_timeout(600)


def wait_for_plots(page, timeout: int = 30000) -> None:
    page.wait_for_function(
        """() => Array.from(document.querySelectorAll('.js-plotly-plot')).some((el) => {
            const rect = el.getBoundingClientRect();
            return rect.width > 100 && rect.height > 80;
        })""",
        timeout=timeout,
    )
    page.wait_for_timeout(600)


def activate_tab(page, label: str) -> None:
    tab = page.get_by_role("tab", name=re.compile(label, re.IGNORECASE)).first
    tab.click(timeout=15000)
    page.wait_for_timeout(1200)
    page.evaluate("window.dispatchEvent(new Event('resize'))")
    page.wait_for_timeout(700)


def capture(page, output: Path, name: str) -> Path:
    path = output / name
    page.screenshot(path=str(path), full_page=False)
    log(f"Captured {name}")
    return path


def select_report_row(page) -> bool:
    """Select the first Reports row and wait for the drill-down to render."""
    table = page.locator('[data-testid="stDataFrame"]').last
    table.scroll_into_view_if_needed(timeout=15000)
    table.wait_for(state="visible", timeout=15000)

    # Glide Data Grid renders selection controls on a canvas, so use precise
    # element-relative coordinates. Try the checkbox column first, then the
    # wider row area in case a Streamlit version changes the hit target.
    for x_offset, y_offset in (
        (20, 55),
        (26, 55),
        (34, 55),
        (60, 55),
        (180, 55),
        (20, 72),
    ):
        table.click(position={"x": x_offset, "y": y_offset}, timeout=10000)
        try:
            page.wait_for_function(
                "() => document.body.innerText.includes('Report from')",
                timeout=5000,
            )
            return True
        except Exception:
            page.wait_for_timeout(300)
    return False


def png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as handle:
        header = handle.read(24)
    if len(header) < 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path} is not a PNG file")
    return struct.unpack(">II", header[16:24])



def scroll_to_text(page, text: str, offset: int = 90, exact: bool = True) -> None:
    locator = page.get_by_text(text, exact=exact).first
    locator.wait_for(state="visible", timeout=20000)
    scroll_to(page, locator, offset)


def add_bottom_spacer(page, height: int = 180) -> None:
    """Add temporary page height so a lower section can scroll to the top."""
    page.evaluate(
        """(height) => {
            const container = document.querySelector(
                '[data-testid="stMain"] .block-container'
            ) || document.querySelector('.block-container');
            if (!container) return;
            let spacer = document.getElementById('screenshot-spacer');
            if (!spacer) {
                spacer = document.createElement('div');
                spacer.id = 'screenshot-spacer';
                container.appendChild(spacer);
            }
            spacer.style.height = `${height}px`;
        }""",
        height,
    )
    page.wait_for_timeout(400)


def remove_bottom_spacer(page) -> None:
    page.evaluate(
        """() => {
            const spacer = document.getElementById('screenshot-spacer');
            if (spacer) spacer.remove();
        }"""
    )
    page.wait_for_timeout(300)


def scroll_to_bottom_padding(page, padding: int = 20) -> None:
    """Scroll near the bottom, leaving *padding* pixels below the fold."""
    page.evaluate(
        """(padding) => {
            const main = document.querySelector('[data-testid="stMain"]')
                || document.querySelector('section.main');
            if (main) {
                main.scrollTop = Math.max(
                    0, main.scrollHeight - main.clientHeight - padding
                );
            }
        }""",
        padding,
    )
    page.wait_for_timeout(500)


def capture_all(page, url: str, output: Path) -> list[Path]:
    """Navigate the dashboard and capture every documented view."""
    log(f"Opening {url}")
    page.goto(url, wait_until="domcontentloaded", timeout=90000)
    page.add_style_tag(content=SCREENSHOT_CSS)
    page.wait_for_selector('[role="tab"]', timeout=90000)
    page.wait_for_function(
        "() => document.body.innerText.includes('DMARC Compliance Overview')",
        timeout=90000,
    )
    page.wait_for_timeout(1800)

    captured: list[Path] = []

    # ── Overview ──
    force_render(page)
    wait_for_plots(page)
    scroll_to_top(page)
    captured.append(capture(page, output, "overview-summary.png"))

    scroll_to_text(page, "Disposition Distribution")
    wait_for_plots(page)
    captured.append(capture(page, output, "overview-details.png"))

    # ── Sources ──
    activate_tab(page, "Sources")
    page.get_by_text("Source Classification", exact=True).wait_for(timeout=30000)
    page.wait_for_timeout(1000)
    force_render(page)
    scroll_to_top(page)
    captured.append(capture(page, output, "sources-summary.png"))

    scroll_to_text(page, "Top 10 Sending IPs")
    wait_for_plots(page)
    captured.append(capture(page, output, "sources-details.png"))

    # ── Domains ──
    activate_tab(page, "Domains")
    page.get_by_text("Domain Overview", exact=True).wait_for(timeout=30000)
    page.wait_for_timeout(1000)
    force_render(page)
    scroll_to_top(page)
    captured.append(capture(page, output, "domains-summary.png"))

    add_bottom_spacer(page)
    scroll_to_text(page, "Domain Comparison")
    wait_for_plots(page)
    captured.append(capture(page, output, "domains-policies.png"))
    remove_bottom_spacer(page)

    # ── Reports ──
    activate_tab(page, "Reports")
    page.get_by_text("Available DMARC Reports", exact=True).wait_for(timeout=30000)
    page.wait_for_timeout(1000)
    force_render(page)
    scroll_to_top(page)
    captured.append(capture(page, output, "reports-list.png"))

    if not select_report_row(page):
        raise RuntimeError(
            "Could not select a report row; the drill-down screenshot was not created"
        )
    page.get_by_text(re.compile("Report from")).first.wait_for(timeout=30000)
    page.wait_for_timeout(1200)
    force_render(page)
    scroll_to_text(page, "Report from", offset=80, exact=False)
    # The drill-down makes the page only slightly taller than the viewport;
    # settle at the natural bottom so the report list header is not clipped.
    scroll_to_bottom_padding(page, padding=20)
    captured.append(capture(page, output, "reports-detail.png"))

    return captured


def validate_images(paths: list[Path], viewport: tuple[int, int]) -> None:
    """Fail loudly if any screenshot is missing, tiny or the wrong size."""
    if len(paths) != 8:
        raise RuntimeError(f"Expected 8 screenshots, generated {len(paths)}")
    for path in paths:
        if not path.exists():
            raise RuntimeError(f"Missing screenshot: {path}")
        size = path.stat().st_size
        width, height = png_dimensions(path)
        if size < 10_000:
            raise RuntimeError(f"Screenshot looks empty: {path} ({size} bytes)")
        if (width, height) != viewport:
            raise RuntimeError(
                f"Unexpected dimensions for {path}: {width}x{height}"
            )
        log(f"  {path.name}: {width}x{height}, {size / 1024:.1f} KiB")



def parse_viewport(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d{3,5})x(\d{3,5})", value.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError("viewport must look like 1600x1000")
    return int(match.group(1)), int(match.group(2))


def check_docker() -> None:
    if not shutil.which("docker"):
        raise SystemExit(
            "docker was not found. Install Docker or run the dashboard manually "
            "and adapt scripts/generate_screenshots.py."
        )
    result = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        raise SystemExit(
            "The Docker daemon is not reachable: "
            + (detail[-1] if detail else "unknown error")
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Directory for the PNG files (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--seed", type=int, default=42, help="Synthetic data seed")
    parser.add_argument(
        "--days", type=int, default=14, help="Days of synthetic reports to create"
    )
    parser.add_argument(
        "--viewport",
        type=parse_viewport,
        default=(1600, 1000),
        help="Browser viewport, e.g. 1600x1000",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Show the browser window while capturing (requires a display)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Leave the demo database and dashboard running after capture",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.days < 1:
        raise SystemExit("--days must be at least 1")

    check_docker()
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit(
            "Playwright is not installed. Run:\n"
            "  pip install -r requirements.txt "
            "-r scripts/requirements-screenshots.txt"
        ) from exc

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    container = f"dmarclyzer-shots-{os.getpid()}"
    db_port = free_port()
    app_port = free_port()
    app_process: subprocess.Popen | None = None
    app_log: Path | None = None
    browser = None
    db_started = False

    try:
        start_database(db_port, container)
        db_started = True
        seed_database(db_port, args.days, args.seed)
        app_process, app_log = start_app(app_port, db_port)
        url = f"http://127.0.0.1:{app_port}/"

        with sync_playwright() as playwright:
            launch_args = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--force-color-profile=srgb",
                "--font-render-hinting=none",
            ]
            chrome = find_chrome()
            try:
                if chrome:
                    browser = playwright.chromium.launch(
                        executable_path=chrome,
                        headless=not args.headed,
                        args=launch_args,
                    )
                else:
                    browser = playwright.chromium.launch(
                        headless=not args.headed,
                        args=launch_args,
                    )
            except PlaywrightError as exc:
                if not chrome:
                    raise RuntimeError(
                        "Could not launch Chromium. Install Google Chrome or run "
                        "'python -m playwright install chromium'."
                    ) from exc
                log("System Chrome failed to launch; trying bundled Chromium")
                browser = playwright.chromium.launch(
                    headless=not args.headed,
                    args=launch_args,
                )

            context = browser.new_context(
                viewport={"width": args.viewport[0], "height": args.viewport[1]},
                device_scale_factor=1,
                color_scheme="light",
                locale="en-US",
                reduced_motion="reduce",
            )
            page = context.new_page()
            page.set_default_timeout(30000)

            captured = capture_all(page, url, output)
            validate_images(captured, args.viewport)

            context.close()
            browser.close()
            browser = None

        log(f"All screenshots written to {output}")
        return 0
    except Exception as exc:
        log(f"ERROR: {exc}")
        if app_log and app_log.exists():
            tail = app_log.read_text(encoding="utf-8", errors="replace")[-3000:]
            if tail.strip():
                log("Last Streamlit log lines:\n" + tail)
        raise
    finally:
        if browser is not None:
            # If Playwright's context manager already stopped after an error,
            # closing the browser again raises "Event loop is closed"; never let
            # that prevent the database/app cleanup below.
            with suppress(Exception):
                browser.close()
        if args.keep:
            if app_process is not None:
                log(f"Keeping dashboard at http://127.0.0.1:{app_port}/")
            if db_started:
                log(
                    f"Keeping MariaDB container {container} on 127.0.0.1:{db_port}"
                )
            log(f"Cleanup: docker rm -f {container}")
        else:
            stop_app(app_process)
            if db_started:
                stop_database(container)


if __name__ == "__main__":
    raise SystemExit(main())

