import time
import os
import threading
import subprocess
import logging
from fetcher import fetch_dmarc_reports
from parser import parse_dmarc_xml
from models import init_db, cleanup_old_reports
from security import env_int

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetcher_loop():
    """Background thread that periodically fetches and parses DMARC reports."""
    interval = env_int("FETCH_INTERVAL", 300, minimum=30, maximum=86400)

    while True:
        try:
            logger.info("Initializing DB check before fetch cycle...")
            init_db()  # Ensures tables exist before operating

            logger.info("Running cleanup of old reports...")
            cleanup_old_reports()

            logger.info("Starting IMAP fetch cycle...")
            xmls = fetch_dmarc_reports()
            if xmls:
                logger.info(f"Fetched {len(xmls)} XML reports. Parsing...")
                for xml in xmls:
                    parse_dmarc_xml(xml)
                logger.info("Parsing cycle complete.")
        except Exception as e:
            logger.error(f"Error in fetch/parse loop: {e}")
            
        logger.info(f"Sleeping for {interval} seconds until next check.")
        time.sleep(interval)

def start_streamlit():
    """Starts the Streamlit dashboard server."""
    logger.info("Starting Streamlit Dashboard...")
    # Add python path so streamlit can resolve module imports comfortably
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    port = str(env_int("STREAMLIT_SERVER_PORT", 8080, minimum=1, maximum=65535))
    address = os.environ.get("STREAMLIT_SERVER_ADDRESS", "0.0.0.0")
    subprocess.run([
        "streamlit", "run", "dashboard/main.py",
        "--server.port", port,
        "--server.address", address,
        "--server.headless=true",
        "--server.enableXsrfProtection=true",
        "--server.enableCORS=true",
        "--browser.gatherUsageStats=false",
    ], env=env)

if __name__ == "__main__":
    logger.info("=== DMARClyzer Started ===")

    if (os.environ.get("AUTH_METHOD", "none") or "none").strip().lower() == "none":
        logger.warning(
            "AUTH_METHOD=none — the dashboard is unauthenticated. Publish it only "
            "behind a trusted reverse proxy or enable account/Keycloak auth."
        )

    
    # Wait for MariaDB container to be fully up and ready
    logger.info("Waiting a few seconds for MariaDB to initialize...")
    time.sleep(5)
    init_db()

    # Start the background fetcher thread
    t = threading.Thread(target=fetcher_loop, daemon=True)
    t.start()

    # Start the Streamlit dashboard in the main thread
    start_streamlit()
