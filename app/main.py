import time
import os
import threading
import subprocess
import logging
from fetcher import fetch_dmarc_reports
from parser import parse_dmarc_xml
from models import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetcher_loop():
    """Background thread that periodically fetches and parses DMARC reports."""
    interval = int(os.environ.get("FETCH_INTERVAL", 300))
    while True:
        try:
            logger.info("Initializing DB check before fetch cycle...")
            init_db()  # Ensures tables exist before operating

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
    subprocess.run(["streamlit", "run", "dashboard.py", "--server.port", "8080", "--server.address", "0.0.0.0"], env=env)

if __name__ == "__main__":
    logger.info("=== DMARClyzer Started ===")
    
    # Wait for MariaDB container to be fully up and ready
    logger.info("Waiting a few seconds for MariaDB to initialize...")
    time.sleep(5)
    init_db()

    # Start the background fetcher thread
    t = threading.Thread(target=fetcher_loop, daemon=True)
    t.start()

    # Start the Streamlit dashboard in the main thread
    start_streamlit()
