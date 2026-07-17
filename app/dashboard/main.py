"""
DMARClyzer Dashboard — Main Entry Point

Handles sidebar filters, tab navigation, session state,
and the "no data yet" empty state.
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import sessionmaker

from models import get_engine, Report
from auth import require_auth

from dashboard.styles import CUSTOM_CSS
from dashboard.queries import fetch_filter_bounds, _get_engine_cached
from dashboard.overview import render_overview
from dashboard.sources import render_sources
from dashboard.domains import render_domains


def main():
    """Initialize the dashboard with auth, styling, sidebar, and tab layout."""

    # ── Page Config ──
    st.set_page_config(
        page_title="DMARClyzer Dashboard",
        page_icon="🛡️",
        layout="wide",
        menu_items={
            "Get Help": None,
            "Report a bug": None,
            "About": None,
        },
    )

    # ── Authentication ──
    if not require_auth():
        st.stop()

    # ── Global CSS ──
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    # ── Check if any data exists ──
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    try:
        with Session() as session:
            has_data = session.query(Report).first() is not None
    except Exception:
        has_data = False

    if not has_data:
        _render_empty_state()
        return

    # ── Sidebar Filters ──
    _render_sidebar()

    # ── Tab Navigation ──
    tab1, tab2, tab3 = st.tabs(["📊 Overview", "🔍 Sources", "🌐 Domains"])

    filters = _get_filters_from_session()

    with tab1:
        render_overview(**filters)

    with tab2:
        render_sources(**filters)

    with tab3:
        render_domains(**filters)


def _render_empty_state():
    """Display when no DMARC reports exist yet."""
    st.title("🛡️ DMARClyzer")
    st.info(
        "No DMARC reports found yet. The fetcher daemon might still be processing, "
        "or your configured IMAP inbox hasn't received any new valid Aggregate XML attachments."
    )

    if "initial_refresh_count" not in st.session_state:
        st.session_state["initial_refresh_count"] = 0

    if st.session_state["initial_refresh_count"] < 3:
        import time

        st.session_state["initial_refresh_count"] += 1
        with st.spinner("Waiting for background processing... Auto-refreshing..."):
            time.sleep(3)
        st.rerun()
    else:
        if st.button("Refresh Dashboard", type="primary"):
            st.session_state["initial_refresh_count"] = 0
            st.rerun()

    st.stop()


def _render_sidebar():
    """Render the shared sidebar with filters stored in session state."""
    st.sidebar.header("📋 Filter Reports")

    min_dt, max_dt, available_domains, available_orgs = fetch_filter_bounds()

    # ── Date Range ──
    max_allowed = max_dt.date() if max_dt else datetime.today().date()
    min_allowed = min_dt.date() if min_dt else datetime.today().date() - timedelta(days=30)

    default_start = max_allowed - timedelta(days=7)
    if default_start < min_allowed:
        default_start = min_allowed

    # Use session state to persist date range across tabs
    if "dash_date_range" not in st.session_state:
        st.session_state["dash_date_range"] = (default_start, max_allowed)

    dates = st.sidebar.date_input(
        "Date Range",
        st.session_state["dash_date_range"],
        min_value=min_allowed,
        max_value=max_allowed,
        key="sidebar_date_input",
    )

    if len(dates) == 2:
        st.session_state["dash_date_range"] = (dates[0], dates[1])
    else:
        st.warning("Please select both a start and end date from the sidebar Date Range.")
        st.stop()

    # ── Domains ──
    st.sidebar.divider()

    if "dash_domains" not in st.session_state:
        st.session_state["dash_domains"] = available_domains

    selected_domains_all = st.sidebar.checkbox("Select All Domains", value=True)
    selected_domains = st.sidebar.multiselect(
        "Domains",
        available_domains,
        default=available_domains if selected_domains_all else st.session_state.get("dash_domains", []),
        key="sidebar_domains",
    )
    st.session_state["dash_domains"] = selected_domains

    # ── Organizations ──
    st.sidebar.divider()

    if "dash_orgs" not in st.session_state:
        st.session_state["dash_orgs"] = available_orgs

    selected_orgs_all = st.sidebar.checkbox("Select All Reporter Organizations", value=True)
    selected_orgs = st.sidebar.multiselect(
        "Reporter Organizations",
        available_orgs,
        default=available_orgs if selected_orgs_all else st.session_state.get("dash_orgs", []),
        key="sidebar_orgs",
    )
    st.session_state["dash_orgs"] = selected_orgs

    # ── Validation ──
    if not selected_domains or not selected_orgs:
        st.warning("Please select at least one Domain and one Organization to view data.")
        st.stop()

    # ── Refresh ──
    st.sidebar.divider()
    if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


def _get_filters_from_session():
    """Extract current filter values from session state."""
    start_date, end_date = st.session_state["dash_date_range"]
    return {
        "start_date": start_date,
        "end_date": end_date,
        "domains": tuple(st.session_state["dash_domains"]),
        "orgs": tuple(st.session_state["dash_orgs"]),
    }
