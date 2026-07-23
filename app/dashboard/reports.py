"""
DMARClyzer Dashboard — Reports Tab

Shows: Master list of individual DMARC reports with drill-down
into IP-level detail including DKIM/SPF auth results.
"""
import streamlit as st
import pandas as pd

from dashboard.components import section_header
from dashboard.queries import fetch_report_list, fetch_report_detail


def render_reports(start_date, end_date, domains, orgs):
    """Render the Reports tab with master list and IP drill-down."""

    reports_df = fetch_report_list(start_date, end_date, tuple(domains), tuple(orgs))

    if reports_df.empty:
        st.info("No reports match the current filters.")
        return

    # ── Master Reports List ──
    section_header(
        "Available DMARC Reports",
        "Select a report row below to expand the IP-level inspection array",
    )

    display_df = reports_df[["begin_date", "end_date", "domain", "org_name", "report_id", "messages"]].copy()
    display_df.columns = ["Start Date", "End Date", "Domain", "Reporting Organization", "Report ID", "Messages"]
    display_df["Start Date"] = pd.to_datetime(display_df["Start Date"]).dt.date
    display_df["End Date"] = pd.to_datetime(display_df["End Date"]).dt.date

    column_config = {
        "Messages": st.column_config.NumberColumn("Messages", format="%d"),
    }

    event = st.dataframe(
        display_df,
        column_config=column_config,
        on_select="rerun",
        selection_mode="single-row",
        width="stretch",
        hide_index=True,
    )

    selected_rows = event.selection.rows

    if not selected_rows:
        st.info("👆 Click on any row in the table above to drill down into IP-level inspection.")
        return

    # ── Detail View ──
    st.divider()
    selected_index = selected_rows[0]
    selected_report = reports_df.iloc[selected_index]
    target_db_id = int(selected_report["db_id"])

    # Policy Header
    st.markdown(
        f"**Report from {selected_report['org_name']} for {selected_report['domain']}**"
    )
    st.markdown(
        f"{pd.to_datetime(selected_report['begin_date']).date()} to {pd.to_datetime(selected_report['end_date']).date()}"
    )
    st.markdown(
        f"**Policies:** adkim={selected_report['adkim']}, aspf={selected_report['aspf']}, "
        f"p={selected_report['p']}, sp={selected_report['sp']}, pct={selected_report['pct']}"
    )

    st.divider()

    # Fetch and display IP detail
    detail_df = fetch_report_detail(target_db_id)

    if detail_df.empty:
        st.info("No IP-level records found in this report.")
        return

    column_config = {
        "source_ip": st.column_config.TextColumn(
            "IP", help="The source IP address of the email sender originating the message"
        ),
        "host_name": st.column_config.TextColumn(
            "Host Name", help="The reverse DNS resolved hostname of the IP address"
        ),
        "count": st.column_config.NumberColumn(
            "Message Count", help="The sum of messages sent from this IP"
        ),
        "disposition": st.column_config.TextColumn(
            "Disposition", help="The DMARC policy action applied: none (pass), quarantine, or reject"
        ),
        "reason": st.column_config.TextColumn(
            "Reason", help="Policy override reasons applied by the receiver"
        ),
        "dkim_domain": st.column_config.TextColumn(
            "DKIM Domain", help="The domain embedded in the DKIM cryptographic signature header"
        ),
        "dkim_auth": st.column_config.TextColumn(
            "DKIM Auth", help="The raw result of validating the DKIM cryptographic signature"
        ),
        "spf_domain": st.column_config.TextColumn(
            "SPF Domain", help="The envelope-from (Return-Path) domain evaluated for SPF routing checks"
        ),
        "spf_auth": st.column_config.TextColumn(
            "SPF Auth", help="The raw result of the SPF validation querying DNS for permitted ranges"
        ),
        "dkim": st.column_config.TextColumn(
            "DKIM Align", help="Alignment: Did the passing DKIM Domain properly match the 'From' header domain?"
        ),
        "spf": st.column_config.TextColumn(
            "SPF Align", help="Alignment: Did the passing SPF Domain properly match the 'From' header domain?"
        ),
        "dmarc": st.column_config.TextColumn(
            "DMARC", help="Derived Overall DMARC Pass/Fail"
        ),
    }

    st.dataframe(
        detail_df,
        width="stretch",
        column_config=column_config,
        hide_index=True,
    )
