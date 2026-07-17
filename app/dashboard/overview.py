"""
DMARClyzer Dashboard — Overview Tab

Shows: DMARC compliance gauge, key metrics, volume over time,
disposition distribution, DKIM/SPF alignment comparison, and policy adoption.
"""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from dashboard.styles import COLORS, PLOTLY_TEMPLATE, CHART_LAYOUT
from dashboard.components import metric_card, compliance_gauge, section_header, format_number
from dashboard.queries import (
    fetch_overview_metrics,
    fetch_volume_timeseries,
    fetch_disposition_distribution,
    fetch_dkim_spf_alignment,
    fetch_policy_distribution,
)


def render_overview(start_date, end_date, domains, orgs):
    """Render the Overview tab with all summary charts and KPIs."""

    metrics = fetch_overview_metrics(start_date, end_date, tuple(domains), tuple(orgs))

    if metrics["total_messages"] == 0:
        st.info("No DMARC data matches the current filters. Try adjusting the date range or domain selection.")
        return

    # ── Row 1: Compliance Gauge + 3 Metric Cards ──
    section_header("DMARC Compliance Overview")

    col_gauge, col1, col2, col3 = st.columns([1, 1, 1, 1])

    with col_gauge:
        compliance_gauge(metrics["pass_rate"], "DMARC Compliance")

    with col1:
        metric_card(
            "Total Messages",
            format_number(metrics["total_messages"]),
            icon="📧",
            bg_color=COLORS["primary"],
        )

    with col2:
        metric_card(
            "DMARC Pass Rate",
            f"{metrics['pass_rate']}%",
            delta=f"{metrics['compliant_msgs']:,} compliant messages",
            delta_color="up" if metrics["pass_rate"] >= 70 else "down",
            icon="🛡️",
            bg_color=COLORS["pass"] if metrics["pass_rate"] >= 70 else COLORS["forwarded"],
        )

    with col3:
        metric_card(
            "Unique Sending IPs",
            format_number(metrics["total_ips"]),
            icon="🌐",
            bg_color=COLORS["secondary"],
        )

    st.divider()

    # ── Row 2: Volume Over Time (Area Chart) ──
    section_header("Email Volume Over Time", "Daily volume stacked by DMARC disposition")

    vol_df = fetch_volume_timeseries(start_date, end_date, tuple(domains), tuple(orgs))
    if not vol_df.empty:
        pivot = vol_df.pivot(index="date", columns="disposition", values="count").fillna(0)

        color_map = {
            "none": COLORS["none_policy"],
            "quarantine": COLORS["quarantine"],
            "reject": COLORS["reject"],
        }
        # Only include columns that exist
        available_cols = [c for c in ["none", "quarantine", "reject"] if c in pivot.columns]
        colors = {c: color_map.get(c, COLORS["secondary"]) for c in available_cols}

        if len(available_cols) == 1:
            fig = px.bar(
                pivot, y=available_cols[0],
                color_discrete_sequence=[colors[available_cols[0]]],
                labels={"value": "Messages", "date": "Date", "variable": "Disposition"},
            )
        else:
            fig = px.area(
                pivot, y=available_cols,
                color_discrete_map=colors,
                labels={"value": "Messages", "date": "Date", "variable": "Disposition"},
            )

        fig.update_layout(
            **CHART_LAYOUT,
            height=350,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        fig.update_traces(line=dict(width=2) if len(available_cols) > 1 else {})
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("Not enough data for volume trend chart.")

    st.divider()

    # ── Row 3: Disposition Donut + DKIM/SPF Alignment ──
    col_left, col_right = st.columns(2)

    with col_left:
        section_header("Disposition Distribution", "How messages are handled by receivers")

        disp_df = fetch_disposition_distribution(start_date, end_date, tuple(domains), tuple(orgs))
        if not disp_df.empty:
            fig = px.pie(
                disp_df,
                values="count",
                names="disposition",
                color="disposition",
                color_discrete_map={
                    "none": COLORS["none_policy"],
                    "quarantine": COLORS["quarantine"],
                    "reject": COLORS["reject"],
                },
                hole=0.45,
            )
            fig.update_layout(
                height=320,
                margin={"l": 0, "r": 0, "t": 10, "b": 10},
                showlegend=True,
                legend=dict(orientation="h", y=-0.15),
            )
            fig.update_traces(textinfo="percent+value", textfont_size=12)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No disposition data available.")

    with col_right:
        section_header("DKIM vs SPF Alignment", "Pass/fail comparison by protocol")

        align_df = fetch_dkim_spf_alignment(start_date, end_date, tuple(domains), tuple(orgs))
        if not align_df.empty:
            fig = px.bar(
                align_df,
                x="Protocol",
                y="Messages",
                color="Result",
                barmode="group",
                color_discrete_map={"Pass": COLORS["pass"], "Fail": COLORS["fail"]},
                text_auto=".2s",
            )
            fig.update_layout(
                **CHART_LAYOUT,
                height=320,
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=1.02),
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No alignment data available.")

    st.divider()

    # ── Row 4: Policy Distribution Across Domains ──
    section_header(
        "DMARC Policy Distribution",
        "Policy modes (p=) in use across your domains — 'reject' is the strongest protection",
    )

    policy_df = fetch_policy_distribution(start_date, end_date, tuple(domains), tuple(orgs))
    if not policy_df.empty:
        fig = px.bar(
            policy_df,
            x="domain",
            y="report_count",
            color="p",
            barmode="stack",
            color_discrete_map={
                "reject": COLORS["reject"],
                "quarantine": COLORS["quarantine"],
                "none": COLORS["none_policy"],
            },
            labels={"domain": "Domain", "report_count": "Reports", "p": "Policy"},
        )
        fig.update_layout(
            **CHART_LAYOUT,
            height=300,
            xaxis={"categoryorder": "total descending"},
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("No policy distribution data available.")

    # ── Quick Stats Footer ──
    st.divider()
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("DKIM Pass Rate", f"{metrics['dkim_pass_rate']}%")
    with c2:
        st.metric("SPF Pass Rate", f"{metrics['spf_pass_rate']}%")
    with c3:
        st.metric("Forwarded Mail", f"{metrics['forwarded_msgs']:,}")
    with c4:
        st.metric("Failing (Both)", f"{metrics['failing_msgs']:,}")
