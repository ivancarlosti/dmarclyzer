"""
DMARClyzer Dashboard — Domains Tab

Shows: Per-domain metric cards, domain comparison table,
policy distribution chart, and policy adoption timeline.
"""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from .styles import COLORS, PLOTLY_TEMPLATE, CHART_LAYOUT
from .components import metric_card, section_header, format_number, status_indicator
from .queries import (
    fetch_domain_metrics,
    fetch_policy_distribution,
    fetch_policy_timeline,
)


def render_domains(start_date, end_date, domains, orgs):
    """Render the Domains tab with per-domain KPIs and policy analysis."""

    domain_df = fetch_domain_metrics(start_date, end_date, tuple(domains), tuple(orgs))

    if domain_df.empty:
        st.info("No domain data matches the current filters.")
        return

    # ── Row 1: Per-Domain Metric Cards ──
    section_header("Domain Overview", "Key metrics for each of your monitored domains")

    # Render cards in rows of 3
    for i in range(0, len(domain_df), 3):
        cols = st.columns(3)
        for j, col in enumerate(cols):
            idx = i + j
            if idx >= len(domain_df):
                break
            row = domain_df.iloc[idx]
            with col:
                pass_ok = row["pass_rate"] >= 70
                pass_color = COLORS["pass"] if pass_ok else COLORS["forwarded"]

                # Build a richer card using markdown
                st.markdown(
                    f"""
                    <div class="dash-card" style="border-left: 4px solid {pass_color};">
                        <div style="font-size: 1.1rem; font-weight: 600; color: {COLORS['primary']}; margin-bottom: 8px;">
                            🌐 {row['domain']}
                        </div>
                        <div style="display: flex; gap: 16px; flex-wrap: wrap;">
                            <div>
                                <span style="font-size: 0.7rem; color: {COLORS['text_light']}; text-transform: uppercase;">Volume</span><br>
                                <span style="font-weight: 700; color: {COLORS['primary']};">{format_number(row['total_messages'])}</span>
                            </div>
                            <div>
                                <span style="font-size: 0.7rem; color: {COLORS['text_light']}; text-transform: uppercase;">DMARC Pass</span><br>
                                <span style="font-weight: 700; color: {pass_color};">{row['pass_rate']}%</span>
                            </div>
                            <div>
                                <span style="font-size: 0.7rem; color: {COLORS['text_light']}; text-transform: uppercase;">DKIM</span><br>
                                <span style="font-weight: 700; color: {COLORS['primary']};">{row['dkim_pass_rate']}%</span>
                            </div>
                            <div>
                                <span style="font-size: 0.7rem; color: {COLORS['text_light']}; text-transform: uppercase;">SPF</span><br>
                                <span style="font-weight: 700; color: {COLORS['primary']};">{row['spf_pass_rate']}%</span>
                            </div>
                            <div>
                                <span style="font-size: 0.7rem; color: {COLORS['text_light']}; text-transform: uppercase;">Policy</span><br>
                                <span style="font-weight: 700; color: {COLORS['primary']};">p={row['policy']}</span>
                            </div>
                            <div>
                                <span style="font-size: 0.7rem; color: {COLORS['text_light']}; text-transform: uppercase;">IPs</span><br>
                                <span style="font-weight: 700; color: {COLORS['primary']};">{row['unique_ips']}</span>
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    st.divider()

    # ── Row 2: Domain Comparison Table ──
    section_header("Domain Comparison", "Side-by-side comparison of all domains")

    table_df = domain_df.copy()
    table_df["Status"] = table_df["pass_rate"].apply(
        lambda p: status_indicator(p >= 70, f"{p}%", f"{p}%")
    )

    column_config = {
        "domain": st.column_config.TextColumn("Domain", width="medium"),
        "total_messages": st.column_config.NumberColumn("Messages", format="%d"),
        "pass_rate": st.column_config.NumberColumn("Pass %", format="%.1f%%"),
        "dkim_pass_rate": st.column_config.NumberColumn("DKIM %", format="%.1f%%"),
        "spf_pass_rate": st.column_config.NumberColumn("SPF %", format="%.1f%%"),
        "policy": st.column_config.TextColumn("Policy", width="small"),
        "unique_ips": st.column_config.NumberColumn("Unique IPs"),
        "Status": st.column_config.TextColumn("Status", width="small"),
    }

    st.dataframe(
        table_df[["domain", "total_messages", "pass_rate", "dkim_pass_rate", "spf_pass_rate", "policy", "unique_ips"]],
        column_config=column_config,
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # ── Row 3: Policy Distribution + Timeline ──
    col_left, col_right = st.columns(2)

    with col_left:
        section_header(
            "Policy Distribution by Domain",
            "Which DMARC policies are enforced per domain",
        )

        policy_df = fetch_policy_distribution(start_date, end_date, tuple(domains), tuple(orgs))
        if not policy_df.empty:
            fig = px.bar(
                policy_df,
                x="domain",
                y="report_count",
                color="p",
                barmode="group",
                color_discrete_map={
                    "reject": COLORS["reject"],
                    "quarantine": COLORS["quarantine"],
                    "none": COLORS["none_policy"],
                },
                labels={"domain": "Domain", "report_count": "Reports", "p": "Policy"},
            )
            fig.update_layout(
                **CHART_LAYOUT,
                height=320,
                legend=dict(orientation="h", yanchor="bottom", y=1.02),
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No policy distribution data.")

    with col_right:
        section_header(
            "Policy Adoption Timeline",
            "How DMARC policies have changed over time",
        )

        timeline_df = fetch_policy_timeline(start_date, end_date, tuple(domains), tuple(orgs))
        if not timeline_df.empty and timeline_df["domain"].nunique() <= 5:
            fig = px.line(
                timeline_df,
                x="date",
                y="report_count",
                color="domain",
                line_dash="p",
                labels={"date": "Date", "report_count": "Reports", "domain": "Domain", "p": "Policy"},
            )
            fig.update_layout(
                **CHART_LAYOUT,
                height=320,
                legend=dict(orientation="h", yanchor="bottom", y=1.02),
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        elif not timeline_df.empty:
            # Too many domains for line chart — use faceted bar
            st.caption("Timeline shown as faceted bar chart (too many domains for line overlay)")
            fig = px.bar(
                timeline_df,
                x="date",
                y="report_count",
                color="p",
                facet_row="domain",
                color_discrete_map={
                    "reject": COLORS["reject"],
                    "quarantine": COLORS["quarantine"],
                    "none": COLORS["none_policy"],
                },
                labels={"date": "Date", "report_count": "Reports", "p": "Policy"},
            )
            fig.update_layout(
                **CHART_LAYOUT,
                height=400,
            )
            fig.for_each_annotation(lambda a: a.update(text=a.text.split("=")[-1]))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No policy timeline data.")
