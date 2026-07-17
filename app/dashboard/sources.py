"""
DMARClyzer Dashboard — Sources Tab

Shows: Source classification table (Compliant/Forwarded/DKIM Issue/Failing),
top sending IPs, DKIM/SPF alignment heatmap, and forwarded mail analysis.
"""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from dashboard.styles import COLORS, SOURCE_CATEGORIES, PLOTLY_TEMPLATE, CHART_LAYOUT
from dashboard.components import (
    source_badge,
    section_header,
    format_number,
    status_indicator,
)
from dashboard.queries import (
    fetch_overview_metrics,
    fetch_source_classification,
    fetch_forwarded_analysis,
    fetch_dkim_spf_alignment,
)


def render_sources(start_date, end_date, domains, orgs):
    """Render the Sources tab with IP-level classification and analysis."""

    metrics = fetch_overview_metrics(start_date, end_date, tuple(domains), tuple(orgs))
    df = fetch_source_classification(start_date, end_date, tuple(domains), tuple(orgs))

    if df.empty:
        st.info("No source data matches the current filters.")
        return

    # ── Row 1: Source Category Summary Cards ──
    section_header("Source Classification", "Categorizing sending IPs by DMARC alignment status")

    # Compute category summary
    cat_summary = df.groupby("category")["total_count"].sum().to_dict()
    total_all = sum(cat_summary.values())

    cols = st.columns(4)
    categories = ["Compliant", "Forwarded", "DKIM Issue", "Failing"]
    for i, cat in enumerate(categories):
        count = int(cat_summary.get(cat, 0))
        pct = (count / total_all * 100) if total_all > 0 else 0.0
        info = SOURCE_CATEGORIES[cat]
        with cols[i]:
            st.metric(
                label=f"{info['icon']} {cat}",
                value=format_number(count),
                delta=f"{pct:.1f}% of total",
            )

    st.divider()

    # ── Row 2: Source Classification Table ──
    section_header(
        "All Sending Sources",
        "IP-level breakdown with category, volume, and alignment status",
    )

    # Prepare display dataframe
    display_df = df.copy()
    display_df = display_df.rename(
        columns={
            "source_ip": "IP Address",
            "host_name": "Hostname",
            "total_count": "Messages",
            "disposition": "Disposition",
            "category": "Category",
        }
    )

    # Render table with colored badges for category
    for idx, row in display_df.iterrows():
        cat = row["Category"]
        info = SOURCE_CATEGORIES.get(cat, {})
        display_df.at[idx, "Category"] = (
            f'<span class="source-badge" style="background-color:{info.get("color", "#95a5a6")}">'
            f'{info.get("icon", "")} {cat}</span>'
        )

    # DKIM/SPF status indicators
    display_df["DKIM"] = df["dkim"].apply(
        lambda x: status_indicator(x == "pass") if pd.notna(x) else "—"
    )
    display_df["SPF"] = df["spf"].apply(
        lambda x: status_indicator(x == "pass") if pd.notna(x) else "—"
    )

    # Column config
    column_config = {
        "IP Address": st.column_config.TextColumn("IP Address", width="medium"),
        "Hostname": st.column_config.TextColumn("Hostname", width="medium"),
        "Messages": st.column_config.NumberColumn("Messages", format="%d"),
        "Disposition": st.column_config.TextColumn("Disposition", width="small"),
        "Category": st.column_config.TextColumn("Category", width="small"),
        "DKIM": st.column_config.TextColumn("DKIM", width="small"),
        "SPF": st.column_config.TextColumn("SPF", width="small"),
    }

    st.write(
        display_df[["IP Address", "Hostname", "Messages", "Category", "DKIM", "SPF", "Disposition"]].to_html(
            escape=False, index=False
        ),
        unsafe_allow_html=True,
    )

    st.caption(f"Showing {len(display_df)} unique sending sources")

    st.divider()

    # ── Row 3: Top 10 Senders + Forwarded Analysis ──
    col_left, col_right = st.columns(2)

    with col_left:
        section_header("Top 10 Sending IPs", "Highest volume sources by message count")

        top10 = df.head(10).copy()
        top10["label"] = top10["source_ip"].fillna("Unknown") + (
            top10["host_name"].apply(lambda h: f" ({h})" if pd.notna(h) and h else "")
        )

        fig = px.bar(
            top10.iloc[::-1],  # reverse for horizontal bar
            x="total_count",
            y="label",
            orientation="h",
            color="category",
            color_discrete_map={
                "Compliant": COLORS["pass"],
                "Forwarded": COLORS["forwarded"],
                "DKIM Issue": COLORS["dkim_issue"],
                "Failing": COLORS["fail"],
            },
            labels={"total_count": "Messages", "label": "", "category": "Category"},
            text_auto=".2s",
        )
        fig.update_layout(
            **CHART_LAYOUT,
            height=350,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02),
        )
        fig.update_yaxes(categoryorder="total ascending")
        st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})

    with col_right:
        section_header(
            "Forwarded Mail Analysis",
            "Top forwarders where SPF breaks but DKIM survives — typical of mailing lists",
        )

        fwd_df = fetch_forwarded_analysis(start_date, end_date, tuple(domains), tuple(orgs))
        if not fwd_df.empty:
            fwd_df["label"] = fwd_df["source_ip"].fillna("Unknown") + (
                fwd_df["host_name"].apply(lambda h: f" ({h})" if pd.notna(h) and h else "")
            )
            fig = px.bar(
                fwd_df.iloc[::-1],
                x="total_count",
                y="label",
                orientation="h",
                color_discrete_sequence=[COLORS["forwarded"]],
                labels={"total_count": "Messages", "label": ""},
                text_auto=".2s",
            )
            fig.update_layout(
                **CHART_LAYOUT,
                height=350,
                showlegend=False,
            )
            fig.update_yaxes(categoryorder="total ascending")
            st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})
        else:
            st.info("No forwarded mail sources detected.")

    st.divider()

    # ── Row 4: DKIM/SPF Alignment Matrix ──
    section_header("DKIM/SPF Alignment Matrix", "Message count by alignment combination")

    # Build alignment matrix
    matrix = (
        df.groupby(["dkim", "spf"])["total_count"]
        .sum()
        .reset_index()
        .pivot(index="dkim", columns="spf", values="total_count")
        .fillna(0)
    )

    if not matrix.empty:
        fig = px.imshow(
            matrix.values,
            x=list(matrix.columns),
            y=list(matrix.index),
            color_continuous_scale="RdYlGn",
            text_auto=".2s",
            labels={"x": "SPF", "y": "DKIM", "color": "Messages"},
        )
        fig.update_layout(
            **CHART_LAYOUT,
            height=280,
        )
        fig.update_xaxes(side="top")
        st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})
    else:
        st.info("Not enough data for alignment matrix.")
