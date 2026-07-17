"""
DMARClyzer Dashboard — Reusable UI Components

Metric cards, compliance gauges, source badges, and section headers.
"""
import streamlit as st
import plotly.graph_objects as go
from .styles import COLORS, SOURCE_CATEGORIES, PLOTLY_TEMPLATE, CHART_LAYOUT


def metric_card(
    label: str,
    value: str,
    delta: str | None = None,
    delta_color: str = "normal",
    icon: str = "",
    bg_color: str | None = None,
):
    """Render a styled KPI metric card using custom HTML."""
    icon_html = f'<div class="card-icon">{icon}</div>' if icon else ""
    delta_html = ""
    if delta:
        d_color = {
            "normal": "#7f8c8d",
            "up": "#27ae60",
            "down": "#e74c3c",
            "off": "#7f8c8d",
        }.get(delta_color, "#7f8c8d")
        delta_html = f'<div class="card-delta" style="color:{d_color}">{delta}</div>'

    style_attr = f'style="border-left: 4px solid {bg_color};"' if bg_color else ""

    st.markdown(
        f"""
        <div class="dash-card" {style_attr}>
            {icon_html}
            <div class="card-label">{label}</div>
            <div class="card-value">{value}</div>
            {delta_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def compliance_gauge(value: float, title: str = "DMARC Compliance"):
    """Render a Plotly gauge chart showing DMARC compliance percentage (0-100)."""
    clamped = max(0.0, min(100.0, value))

    # Determine color zone
    if clamped >= 90:
        gauge_color = COLORS["pass"]
    elif clamped >= 70:
        gauge_color = COLORS["forwarded"]
    elif clamped >= 50:
        gauge_color = COLORS["dkim_issue"]
    else:
        gauge_color = COLORS["fail"]

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=clamped,
            number={"suffix": "%", "font": {"size": 42, "color": COLORS["primary"]}},
            title={"text": title, "font": {"size": 14, "color": COLORS["text_light"]}},
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 1,
                    "tickcolor": COLORS["primary"],
                    "tickfont": {"size": 10},
                },
                "bar": {"color": gauge_color, "thickness": 0.2},
                "bgcolor": "#ecf0f1",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 50], "color": "#fdedec"},
                    {"range": [50, 70], "color": "#fef5e7"},
                    {"range": [70, 90], "color": "#fef9e7"},
                    {"range": [90, 100], "color": "#eafaf1"},
                ],
                "threshold": {
                    "line": {"color": COLORS["fail"], "width": 2},
                    "thickness": 0.75,
                    "value": 90,
                },
            },
        )
    )

    fig.update_layout(
        height=220,
        margin={"l": 20, "r": 20, "t": 50, "b": 10},
        font={"family": CHART_LAYOUT["font_family"]},
        template=PLOTLY_TEMPLATE,
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def source_badge(category: str) -> str:
    """Return an HTML colored badge for a source classification category."""
    info = SOURCE_CATEGORIES.get(category)
    if not info:
        return f'<span class="source-badge" style="background-color:#95a5a6">{category}</span>'
    return f'<span class="source-badge" style="background-color:{info["color"]}">{info["icon"]} {category}</span>'


def section_header(title: str, description: str = ""):
    """Render a consistent section header with optional subtitle."""
    desc_html = f"<p>{description}</p>" if description else ""
    st.markdown(
        f"""
        <div class="section-header">
            <h3>{title}</h3>
            {desc_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def status_indicator(passed: bool, label_true: str = "Pass", label_false: str = "Fail"):
    """Render a small inline pass/fail indicator."""
    if passed:
        return f'<span style="color:{COLORS["pass"]};font-weight:600">✅ {label_true}</span>'
    return f'<span style="color:{COLORS["fail"]};font-weight:600">❌ {label_false}</span>'


def format_number(n: int | float) -> str:
    """Format large numbers with K/M/B suffixes."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(int(n))
