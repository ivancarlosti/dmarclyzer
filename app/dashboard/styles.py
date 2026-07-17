"""
DMARClyzer Dashboard — Styling & Theme Constants

A clean, professional aesthetic inspired by dmarcian.com.
"""

# ── Color Palette ───────────────────────────────────────────
COLORS = {
    "pass": "#27ae60",          # green — DMARC compliant
    "fail": "#e74c3c",          # red — failing
    "forwarded": "#f39c12",     # amber/orange — forwarded mail
    "dkim_issue": "#e67e22",    # dark orange — DKIM misconfiguration
    "threat": "#c0392b",        # dark red — threat/unknown
    "quarantine": "#f1c40f",    # yellow
    "reject": "#e74c3c",        # red
    "none_policy": "#95a5a6",   # grey — p=none
    "primary": "#2c3e50",       # dark blue-grey
    "secondary": "#7f8c8d",     # medium grey
    "background": "#f5f6fa",    # light grey background
    "card_bg": "#ffffff",       # white cards
    "text": "#2c3e50",          # dark text
    "text_light": "#7f8c8d",    # light text
    "border": "#e1e5eb",        # subtle border
}

# ── Category Display Config ─────────────────────────────────
SOURCE_CATEGORIES = {
    "Compliant": {
        "color": COLORS["pass"],
        "icon": "✅",
        "description": "DKIM & SPF aligned — passing DMARC",
    },
    "Forwarded": {
        "color": COLORS["forwarded"],
        "icon": "↗️",
        "description": "SPF broken by forwarding, DKIM intact",
    },
    "DKIM Issue": {
        "color": COLORS["dkim_issue"],
        "icon": "⚠️",
        "description": "DKIM failing, SPF passing",
    },
    "Failing": {
        "color": COLORS["fail"],
        "icon": "❌",
        "description": "Both DKIM & SPF failing",
    },
}

# ── Plotly Theme ────────────────────────────────────────────
PLOTLY_TEMPLATE = "plotly_white"

CHART_LAYOUT = {
    "font_family": "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
    "title_font_size": 16,
    "margin": {"l": 40, "r": 20, "t": 50, "b": 40},
    "plot_bgcolor": "#ffffff",
    "paper_bgcolor": "#ffffff",
    "xaxis": {"gridcolor": "#ecf0f1", "zeroline": False},
    "yaxis": {"gridcolor": "#ecf0f1", "zeroline": False},
    "hovermode": "x unified",
}

# ── Global CSS Injection ────────────────────────────────────
CUSTOM_CSS = """
<style>
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Container padding */
    .block-container {
        padding-top: 2rem !important;
        padding-left: 1.5rem !important;
        padding-right: 1.5rem !important;
        padding-bottom: 1rem !important;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] .block-container {
        padding-top: 2rem !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }
    
    /* Metric Cards */
    .dash-card {
        background: #ffffff;
        border: 1px solid #e1e5eb;
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        transition: box-shadow 0.2s;
    }
    .dash-card:hover {
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }
    .dash-card .card-label {
        font-size: 0.8rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: #7f8c8d;
        margin-bottom: 6px;
    }
    .dash-card .card-value {
        font-size: 2rem;
        font-weight: 700;
        color: #2c3e50;
        line-height: 1.2;
    }
    .dash-card .card-delta {
        font-size: 0.85rem;
        margin-top: 4px;
    }
    .dash-card .card-icon {
        float: right;
        font-size: 1.8rem;
        opacity: 0.4;
    }
    
    /* Source Badges */
    .source-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        color: #fff;
    }
    
    /* Section Headers */
    .section-header {
        border-bottom: 2px solid #e1e5eb;
        padding-bottom: 8px;
        margin-bottom: 16px;
        margin-top: 8px;
    }
    .section-header h3 {
        color: #2c3e50;
        font-weight: 600;
        margin: 0;
    }
    .section-header p {
        color: #7f8c8d;
        font-size: 0.85rem;
        margin: 2px 0 0 0;
    }
    
    /* Tab styling overrides */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
        border-bottom: 2px solid #e1e5eb;
    }
    .stTabs [data-baseweb="tab"] {
        font-weight: 500;
        font-size: 0.95rem;
        color: #7f8c8d;
        padding: 8px 4px 12px 4px;
    }
    .stTabs [aria-selected="true"] {
        color: #2c3e50;
        font-weight: 600;
        border-bottom: 3px solid #27ae60;
    }
    
    /* Dataframe styling */
    [data-testid="stDataFrame"] {
        font-size: 0.85rem;
    }
    [data-testid="stDataFrame"] th {
        background-color: #f8f9fa !important;
        font-weight: 600;
        color: #2c3e50;
        border-bottom: 2px solid #e1e5eb !important;
    }
    
    /* Metric overrides */
    [data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #e1e5eb;
        border-radius: 10px;
        padding: 12px 16px;
    }
    [data-testid="stMetricValue"] {
        font-weight: 700;
        color: #2c3e50;
    }
    
    /* Divider */
    hr {
        border-color: #e1e5eb;
        margin: 1.2rem 0;
    }
</style>
"""
