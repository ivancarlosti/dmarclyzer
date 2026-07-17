# DMARClyzer Dashboard Package
from .styles import COLORS, CUSTOM_CSS, PLOTLY_TEMPLATE, CHART_LAYOUT
from .components import metric_card, compliance_gauge, source_badge, section_header
from .queries import (
    fetch_filter_bounds,
    fetch_overview_metrics,
    fetch_volume_timeseries,
    fetch_disposition_distribution,
    fetch_dkim_spf_alignment,
    fetch_policy_distribution,
    fetch_source_classification,
    fetch_forwarded_analysis,
    fetch_domain_metrics,
    fetch_policy_timeline,
)
