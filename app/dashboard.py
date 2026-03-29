import streamlit as st
import pandas as pd
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from models import get_engine, Report, Record
from datetime import datetime, timedelta

st.set_page_config(
    page_title="DMARClyzer Dashboard", 
    page_icon="🛡️", 
    layout="wide",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': None
    }
)

hide_st_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
"""
st.markdown(hide_st_style, unsafe_allow_html=True)

@st.cache_resource
def get_engine_cached():
    return get_engine()

engine = get_engine_cached()
Session = sessionmaker(bind=engine)

def fetch_data():
    with Session() as session:
        # Get overall limits for filters
        min_date = session.query(func.min(Report.begin_date)).scalar()
        max_date = session.query(func.max(Report.end_date)).scalar()
        all_domains = [d[0] for d in session.query(Report.domain).distinct().all() if d[0]]
        all_orgs = [o[0] for o in session.query(Report.org_name).distinct().all() if o[0]]
        return min_date, max_date, all_domains, all_orgs

# Error handling if empty
try:
    with Session() as session:
        has_data = session.query(Report).first() is not None
except Exception:
    has_data = False

if not has_data:
    st.title("🛡️ DMARClyzer")
    st.info("No DMARC reports found yet. The fetcher daemon might still be processing, or your configured IMAP inbox hasn't received any new valid Aggregate XML attachments.")
    st.stop()

# Sidebar Filters
st.sidebar.header("Filter Reports")
min_dt, max_dt, available_domains, available_orgs = fetch_data()

# Dates
startDate = min_dt.date() if min_dt else datetime.today().date() - timedelta(days=30)
endDate = max_dt.date() if max_dt else datetime.today().date()

dates = st.sidebar.date_input("Date Range", [startDate, endDate], min_value=startDate, max_value=endDate)
if len(dates) == 2:
    start_filter, end_filter = dates
elif len(dates) == 1:
    start_filter = dates[0]
    end_filter = endDate
else:
    start_filter = startDate
    end_filter = endDate

# Multi-selects
selected_domains = st.sidebar.multiselect("Domains", available_domains, default=available_domains)
selected_orgs = st.sidebar.multiselect("Reporter Organizations", available_orgs, default=available_orgs)

if not selected_domains or not selected_orgs:
    st.warning("Please select at least one Domain and one Organization from the sidebar to view data.")
    st.stop()

st.title("🛡️ DMARC Dashboard")
st.markdown("Advanced interactive filtering and charting for your DMARC aggregate reports.")

# Query data based on filters
with Session() as session:
    query = session.query(
        Report.domain,
        Report.org_name,
        Report.begin_date,
        Record.source_ip,
        Record.count,
        Record.disposition,
        Record.dkim,
        Record.spf,
        Record.reason
    ).join(Record, Report.id == Record.report_id)
    
    query = query.filter(Report.domain.in_(selected_domains))
    query = query.filter(Report.org_name.in_(selected_orgs))
    
    query = query.filter(Report.begin_date >= start_filter, Report.begin_date <= pd.to_datetime(end_filter) + pd.Timedelta(days=1))
    
    df = pd.read_sql(query.statement, session.bind)

if df.empty:
    st.warning("No records match the current filters.")
    st.stop()

# Basic metrics
col1, col2, col3 = st.columns(3)
col1.metric("Total Unique IPs", df['source_ip'].nunique())
col2.metric("Total Email Volume", int(df['count'].sum()))
pass_rate = (df[df['disposition'] == 'none']['count'].sum() / df['count'].sum()) * 100 if df['count'].sum() > 0 else 0
col3.metric("Overall Pass Rate (none)", f"{pass_rate:.1f}%")

st.divider()

# Time series chart
st.subheader("Email Volume over Time")
df['date'] = pd.to_datetime(df['begin_date']).dt.date
daily_vol = df.groupby(['date', 'disposition'])['count'].sum().reset_index()

vol_pivot = daily_vol.pivot(index='date', columns='disposition', values='count').fillna(0)

# If only one day of data exists, an Area chart will fail to render lines. We default to a Bar chart in that state.
if len(vol_pivot) < 2:
    st.bar_chart(vol_pivot)
else:
    st.area_chart(vol_pivot)

colA, colB = st.columns(2)

with colA:
    st.subheader("DKIM Alignment")
    dkim_counts = df.groupby('dkim')['count'].sum().reset_index()
    if not dkim_counts.empty:
        st.bar_chart(dkim_counts.set_index('dkim'))

with colB:
    st.subheader("SPF Alignment")
    spf_counts = df.groupby('spf')['count'].sum().reset_index()
    if not spf_counts.empty:
        st.bar_chart(spf_counts.set_index('spf'))

st.subheader("Failure Analysis & Top Source IPs")
failures_df = df[df['disposition'] != 'none']
if not failures_df.empty:
    st.markdown("**Detailed Failure Breakdown**")
    fail_stats = failures_df.groupby(['source_ip', 'domain', 'reason', 'dkim', 'spf'])['count'].sum().reset_index().sort_values(by='count', ascending=False)
    st.dataframe(fail_stats, use_container_width=True)
else:
    st.success("No DMARC failures detected for the currently filtered domains!")

st.markdown("**All Source IPs Summary**")
ip_stats = df.groupby(['source_ip', 'domain', 'org_name', 'disposition'])['count'].sum().reset_index().sort_values(by='count', ascending=False).head(500)
st.dataframe(ip_stats, use_container_width=True)
