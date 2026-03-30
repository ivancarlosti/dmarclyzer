import streamlit as st
import pandas as pd
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from models import get_engine, Report, Record, AuthResult
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
selected_domains_all = st.sidebar.checkbox("Select All Domains", value=True)
selected_domains = st.sidebar.multiselect(
    "Domains", 
    available_domains, 
    default=available_domains if selected_domains_all else []
)

selected_orgs_all = st.sidebar.checkbox("Select All Reporter Organizations", value=True)
selected_orgs = st.sidebar.multiselect(
    "Reporter Organizations", 
    available_orgs, 
    default=available_orgs if selected_orgs_all else []
)

if not selected_domains or not selected_orgs:
    st.warning("Please select at least one Domain and one Organization from the sidebar to view data.")
    st.stop()

st.title("🛡️ DMARC Dashboard")
st.markdown("Advanced interactive filtering and charting for your DMARC aggregate reports.")

# Query data based on filters
with Session() as session:
    query = session.query(
        Record.id.label('record_id'),
        Report.domain,
        Report.org_name,
        Report.begin_date,
        Record.source_ip,
        Record.host_name,
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

    if not df.empty:
        record_ids = df['record_id'].unique().tolist()
        auth_query = session.query(
            AuthResult.record_id, 
            AuthResult.type, 
            AuthResult.domain, 
            AuthResult.result
        ).filter(AuthResult.record_id.in_(record_ids))
        
        auth_df = pd.read_sql(auth_query.statement, session.bind)
        
        if not auth_df.empty:
            # Process DKIM
            dkim_auths = auth_df[auth_df['type'] == 'dkim']
            if not dkim_auths.empty:
                dkim_grouped = dkim_auths.groupby('record_id').agg({
                    'domain': lambda x: ', '.join([str(d) for d in x if pd.notna(d)]),
                    'result': lambda x: ', '.join([str(r) for r in x if pd.notna(r)])
                }).reset_index().rename(columns={'domain': 'dkim_domain', 'result': 'dkim_auth'})
                df = df.merge(dkim_grouped, on='record_id', how='left')
            else:
                df['dkim_domain'] = None
                df['dkim_auth'] = None

            # Process SPF
            spf_auths = auth_df[auth_df['type'] == 'spf']
            if not spf_auths.empty:
                spf_grouped = spf_auths.groupby('record_id').agg({
                    'domain': lambda x: ', '.join([str(d) for d in x if pd.notna(d)]),
                    'result': lambda x: ', '.join([str(r) for r in x if pd.notna(r)])
                }).reset_index().rename(columns={'domain': 'spf_domain', 'result': 'spf_auth'})
                df = df.merge(spf_grouped, on='record_id', how='left')
            else:
                df['spf_domain'] = None
                df['spf_auth'] = None
        else:
            df['dkim_domain'] = None
            df['dkim_auth'] = None
            df['spf_domain'] = None
            df['spf_auth'] = None
            
        df['dmarc'] = df.apply(lambda row: 'pass' if row['disposition'] == 'none' else 'fail', axis=1)

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

st.subheader("Comprehensive Inspection Table")
st.markdown("Detailed tabular breakdown featuring reverse DNS resolving. Hover your mouse horizontally across any column header to view an explicit explanation popup!")

column_config = {
    "source_ip": st.column_config.TextColumn("IP", help="The source IP address of the email sender originating the message"),
    "host_name": st.column_config.TextColumn("Host Name", help="The reverse DNS resolved hostname of the IP address (calculated at parsing time)"),
    "count": st.column_config.NumberColumn("Message Count", help="The sum of messages sent from this IP matching these parameters"),
    "disposition": st.column_config.TextColumn("Disposition", help="The DMARC policy action applied by the receiver: none (pass), quarantine, or reject"),
    "reason": st.column_config.TextColumn("Reason", help="Policy override reasons applied by the receiver, if any (e.g., forwarded, local_policy)"),
    "dkim_domain": st.column_config.TextColumn("DKIM Domain", help="The explicit domain securely embedded in the DKIM cryptographic signature header"),
    "dkim_auth": st.column_config.TextColumn("DKIM Auth", help="The raw result of validating the DKIM cryptographic signature (pass/fail)"),
    "spf_domain": st.column_config.TextColumn("SPF Domain", help="The envelope-from (Return-Path) domain evaluated for SPF routing checks"),
    "spf_auth": st.column_config.TextColumn("SPF Auth", help="The raw result of the SPF validation querying DNS for permitted ranges (pass/fail/softfail)"),
    "dkim": st.column_config.TextColumn("DKIM Align", help="Alignment: Did the passing DKIM Domain properly match the 'From' header domain?"),
    "spf": st.column_config.TextColumn("SPF Align", help="Alignment: Did the passing SPF Domain properly match the 'From' header domain?"),
    "dmarc": st.column_config.TextColumn("DMARC", help="Derived Overall DMARC Pass/Fail. To pass DMARC, a message MUST pass EITHER DKIM Alignment OR SPF Alignment.", width="small")
}

aggregate_cols = ['source_ip', 'host_name', 'count', 'disposition', 'reason', 'dkim_domain', 'dkim_auth', 'spf_domain', 'spf_auth', 'dkim', 'spf', 'dmarc']
ip_stats = df.groupby(['source_ip', 'host_name', 'disposition', 'reason', 'dkim_domain', 'dkim_auth', 'spf_domain', 'spf_auth', 'dkim', 'spf', 'dmarc'], dropna=False)['count'].sum().reset_index().sort_values(by='count', ascending=False)
st.dataframe(ip_stats[aggregate_cols], use_container_width=True, column_config=column_config, hide_index=True)
