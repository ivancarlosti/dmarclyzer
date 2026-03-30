import streamlit as st
import pandas as pd
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from models import get_engine, Report, Record, AuthResult
from datetime import datetime, timedelta
from auth import require_auth

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

if not require_auth():
    st.stop()

hide_st_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Aggressively reduce main container padded whitespace */
    .block-container {
        padding-top: 1rem !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
        padding-bottom: 1rem !important;
    }
    
    /* Reduce sidebar whitespace */
    section[data-testid="stSidebar"] div.css-ng1t4o, 
    section[data-testid="stSidebar"] div.css-1d391kg {
        padding-top: 1rem !important;
    }
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
max_allowed = max_dt.date() if max_dt else datetime.today().date()
min_allowed = min_dt.date() if min_dt else datetime.today().date() - timedelta(days=30)

default_start = max_allowed - timedelta(days=7)
if default_start < min_allowed:
    default_start = min_allowed

dates = st.sidebar.date_input("Date Range", [default_start, max_allowed], min_value=min_allowed, max_value=max_allowed)
if len(dates) == 2:
    start_filter, end_filter = dates
else:
    st.warning("Please select both a start and end date from the sidebar Date Range.")
    st.stop()

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

# Global Data Fetching for Charts
with Session() as session:
    # 1. Global Metrics Query
    global_query = session.query(
        Report.begin_date,
        Record.source_ip,
        Record.count,
        Record.disposition,
        Record.dkim,
        Record.spf
    ).join(Record, Report.id == Record.report_id)
    
    global_query = global_query.filter(Report.domain.in_(selected_domains))
    global_query = global_query.filter(Report.org_name.in_(selected_orgs))
    global_query = global_query.filter(Report.begin_date >= start_filter, Report.begin_date <= pd.to_datetime(end_filter) + pd.Timedelta(days=1))
    
    global_df = pd.read_sql(global_query.statement, session.bind)

    if global_df.empty:
        st.warning("No records match the current filters.")
        st.stop()

    # Basic metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total IPs Evaluated", global_df['source_ip'].nunique())
    col2.metric("Total Email Message Volume", int(global_df['count'].sum()))
    pass_rate = (global_df[global_df['disposition'] == 'none']['count'].sum() / global_df['count'].sum()) * 100 if global_df['count'].sum() > 0 else 0
    col3.metric("Overall Authenticated Pass Rate", f"{pass_rate:.1f}%")

    # Time series chart
    st.subheader("Global Email Volume over Time")
    global_df['date'] = pd.to_datetime(global_df['begin_date']).dt.date
    daily_vol = global_df.groupby(['date', 'disposition'])['count'].sum().reset_index()
    vol_pivot = daily_vol.pivot(index='date', columns='disposition', values='count').fillna(0)
    if len(vol_pivot) < 2:
        st.bar_chart(vol_pivot)
    else:
        st.area_chart(vol_pivot)

    st.divider()

    # 2. Master Reports List Query
    st.subheader("Available DMARC Reports")
    st.markdown("Select an individual report row from below to instantly expand the deep IP-level processing inspection array exactly like the legacy PHP application!")

    report_query = session.query(
        Report.begin_date.label('Start Date'),
        Report.end_date.label('End Date'),
        Report.domain.label('Domain'),
        Report.org_name.label('Reporting Organization'),
        Report.report_id.label('Report ID'),
        func.sum(Record.count).label('Messages'),
        Report.id.label('db_id'),
        Report.adkim.label('adkim'),
        Report.aspf.label('aspf'),
        Report.p.label('p'),
        Report.sp.label('sp'),
        Report.pct.label('pct')
    ).join(Record, Report.id == Record.report_id).group_by(Report.id)

    report_query = report_query.filter(Report.domain.in_(selected_domains))
    report_query = report_query.filter(Report.org_name.label('Reporting Organization').in_(selected_orgs))
    report_query = report_query.filter(Report.begin_date >= start_filter, Report.begin_date <= pd.to_datetime(end_filter) + pd.Timedelta(days=1))
    
    reports_df = pd.read_sql(report_query.statement, session.bind)
    reports_df.sort_values(by='Start Date', ascending=False, inplace=True)
    
    display_df = reports_df[['Start Date', 'End Date', 'Domain', 'Reporting Organization', 'Report ID', 'Messages']]
    
    # Render Master List natively requesting selection state
    event = st.dataframe(display_df, on_select="rerun", selection_mode="single-row", width="stretch", hide_index=True)
    
    selected_rows = event.selection.rows
    if not selected_rows:
        st.info("👆 Click directly on any row inside the table above to drill down into the Comprehensive IP inspection!")
    else:
        st.divider()
        # 3. Detail View Render
        selected_index = selected_rows[0]
        selected_report = reports_df.iloc[selected_index]
        
        # Policy Header identical to legacy
        st.markdown(f"**Report from {selected_report['Reporting Organization']} for {selected_report['Domain']}**")
        st.markdown(f"{selected_report['Start Date']} to {selected_report['End Date']}")
        st.markdown(f"**Policies: adkim={selected_report['adkim']}, aspf={selected_report['aspf']}, p={selected_report['p']}, sp={selected_report['sp']}, pct={selected_report['pct']}**")
        
        # Comprehensive Data Query scoped explicitly to this document
        target_db_id = int(selected_report['db_id'])
        
        detail_query = session.query(
            Record.id.label('record_id'),
            Record.source_ip,
            Record.host_name,
            Record.count,
            Record.disposition,
            Record.dkim,
            Record.spf,
            Record.reason
        ).filter(Record.report_id == target_db_id)
        
        detail_df = pd.read_sql(detail_query.statement, session.bind)
        
        if not detail_df.empty:
            record_ids = detail_df['record_id'].unique().tolist()
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
                    detail_df = detail_df.merge(dkim_grouped, on='record_id', how='left')
                else:
                    detail_df['dkim_domain'] = None
                    detail_df['dkim_auth'] = None

                # Process SPF
                spf_auths = auth_df[auth_df['type'] == 'spf']
                if not spf_auths.empty:
                    spf_grouped = spf_auths.groupby('record_id').agg({
                        'domain': lambda x: ', '.join([str(d) for d in x if pd.notna(d)]),
                        'result': lambda x: ', '.join([str(r) for r in x if pd.notna(r)])
                    }).reset_index().rename(columns={'domain': 'spf_domain', 'result': 'spf_auth'})
                    detail_df = detail_df.merge(spf_grouped, on='record_id', how='left')
                else:
                    detail_df['spf_domain'] = None
                    detail_df['spf_auth'] = None
            else:
                detail_df['dkim_domain'] = None
                detail_df['dkim_auth'] = None
                detail_df['spf_domain'] = None
                detail_df['spf_auth'] = None
                
            detail_df['dmarc'] = detail_df.apply(lambda row: 'pass' if row['disposition'] == 'none' else 'fail', axis=1)

            column_config = {
                "source_ip": st.column_config.TextColumn("IP", help="The source IP address of the email sender originating the message"),
                "host_name": st.column_config.TextColumn("Host Name", help="The reverse DNS resolved hostname of the IP address"),
                "count": st.column_config.NumberColumn("Message Count", help="The sum of messages sent from this IP"),
                "disposition": st.column_config.TextColumn("Disposition", help="The DMARC policy action applied by the receiver: none (pass), quarantine, or reject"),
                "reason": st.column_config.TextColumn("Reason", help="Policy override reasons applied by the receiver"),
                "dkim_domain": st.column_config.TextColumn("DKIM Domain", help="The explicit domain securely embedded in the DKIM cryptographic signature header"),
                "dkim_auth": st.column_config.TextColumn("DKIM Auth", help="The raw result of validating the DKIM cryptographic signature"),
                "spf_domain": st.column_config.TextColumn("SPF Domain", help="The envelope-from (Return-Path) domain evaluated for SPF routing checks"),
                "spf_auth": st.column_config.TextColumn("SPF Auth", help="The raw result of the SPF validation querying DNS for permitted ranges"),
                "dkim": st.column_config.TextColumn("DKIM Align", help="Alignment: Did the passing DKIM Domain properly match the 'From' header domain?"),
                "spf": st.column_config.TextColumn("SPF Align", help="Alignment: Did the passing SPF Domain properly match the 'From' header domain?"),
                "dmarc": st.column_config.TextColumn("DMARC", help="Derived Overall DMARC Pass/Fail")
            }

            aggregate_cols = ['source_ip', 'host_name', 'count', 'disposition', 'reason', 'dkim_domain', 'dkim_auth', 'spf_domain', 'spf_auth', 'dkim', 'spf', 'dmarc']
            ip_stats = detail_df.groupby(['source_ip', 'host_name', 'disposition', 'reason', 'dkim_domain', 'dkim_auth', 'spf_domain', 'spf_auth', 'dkim', 'spf', 'dmarc'], dropna=False)['count'].sum().reset_index().sort_values(by='count', ascending=False)
            st.dataframe(ip_stats[aggregate_cols], width="stretch", column_config=column_config, hide_index=True)
            
            # Simple UI HTML Export Button placeholder logic for isolated viewing
            # st.download_button("Export Detailed Selection", data=ip_stats[aggregate_cols].to_csv(index=False), file_name=f"dmarc_export_{selected_report['Report ID']}.csv", mime="text/csv")
