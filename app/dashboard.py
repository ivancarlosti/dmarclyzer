import streamlit as st
import pandas as pd
from sqlalchemy.orm import sessionmaker
from models import get_engine, Report, Record

st.set_page_config(page_title="DMARClyzer Dashboard", page_icon="🛡️", layout="wide")

@st.cache_resource
def get_db_session():
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()

session = get_db_session()

st.title("🛡️ DMARClyzer")
st.markdown("Modern DMARC Aggregate Report Analyzer")

# Basic metrics
total_reports = session.query(Report).count()
total_records = session.query(Record).count()

col1, col2 = st.columns(2)
col1.metric("Total Reports Processed", total_reports)
col2.metric("Total IPs/Records Processed", total_records)

st.divider()

if total_reports > 0:
    st.subheader("Recent Reports Overview")
    # Fetch some reports to display
    query = session.query(
        Report.domain,
        Report.org_name,
        Report.begin_date,
        Report.end_date,
        Report.p,
        Report.sp
    ).order_by(Report.begin_date.desc()).limit(100)
    
    df = pd.read_sql(query.statement, session.bind)
    st.dataframe(df, use_container_width=True)

    st.subheader("Source IPs Overview (Dispositions)")
    # Fetch records for charts
    rec_query = session.query(
        Record.source_ip,
        Record.disposition,
        Record.dkim,
        Record.spf,
        Record.count
    ).limit(1000)
    df_rec = pd.read_sql(rec_query.statement, session.bind)
    
    if not df_rec.empty:
        colA, colB = st.columns(2)
        with colA:
            st.markdown("**Disposition Breakdown**")
            disp_counts = df_rec.groupby('disposition')['count'].sum().reset_index()
            # We index by disposition so Streamlit automatically uses it for the axis
            st.bar_chart(disp_counts.set_index('disposition'))

        with colB:
            st.markdown("**SPF Evaluation**")
            spf_counts = df_rec.groupby('spf')['count'].sum().reset_index()
            st.bar_chart(spf_counts.set_index('spf'))

        st.markdown("**Record Details**")
        st.dataframe(df_rec, use_container_width=True)
else:
    st.info("No DMARC reports found yet. The fetcher might still be processing, or the IMAP inbox is empty/lacks attachments.")
