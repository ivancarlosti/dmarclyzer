"""
DMARClyzer Dashboard — Shared Data Queries

All database access is centralized here. Each function returns a pd.DataFrame
or scalar values. All functions accept the same filter signature for consistency.

Caching: @st.cache_data is used for expensive queries with TTL.
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func, case, text
from models import get_engine, Report, Record, AuthResult


@st.cache_resource
def _get_engine_cached():
    return get_engine()


@st.cache_data(ttl=300, show_spinner=False)
def fetch_filter_bounds():
    """Return (min_date, max_date, all_domains[], all_orgs[]) for sidebar filters."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        min_date = session.query(func.min(Report.begin_date)).scalar()
        max_date = session.query(func.max(Report.end_date)).scalar()
        all_domains = [d[0] for d in session.query(Report.domain).distinct().all() if d[0]]
        all_orgs = [o[0] for o in session.query(Report.org_name).distinct().all() if o[0]]
        return min_date, max_date, all_domains, all_orgs


def _base_record_query(session, start_date, end_date, domains, orgs):
    """Return a base query joining Reports + Records with common filters applied."""
    q = (
        session.query(
            Report.begin_date,
            Report.domain,
            Report.org_name,
            Report.p,
            Report.sp,
            Report.pct,
            Record.source_ip,
            Record.host_name,
            Record.count,
            Record.disposition,
            Record.dkim,
            Record.spf,
            Record.reason,
        )
        .join(Record, Report.id == Record.report_id)
        .filter(Report.domain.in_(domains))
        .filter(Report.org_name.in_(orgs))
        .filter(
            Report.begin_date >= start_date,
            Report.begin_date <= pd.to_datetime(end_date) + pd.Timedelta(days=1),
        )
    )
    return q


def _source_category_expr():
    """SQLAlchemy CASE expression for source classification."""
    return case(
        (
            (Record.dkim == "pass") & (Record.spf == "pass"),
            "Compliant",
        ),
        (
            (Record.dkim == "pass") & (Record.spf == "fail"),
            "Forwarded",
        ),
        (
            (Record.dkim == "fail") & (Record.spf == "pass"),
            "DKIM Issue",
        ),
        else_="Failing",
    )


# ═══════════════════════════════════════════════════════════
# Overview Tab Queries
# ═══════════════════════════════════════════════════════════

@st.cache_data(ttl=300, show_spinner="Loading overview metrics...")
def fetch_overview_metrics(start_date, end_date, domains, orgs):
    """Return dict of aggregate KPIs for the Overview tab."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = _base_record_query(session, start_date, end_date, domains, orgs)
        df = pd.read_sql(q.statement, session.bind)

        if df.empty:
            return {
                "total_messages": 0,
                "total_ips": 0,
                "pass_rate": 0.0,
                "compliant_msgs": 0,
                "failing_msgs": 0,
                "forwarded_msgs": 0,
                "dkim_pass_rate": 0.0,
                "spf_pass_rate": 0.0,
            }

        total_msgs = int(df["count"].sum())
        total_ips = df["source_ip"].nunique()

        # DMARC pass: at least one alignment passes
        df["dmarc_pass"] = (df["dkim"] == "pass") | (df["spf"] == "pass")
        compliant_msgs = int(df.loc[df["dmarc_pass"], "count"].sum())
        pass_rate = (compliant_msgs / total_msgs * 100) if total_msgs > 0 else 0.0

        # DKIM pass rate
        dkim_pass_msgs = int(df.loc[df["dkim"] == "pass", "count"].sum())
        dkim_pass_rate = (dkim_pass_msgs / total_msgs * 100) if total_msgs > 0 else 0.0

        # SPF pass rate  
        spf_pass_msgs = int(df.loc[df["spf"] == "pass", "count"].sum())
        spf_pass_rate = (spf_pass_msgs / total_msgs * 100) if total_msgs > 0 else 0.0

        # Failing: both fail
        failing_msgs = int(df.loc[(df["dkim"] == "fail") & (df["spf"] == "fail"), "count"].sum())
        # Forwarded: DKIM pass, SPF fail
        forwarded_msgs = int(df.loc[(df["dkim"] == "pass") & (df["spf"] == "fail"), "count"].sum())

        return {
            "total_messages": total_msgs,
            "total_ips": total_ips,
            "pass_rate": round(pass_rate, 1),
            "compliant_msgs": compliant_msgs,
            "failing_msgs": failing_msgs,
            "forwarded_msgs": forwarded_msgs,
            "dkim_pass_rate": round(dkim_pass_rate, 1),
            "spf_pass_rate": round(spf_pass_rate, 1),
        }


@st.cache_data(ttl=300, show_spinner="Loading volume trends...")
def fetch_volume_timeseries(start_date, end_date, domains, orgs):
    """Return DataFrame with daily volume grouped by disposition."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = _base_record_query(session, start_date, end_date, domains, orgs)
        df = pd.read_sql(q.statement, session.bind)
        if df.empty:
            return pd.DataFrame()

        df["date"] = pd.to_datetime(df["begin_date"]).dt.date
        daily = df.groupby(["date", "disposition"])["count"].sum().reset_index()
        return daily


@st.cache_data(ttl=300, show_spinner=False)
def fetch_disposition_distribution(start_date, end_date, domains, orgs):
    """Return DataFrame with total count per disposition type."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = _base_record_query(session, start_date, end_date, domains, orgs)
        df = pd.read_sql(q.statement, session.bind)
        if df.empty:
            return pd.DataFrame(columns=["disposition", "count"])

        dist = df.groupby("disposition")["count"].sum().reset_index()
        return dist


@st.cache_data(ttl=300, show_spinner=False)
def fetch_dkim_spf_alignment(start_date, end_date, domains, orgs):
    """Return DataFrame with DKIM/SPF pass/fail counts for comparison charts."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = _base_record_query(session, start_date, end_date, domains, orgs)
        df = pd.read_sql(q.statement, session.bind)
        if df.empty:
            return pd.DataFrame()

        dkim_pass = int(df.loc[df["dkim"] == "pass", "count"].sum())
        dkim_fail = int(df.loc[df["dkim"] == "fail", "count"].sum())
        spf_pass = int(df.loc[df["spf"] == "pass", "count"].sum())
        spf_fail = int(df.loc[df["spf"] == "fail", "count"].sum())

        return pd.DataFrame(
            {
                "Protocol": ["DKIM", "DKIM", "SPF", "SPF"],
                "Result": ["Pass", "Fail", "Pass", "Fail"],
                "Messages": [dkim_pass, dkim_fail, spf_pass, spf_fail],
            }
        )


@st.cache_data(ttl=300, show_spinner=False)
def fetch_policy_distribution(start_date, end_date, domains, orgs):
    """Return DataFrame with policy (p=) distribution per domain."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = (
            session.query(
                Report.domain,
                Report.p,
                func.count(Report.id).label("report_count"),
            )
            .filter(Report.domain.in_(domains))
            .filter(Report.org_name.in_(orgs))
            .filter(
                Report.begin_date >= start_date,
                Report.begin_date <= pd.to_datetime(end_date) + pd.Timedelta(days=1),
            )
            .group_by(Report.domain, Report.p)
        )
        df = pd.read_sql(q.statement, session.bind)
        return df


# ═══════════════════════════════════════════════════════════
# Sources Tab Queries
# ═══════════════════════════════════════════════════════════

@st.cache_data(ttl=300, show_spinner="Loading source classification...")
def fetch_source_classification(start_date, end_date, domains, orgs):
    """Return IP-level DataFrame with source category classification."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        category = _source_category_expr()

        q = (
            session.query(
                Record.source_ip,
                Record.host_name,
                func.sum(Record.count).label("total_count"),
                Record.dkim,
                Record.spf,
                Record.disposition,
                category.label("category"),
            )
            .join(Report, Record.report_id == Report.id)
            .filter(Report.domain.in_(domains))
            .filter(Report.org_name.in_(orgs))
            .filter(
                Report.begin_date >= start_date,
                Report.begin_date <= pd.to_datetime(end_date) + pd.Timedelta(days=1),
            )
            .group_by(Record.source_ip, Record.host_name, Record.dkim, Record.spf, Record.disposition, category)
            .order_by(func.sum(Record.count).desc())
        )
        df = pd.read_sql(q.statement, session.bind)
        return df


@st.cache_data(ttl=300, show_spinner=False)
def fetch_forwarded_analysis(start_date, end_date, domains, orgs):
    """Return IPs where DKIM passes but SPF fails (forwarded mail)."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = (
            session.query(
                Record.source_ip,
                Record.host_name,
                func.sum(Record.count).label("total_count"),
                Report.domain,
            )
            .join(Report, Record.report_id == Report.id)
            .filter(Report.domain.in_(domains))
            .filter(Report.org_name.in_(orgs))
            .filter(
                Report.begin_date >= start_date,
                Report.begin_date <= pd.to_datetime(end_date) + pd.Timedelta(days=1),
            )
            .filter(Record.dkim == "pass", Record.spf == "fail")
            .group_by(Record.source_ip, Record.host_name, Report.domain)
            .order_by(func.sum(Record.count).desc())
            .limit(20)
        )
        df = pd.read_sql(q.statement, session.bind)
        return df


# ═══════════════════════════════════════════════════════════
# Domains Tab Queries
# ═══════════════════════════════════════════════════════════

@st.cache_data(ttl=300, show_spinner="Loading domain metrics...")
def fetch_domain_metrics(start_date, end_date, domains, orgs):
    """Return per-domain aggregate metrics."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = _base_record_query(session, start_date, end_date, domains, orgs)
        df = pd.read_sql(q.statement, session.bind)
        if df.empty:
            return pd.DataFrame(
                columns=[
                    "domain", "total_messages", "pass_rate", "dkim_pass_rate",
                    "spf_pass_rate", "policy", "unique_ips",
                ]
            )

        results = []
        for domain_name, group in df.groupby("domain"):
            total = int(group["count"].sum())
            group["dmarc_pass"] = (group["dkim"] == "pass") | (group["spf"] == "pass")
            pass_msgs = int(group.loc[group["dmarc_pass"], "count"].sum())
            pass_rate = (pass_msgs / total * 100) if total > 0 else 0.0
            dkim_pass = int(group.loc[group["dkim"] == "pass", "count"].sum())
            dkim_rate = (dkim_pass / total * 100) if total > 0 else 0.0
            spf_pass = int(group.loc[group["spf"] == "pass", "count"].sum())
            spf_rate = (spf_pass / total * 100) if total > 0 else 0.0
            policy = group["p"].mode().iloc[0] if not group["p"].mode().empty else "unknown"
            unique_ips = group["source_ip"].nunique()

            results.append(
                {
                    "domain": domain_name,
                    "total_messages": total,
                    "pass_rate": round(pass_rate, 1),
                    "dkim_pass_rate": round(dkim_rate, 1),
                    "spf_pass_rate": round(spf_rate, 1),
                    "policy": policy,
                    "unique_ips": unique_ips,
                }
            )

        return pd.DataFrame(results).sort_values("total_messages", ascending=False)


@st.cache_data(ttl=300, show_spinner=False)
def fetch_policy_timeline(start_date, end_date, domains, orgs):
    """Return DataFrame showing policy (p=) over time per domain."""
    engine = _get_engine_cached()
    Session = sessionmaker(bind=engine)
    with Session() as session:
        q = (
            session.query(
                Report.begin_date,
                Report.domain,
                Report.p,
                func.count(Report.id).label("report_count"),
            )
            .filter(Report.domain.in_(domains))
            .filter(Report.org_name.in_(orgs))
            .filter(
                Report.begin_date >= start_date,
                Report.begin_date <= pd.to_datetime(end_date) + pd.Timedelta(days=1),
            )
            .group_by(Report.begin_date, Report.domain, Report.p)
            .order_by(Report.begin_date)
        )
        df = pd.read_sql(q.statement, session.bind)
        if not df.empty:
            df["date"] = pd.to_datetime(df["begin_date"]).dt.date
        return df
