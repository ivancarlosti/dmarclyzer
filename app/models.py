"""SQLAlchemy models and database bootstrap for DMARClyzer."""

import logging
import os
from datetime import datetime, timedelta
from functools import lru_cache

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker

from security import env_int, is_safe_index_name

logger = logging.getLogger(__name__)

Base = declarative_base()


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    org_name = Column(String(255))
    email = Column(String(255))
    # RFC 7489 scopes Report-ID uniqueness to the reporting organization, so a
    # single globally-unique column lets one reporter suppress another's data.
    report_id = Column(String(255))
    begin_date = Column(DateTime)
    end_date = Column(DateTime)
    domain = Column(String(255))
    adkim = Column(String(10))
    aspf = Column(String(10))
    p = Column(String(20))
    sp = Column(String(20))
    pct = Column(Integer)

    __table_args__ = (
        UniqueConstraint(
            "report_id", "org_name", "domain", name="uq_reports_identity"
        ),
    )


class Record(Base):
    __tablename__ = "records"
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"))
    source_ip = Column(String(50))
    host_name = Column(String(255))
    count = Column(Integer)
    disposition = Column(String(20))
    dkim = Column(String(20))
    spf = Column(String(20))
    reason = Column(String(255))
    header_from = Column(String(255))


class AuthResult(Base):
    __tablename__ = "auth_results"
    id = Column(Integer, primary_key=True)
    record_id = Column(Integer, ForeignKey("records.id"))
    type = Column(String(10))  # dkim or spf
    domain = Column(String(255))
    result = Column(String(20))
    selector = Column(String(255))


@lru_cache(maxsize=1)
def get_engine():
    """Build (and cache) the SQLAlchemy engine with safe URL handling."""

    db_user = os.environ.get("DB_USER", "dmarcuser")
    db_host = os.environ.get("DB_HOST", "db")
    db_name = os.environ.get("DB_NAME", "dmarc")
    db_port = env_int("DB_PORT", 3306, minimum=1, maximum=65535)

    db_pass = os.environ.get("DB_PASSWORD")
    if not db_pass:
        # Kept for backwards compatibility with the documented compose setup,
        # but it must be loud: this is a well-known default credential.
        logger.warning(
            "DB_PASSWORD is not set; using the insecure default password. "
            "Set DB_PASSWORD in production."
        )
        db_pass = "dmarcpass"

    connect_args: dict = {}
    ssl_ca = (os.environ.get("DB_SSL_CA") or "").strip()
    if ssl_ca:
        connect_args["ssl"] = {"ca": ssl_ca, "check_hostname": True}

    # URL.create percent-encodes special characters (passwords containing
    # '@', ':' or '/' used to corrupt the DSN or leak it into logs).
    url = URL.create(
        "mysql+pymysql",
        username=db_user,
        password=db_pass,
        host=db_host,
        port=db_port,
        database=db_name,
    )
    return create_engine(
        url,
        echo=False,
        pool_pre_ping=True,
        pool_recycle=3600,
        connect_args=connect_args,
    )


def _ensure_host_name_column(conn):
    """Add records.host_name to databases created before it was introduced."""
    try:
        conn.execute(
            text("ALTER TABLE records ADD COLUMN IF NOT EXISTS host_name VARCHAR(255)")
        )
    except Exception as exc:
        logger.debug("host_name migration skipped: %s", exc)


def _migrate_report_identity(conn):
    """Replace the legacy global report_id unique index with the RFC-scoped one."""
    try:
        legacy_indexes = conn.execute(
            text(
                """
                SELECT INDEX_NAME FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'reports'
                  AND NON_UNIQUE = 0
                  AND COLUMN_NAME = 'report_id'
                """
            )
        ).fetchall()
    except Exception as exc:
        logger.warning("Could not inspect indexes on reports: %s", exc)
        return

    for row in legacy_indexes:
        index_name = row[0]
        if index_name in ("PRIMARY", "uq_reports_identity"):
            continue
        if not is_safe_index_name(index_name):
            logger.warning("Skipping unexpected index name %r", index_name)
            continue
        try:
            conn.execute(text(f"ALTER TABLE reports DROP INDEX `{index_name}`"))
            logger.info(
                "Dropped legacy unique index %r on reports.report_id", index_name
            )
        except Exception as exc:
            logger.warning("Could not drop legacy index %r: %s", index_name, exc)

    try:
        already_present = conn.execute(
            text(
                """
                SELECT 1 FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'reports'
                  AND INDEX_NAME = 'uq_reports_identity'
                LIMIT 1
                """
            )
        ).fetchone()
        if not already_present:
            conn.execute(
                text(
                    "ALTER TABLE reports ADD UNIQUE KEY uq_reports_identity "
                    "(report_id, org_name, domain)"
                )
            )
            logger.info("Created composite unique index uq_reports_identity")
    except Exception as exc:
        logger.warning("Could not create uq_reports_identity: %s", exc)


def init_db():
    """Create tables and apply lightweight in-place migrations."""
    engine = get_engine()
    Base.metadata.create_all(engine)

    with engine.begin() as conn:
        _ensure_host_name_column(conn)
        _migrate_report_identity(conn)


def cleanup_old_reports():
    """Delete reports older than REPORT_RETENTION_DAYS (default 180).

    A value of 0 or less disables cleanup. Rows are removed leaf-first because
    the foreign keys do not define ON DELETE CASCADE.
    """
    days = env_int("REPORT_RETENTION_DAYS", 180, minimum=-1, maximum=36500)
    if days <= 0:
        logger.info("REPORT_RETENTION_DAYS is 0 or negative — skipping cleanup.")
        return

    engine = get_engine()
    session = sessionmaker(bind=engine)()

    try:
        cutoff = datetime.now() - timedelta(days=days)
        logger.info(
            "Cleaning up reports older than %s days (before %s)...",
            days,
            cutoff.strftime("%Y-%m-%d %H:%M:%S"),
        )

        old_report_ids = session.query(Report.id).filter(Report.begin_date < cutoff)
        old_record_ids = session.query(Record.id).filter(
            Record.report_id.in_(old_report_ids)
        )

        deleted_auth = (
            session.query(AuthResult)
            .filter(AuthResult.record_id.in_(old_record_ids))
            .delete(synchronize_session=False)
        )
        deleted_records = (
            session.query(Record)
            .filter(Record.report_id.in_(old_report_ids))
            .delete(synchronize_session=False)
        )
        deleted_reports = (
            session.query(Report)
            .filter(Report.begin_date < cutoff)
            .delete(synchronize_session=False)
        )

        session.commit()

        total_deleted = deleted_auth + deleted_records + deleted_reports
        if total_deleted > 0:
            logger.info(
                "Cleanup complete: deleted %s reports, %s records, "
                "%s auth_results (total %s rows).",
                deleted_reports,
                deleted_records,
                deleted_auth,
                total_deleted,
            )
        else:
            logger.info("Cleanup run — no old reports found to delete.")

    except Exception as exc:
        session.rollback()
        logger.error("Cleanup failed (%s).", type(exc).__name__)
    finally:
        session.close()
