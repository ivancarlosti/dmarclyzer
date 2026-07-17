import os
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class Report(Base):
    __tablename__ = 'reports'
    id = Column(Integer, primary_key=True)
    org_name = Column(String(255))
    email = Column(String(255))
    report_id = Column(String(255), unique=True)
    begin_date = Column(DateTime)
    end_date = Column(DateTime)
    domain = Column(String(255))
    adkim = Column(String(10))
    aspf = Column(String(10))
    p = Column(String(20))
    sp = Column(String(20))
    pct = Column(Integer)

class Record(Base):
    __tablename__ = 'records'
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey('reports.id'))
    source_ip = Column(String(50))
    host_name = Column(String(255))
    count = Column(Integer)
    disposition = Column(String(20))
    dkim = Column(String(20))
    spf = Column(String(20))
    reason = Column(String(255))
    header_from = Column(String(255))

class AuthResult(Base):
    __tablename__ = 'auth_results'
    id = Column(Integer, primary_key=True)
    record_id = Column(Integer, ForeignKey('records.id'))
    type = Column(String(10)) # dkim or spf
    domain = Column(String(255))
    result = Column(String(20))
    selector = Column(String(255))

def get_engine():
    db_user = os.environ.get("DB_USER", "dmarcuser")
    db_pass = os.environ.get("DB_PASSWORD", "dmarcpass")
    db_host = os.environ.get("DB_HOST", "db")
    db_name = os.environ.get("DB_NAME", "dmarc")
    
    # We use PyMySQL with SQLAlchemy for MariaDB connection
    database_url = f"mysql+pymysql://{db_user}:{db_pass}@{db_host}/{db_name}"
    engine = create_engine(database_url, echo=False)
    return engine

import logging
from sqlalchemy import text

logger = logging.getLogger(__name__)

def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
    
    # Graceful migration for existing production databases mapping old SQLite sets to standard MariaDB schemas
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE records ADD COLUMN IF NOT EXISTS host_name VARCHAR(255)"))
        except Exception:
            pass


def cleanup_old_reports():
    """Deletes reports older than REPORT_RETENTION_DAYS (default 180).
    A value of 0 disables cleanup. Deletes in FK order: auth_results → records → reports."""
    days = int(os.environ.get("REPORT_RETENTION_DAYS", "180"))
    if days <= 0:
        logger.info("REPORT_RETENTION_DAYS is 0 or negative — skipping cleanup.")
        return

    engine = get_engine()
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        cutoff = datetime.now() - timedelta(days=days)
        logger.info(f"Cleaning up reports older than {days} days (before {cutoff.strftime('%Y-%m-%d %H:%M:%S')})...")

        # Delete from leaf tables first due to FK constraints (no CASCADE defined)
        deleted_auth = (
            session.query(AuthResult)
            .filter(
                AuthResult.record_id.in_(
                    session.query(Record.id).filter(
                        Record.report_id.in_(
                            session.query(Report.id).filter(Report.begin_date < cutoff)
                        )
                    )
                )
            )
            .delete(synchronize_session=False)
        )

        deleted_records = (
            session.query(Record)
            .filter(
                Record.report_id.in_(
                    session.query(Report.id).filter(Report.begin_date < cutoff)
                )
            )
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
                f"Cleanup complete: deleted {deleted_reports} reports, "
                f"{deleted_records} records, {deleted_auth} auth_results "
                f"(total {total_deleted} rows)."
            )
        else:
            logger.info("Cleanup run — no old reports found to delete.")

    except Exception as e:
        session.rollback()
        logger.error(f"Cleanup failed: {e}")
    finally:
        session.close()
