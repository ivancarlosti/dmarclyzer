import os
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

from sqlalchemy import text

def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
    
    # Graceful migration for existing production databases mapping old SQLite sets to standard MariaDB schemas
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE records ADD COLUMN IF NOT EXISTS host_name VARCHAR(255)"))
        except Exception:
            pass
