import xmltodict
import logging
from datetime import datetime
from sqlalchemy.orm import sessionmaker
from models import get_engine, init_db, Report, Record, AuthResult

logger = logging.getLogger(__name__)

def parse_dmarc_xml(xml_content):
    """Parses a single DMARC XML string and saves it to MariaDB."""
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        data = xmltodict.parse(xml_content)
        feedback = data.get('feedback', {})
        
        report_metadata = feedback.get('report_metadata', {})
        policy_published = feedback.get('policy_published', {})
        
        org_name = report_metadata.get('org_name')
        email = report_metadata.get('email')
        report_id_str = report_metadata.get('report_id')
        
        # Check if report already exists
        existing = session.query(Report).filter_by(report_id=report_id_str).first()
        if existing:
            logger.info(f"Report {report_id_str} already parsed. Skipping.")
            return

        date_range = report_metadata.get('date_range', {})
        begin_date = datetime.fromtimestamp(int(date_range.get('begin', 0)))
        end_date = datetime.fromtimestamp(int(date_range.get('end', 0)))

        domain = policy_published.get('domain')
        adkim = policy_published.get('adkim')
        aspf = policy_published.get('aspf')
        p = policy_published.get('p')
        sp = policy_published.get('sp')
        pct = int(policy_published.get('pct', 100))

        report = Report(
            org_name=org_name,
            email=email,
            report_id=report_id_str,
            begin_date=begin_date,
            end_date=end_date,
            domain=domain,
            adkim=adkim,
            aspf=aspf,
            p=p,
            sp=sp,
            pct=pct
        )
        session.add(report)
        session.commit() # commit early to get report.id for foreign keys

        records = feedback.get('record', [])
        if not isinstance(records, list):
            records = [records]

        for prec in records:
            row = prec.get('row', {})
            source_ip = row.get('source_ip')
            count = int(row.get('count', 0))
            
            policy_evaluated = row.get('policy_evaluated', {})
            disposition = policy_evaluated.get('disposition')
            dkim_eval = policy_evaluated.get('dkim')
            spf_eval = policy_evaluated.get('spf')
            
            reasons = policy_evaluated.get('reason', [])
            if isinstance(reasons, dict):
                reasons = [reasons]
            reason_str = ', '.join([r.get('type', '') for r in reasons if isinstance(r, dict)])

            identifiers = prec.get('identifiers', {})
            header_from = identifiers.get('header_from')

            record = Record(
                report_id=report.id,
                source_ip=source_ip,
                count=count,
                disposition=disposition,
                dkim=dkim_eval,
                spf=spf_eval,
                reason=reason_str,
                header_from=header_from
            )
            session.add(record)
            session.commit() 

            # Auth results (DKIM & SPF granular results)
            auth_results = prec.get('auth_results', {})
            dkim_results = auth_results.get('dkim', [])
            if not isinstance(dkim_results, list):
                dkim_results = [dkim_results]
            
            for dr in dkim_results:
                if not isinstance(dr, dict): continue
                ar = AuthResult(
                    record_id=record.id,
                    type='dkim',
                    domain=dr.get('domain'),
                    result=dr.get('result'),
                    selector=dr.get('selector')
                )
                session.add(ar)

            spf_results = auth_results.get('spf', [])
            if not isinstance(spf_results, list):
                spf_results = [spf_results]
            
            for sr in spf_results:
                if not isinstance(sr, dict): continue
                ar = AuthResult(
                    record_id=record.id,
                    type='spf',
                    domain=sr.get('domain'),
                    result=sr.get('result'),
                    selector=None
                )
                session.add(ar)
        
        session.commit()
        logger.info(f"Successfully processed report {report_id_str}")

    except Exception as e:
        session.rollback()
        logger.error(f"Failed to parse XML: {e}")
    finally:
        session.close()
