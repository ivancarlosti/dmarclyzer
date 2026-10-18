"""DMARC aggregate report parsing and persistence.

All values in an inbound report are treated as untrusted: lengths are capped
to the database column widths, numbers/timestamps are parsed defensively, XML
entity expansion is disabled, and the global socket timeout used for reverse
DNS is always restored.
"""

import logging
import socket

import xmltodict
from sqlalchemy.orm import sessionmaker

from models import get_engine, Report, Record, AuthResult
from security import env_int, is_valid_ip, safe_int, safe_timestamp, truncate

logger = logging.getLogger(__name__)

_DNS_TIMEOUT_SECONDS = 1.0
_DNS_CACHE_MAX_ENTRIES = 4096
_DNS_CACHE: dict[str, str | None] = {}

_MAX_INT = 2 ** 31 - 1


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _max_xml_bytes() -> int:
    return env_int("MAX_XML_MB", 10, minimum=1, maximum=100) * 1024 * 1024


def _reverse_dns(source_ip) -> str | None:
    """Resolve a sending IP, restoring the global socket timeout afterwards."""
    if not is_valid_ip(source_ip):
        return None
    cache_key = str(source_ip).strip()
    if cache_key in _DNS_CACHE:
        return _DNS_CACHE[cache_key]

    previous_timeout = socket.getdefaulttimeout()
    host_name = None
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT_SECONDS)
        host_name = socket.gethostbyaddr(cache_key)[0]
    except OSError:
        host_name = None
    finally:
        socket.setdefaulttimeout(previous_timeout)

    host_name = truncate(host_name, 255)
    if len(_DNS_CACHE) >= _DNS_CACHE_MAX_ENTRIES:
        _DNS_CACHE.clear()
    _DNS_CACHE[cache_key] = host_name
    return host_name


def _reason_string(policy_evaluated: dict) -> str | None:
    reasons = [
        item.get("type", "")
        for item in _as_list(policy_evaluated.get("reason"))
        if isinstance(item, dict)
    ]
    return truncate(", ".join(str(reason) for reason in reasons), 255)


def parse_dmarc_xml(xml_content):
    """Parse one DMARC XML document and store it in MariaDB."""
    if isinstance(xml_content, bytes):
        if len(xml_content) > _max_xml_bytes():
            logger.error("Skipping report larger than MAX_XML_MB.")
            return
        xml_content = xml_content.decode("utf-8", errors="replace")

    if not isinstance(xml_content, str) or not xml_content.strip():
        logger.warning("Skipping empty DMARC report payload.")
        return

    if len(xml_content.encode("utf-8", errors="ignore")) > _max_xml_bytes():
        logger.error("Skipping report larger than MAX_XML_MB.")
        return

    try:
        data = xmltodict.parse(xml_content, disable_entities=True)
    except Exception as exc:
        logger.error("Failed to parse XML (%s).", type(exc).__name__)
        return

    feedback = _as_dict(_as_dict(data).get("feedback"))
    if not feedback:
        logger.warning("Payload is not a DMARC feedback document; skipping.")
        return

    metadata = _as_dict(feedback.get("report_metadata"))
    policy = _as_dict(feedback.get("policy_published"))

    report_id = truncate(metadata.get("report_id"), 255)
    if not report_id:
        logger.warning("DMARC report without report_id; skipping.")
        return

    org_name = truncate(metadata.get("org_name"), 255, default="unknown")
    email = truncate(metadata.get("email"), 255)
    domain = truncate(policy.get("domain"), 255, default="unknown")

    date_range = _as_dict(metadata.get("date_range"))
    begin_date = safe_timestamp(date_range.get("begin"))
    end_date = safe_timestamp(date_range.get("end"))
    if begin_date is None or end_date is None:
        logger.warning("Report %r has an invalid date_range; skipping.", report_id)
        return

    report = Report(
        org_name=org_name,
        email=email,
        report_id=report_id,
        begin_date=begin_date,
        end_date=end_date,
        domain=domain,
        adkim=truncate(policy.get("adkim"), 10),
        aspf=truncate(policy.get("aspf"), 10),
        p=truncate(policy.get("p"), 20),
        sp=truncate(policy.get("sp"), 20),
        pct=safe_int(policy.get("pct", 100), default=100, minimum=0, maximum=100),
    )

    session = sessionmaker(bind=get_engine())()
    try:
        existing = (
            session.query(Report)
            .filter_by(report_id=report_id, org_name=org_name, domain=domain)
            .first()
        )
        if existing:
            logger.info(
                "Report %r from %r already imported. Skipping.", report_id, org_name
            )
            return

        session.add(report)
        session.flush()  # assign report.id for the foreign keys

        for entry in _as_list(feedback.get("record")):
            entry = _as_dict(entry)
            row = _as_dict(entry.get("row"))
            policy_evaluated = _as_dict(row.get("policy_evaluated"))
            identifiers = _as_dict(entry.get("identifiers"))
            source_ip = truncate(row.get("source_ip"), 50)

            record = Record(
                report_id=report.id,
                source_ip=source_ip,
                host_name=_reverse_dns(source_ip),
                count=safe_int(
                    row.get("count"), default=0, minimum=0, maximum=_MAX_INT
                ),
                disposition=truncate(policy_evaluated.get("disposition"), 20),
                dkim=truncate(policy_evaluated.get("dkim"), 20),
                spf=truncate(policy_evaluated.get("spf"), 20),
                reason=_reason_string(policy_evaluated),
                header_from=truncate(identifiers.get("header_from"), 255),
            )
            session.add(record)
            session.flush()

            auth_results = _as_dict(entry.get("auth_results"))
            for dkim in _as_list(auth_results.get("dkim")):
                if not isinstance(dkim, dict):
                    continue
                session.add(
                    AuthResult(
                        record_id=record.id,
                        type="dkim",
                        domain=truncate(dkim.get("domain"), 255),
                        result=truncate(dkim.get("result"), 20),
                        selector=truncate(dkim.get("selector"), 255),
                    )
                )

            for spf in _as_list(auth_results.get("spf")):
                if not isinstance(spf, dict):
                    continue
                session.add(
                    AuthResult(
                        record_id=record.id,
                        type="spf",
                        domain=truncate(spf.get("domain"), 255),
                        result=truncate(spf.get("result"), 20),
                        selector=None,
                    )
                )

        session.commit()
        logger.info("Successfully processed report %r from %r.", report_id, org_name)

    except Exception as exc:
        session.rollback()
        logger.error(
            "Failed to import report %r (%s).", report_id, type(exc).__name__
        )
    finally:
        session.close()
