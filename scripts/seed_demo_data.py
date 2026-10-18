"""Seed DMARClyzer with deterministic, synthetic demo data.

The data is only intended for local development, documentation screenshots and
UI experiments. It deliberately uses reserved ``.example`` domains and RFC 5737
documentation IP ranges so that no real sender or customer data is involved.

Usage::

    DB_HOST=127.0.0.1 DB_PORT=3307 DB_NAME=dmarc \
    DB_USER=dmarcuser DB_PASSWORD=dmarcpass \
    python scripts/seed_demo_data.py --reset --days 14 --seed 42
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
sys.path.insert(0, str(APP_DIR))

from models import AuthResult, Record, Report, get_engine, init_db  # noqa: E402

DOMAINS = [
    "acme.example",
    "mail.acme.example",
    "shop.acme.example",
    "acme-labs.example",
]

ORGS = [
    "google.com",
    "outlook.com",
    "yahoo.com",
    "comcast.net",
]

# Reserved documentation ranges (RFC 5737) and .example hostnames only.
COMPLIANT_SENDERS = [
    {"ip": f"192.0.2.{i}", "host": f"mx-{i:02d}.acme.example", "selector": "s1"}
    for i in range(10, 34)
]

FORWARDED_SENDERS = [
    {"ip": f"198.51.100.{i}", "host": f"lists-{i - 19:02d}.example.org", "selector": "list"}
    for i in range(20, 27)
]

DKIM_ISSUE_SENDERS = [
    {"ip": f"203.0.113.{i}", "host": f"app-{i - 39:02d}.example.net", "selector": "default"}
    for i in range(40, 45)
]

FAILING_SENDERS = [
    {"ip": f"203.0.113.{i}", "host": f"unknown-{i - 59:02d}.example", "selector": "mail"}
    for i in range(60, 68)
]

# Failing-mail volume varies by domain so the dashboard shows both healthy
# domains and one domain with a visibly lower compliance rate.
FAILING_VOLUME = {
    "acme.example": (5, 40),
    "mail.acme.example": (20, 90),
    "shop.acme.example": (60, 220),
    "acme-labs.example": (180, 700),
}

DOMAIN_SEVERITY = {
    "acme.example": "healthy",
    "mail.acme.example": "good",
    "shop.acme.example": "watch",
    "acme-labs.example": "poor",
}


def _policy_for(domain: str, age_days: int) -> str:
    """Return the published policy for a domain ``age_days`` ago.

    Newer reports (smaller age) use stronger policies, which produces a
    readable policy-adoption timeline in the default 7-day dashboard window.
    """
    if domain == "acme.example":
        if age_days <= 2:
            return "reject"
        if age_days <= 7:
            return "quarantine"
        return "none"
    if domain == "mail.acme.example":
        if age_days <= 3:
            return "reject"
        if age_days <= 9:
            return "quarantine"
        return "none"
    if domain == "shop.acme.example":
        if age_days <= 4:
            return "quarantine"
        return "none"
    # acme-labs.example only tightened its policy recently.
    if age_days <= 5:
        return "reject"
    if age_days <= 11:
        return "quarantine"
    return "none"


def _compliant_count(rng: random.Random) -> int:
    return rng.randint(80, 650)


def _count_for(category: str, domain: str, rng: random.Random) -> int:
    if category == "Compliant":
        return _compliant_count(rng)
    if category == "Forwarded":
        return rng.randint(25, 150)
    if category == "DKIM Issue":
        low, high = {
            "healthy": (10, 35),
            "good": (15, 60),
            "watch": (25, 110),
            "poor": (60, 260),
        }[DOMAIN_SEVERITY[domain]]
        return rng.randint(low, high)
    low, high = FAILING_VOLUME[domain]
    return rng.randint(low, high)


def _pick_sender(domain: str, category: str, rng: random.Random) -> dict:
    sender: dict
    if category == "Compliant":
        sender = dict(rng.choice(COMPLIANT_SENDERS))
        sender.update(
            dkim="pass",
            spf="pass",
            disposition="none",
            reason=None,
            dkim_domain=domain,
            spf_domain=domain,
        )
    elif category == "Forwarded":
        sender = dict(rng.choice(FORWARDED_SENDERS))
        sender.update(
            dkim="pass",
            spf="fail",
            disposition="quarantine" if rng.random() > 0.35 else "none",
            reason="forwarded",
            dkim_domain=domain,
            spf_domain="bounce.example.net",
        )
    elif category == "DKIM Issue":
        sender = dict(rng.choice(DKIM_ISSUE_SENDERS))
        sender.update(
            dkim="fail",
            spf="pass",
            disposition="quarantine",
            reason="local_policy",
            dkim_domain="mailer.example.net",
            spf_domain=domain,
        )
    else:
        sender = dict(rng.choice(FAILING_SENDERS))
        sender.update(
            dkim="fail",
            spf="fail",
            disposition="reject" if rng.random() > 0.25 else "quarantine",
            reason="local_policy",
            dkim_domain="spam.example",
            spf_domain="spam.example",
        )
    sender["category"] = category
    return sender


def _clear(session) -> None:
    """Remove all rows, leaf-first, so the demo can be regenerated in place."""
    session.query(AuthResult).delete(synchronize_session=False)
    session.query(Record).delete(synchronize_session=False)
    session.query(Report).delete(synchronize_session=False)
    session.commit()


def seed(
    seed_value: int = 42, days: int = 14, reset: bool = False
) -> dict[str, int]:
    """Insert the demo dataset and return row counts.

    Existing rows are only deleted when *reset* is true; otherwise a populated
    database is left untouched so this script cannot silently wipe data.
    """
    rng = random.Random(seed_value)
    engine = get_engine()
    init_db()

    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine)
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    counts = {"reports": 0, "records": 0, "auth_results": 0}

    with Session() as session:
        if reset:
            _clear(session)
        elif session.query(Report.id).first() is not None:
            raise RuntimeError(
                "The target database already contains reports. "
                "Pass --reset to replace them."
            )

        for age in range(days):
            report_day = today - timedelta(days=age)
            for domain in DOMAINS:
                policy = _policy_for(domain, age)
                for org in ORGS:
                    org_slug = org.split(".")[0]
                    # Reporters do not always send exactly one report per day.
                    # Splitting a day's volume across one or two reports keeps
                    # daily totals stable while giving the policy timeline
                    # realistic variation between days.
                    slots = 1 + int(rng.random() < 0.45)
                    for slot in range(slots):
                        suffix = f"-r{slot + 1}" if slot else ""
                        report = Report(
                            org_name=org,
                            email=f"dmarc-reports@{org}",
                            report_id=(
                                f"demo-{org_slug}-{domain}-"
                                f"{report_day:%Y%m%d}{suffix}"
                            ),
                            begin_date=report_day,
                            end_date=report_day + timedelta(days=1),
                            domain=domain,
                            adkim="r",
                            aspf="r",
                            p=policy,
                            sp=policy,
                            pct=100,
                        )
                        session.add(report)
                        session.flush()
                        counts["reports"] += 1

                        senders = [
                            _pick_sender(domain, "Compliant", rng)
                            for _ in range(rng.randint(3, 5))
                        ]
                        senders.append(_pick_sender(domain, "Forwarded", rng))
                        senders.append(_pick_sender(domain, "DKIM Issue", rng))
                        senders.append(_pick_sender(domain, "Failing", rng))
                        if DOMAIN_SEVERITY[domain] == "poor":
                            # Give the unhealthy domain a couple of extra sources.
                            senders.append(_pick_sender(domain, "Failing", rng))
                            senders.append(_pick_sender(domain, "DKIM Issue", rng))

                        for sender in senders:
                            message_count = _count_for(
                                sender["category"], domain, rng
                            )
                            message_count = max(
                                1, round(message_count / slots)
                            )
                            record = Record(
                                report_id=report.id,
                                source_ip=sender["ip"],
                                host_name=sender["host"],
                                count=message_count,
                                disposition=sender["disposition"],
                                dkim=sender["dkim"],
                                spf=sender["spf"],
                                reason=sender["reason"],
                                header_from=domain,
                            )
                            session.add(record)
                            session.flush()
                            counts["records"] += 1

                            session.add(
                                AuthResult(
                                    record_id=record.id,
                                    type="dkim",
                                    domain=sender["dkim_domain"],
                                    result=sender["dkim"],
                                    selector=sender["selector"],
                                )
                            )
                            session.add(
                                AuthResult(
                                    record_id=record.id,
                                    type="spf",
                                    domain=sender["spf_domain"],
                                    result=sender["spf"],
                                    selector=None,
                                )
                            )
                            counts["auth_results"] += 2

        session.commit()

    return counts


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("DB_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=os.environ.get("DB_PORT", "3306"))
    parser.add_argument("--name", default=os.environ.get("DB_NAME", "dmarc"))
    parser.add_argument("--user", default=os.environ.get("DB_USER", "dmarcuser"))
    parser.add_argument(
        "--password", default=os.environ.get("DB_PASSWORD", "dmarcpass")
    )
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing rows before inserting (the demo DB is disposable).",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.days < 1:
        raise SystemExit("--days must be at least 1")

    os.environ["DB_HOST"] = args.host
    os.environ["DB_PORT"] = str(args.port)
    os.environ["DB_NAME"] = args.name
    os.environ["DB_USER"] = args.user
    os.environ["DB_PASSWORD"] = args.password

    counts = seed(seed_value=args.seed, days=args.days, reset=args.reset)
    print(
        "Seeded {reports} reports, {records} records and "
        "{auth_results} auth results.".format(**counts)
    )
    print(
        f"Domains: {', '.join(DOMAINS)} | Reporter orgs: {', '.join(ORGS)} "
        f"| Days: {args.days} | Seed: {args.seed}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

