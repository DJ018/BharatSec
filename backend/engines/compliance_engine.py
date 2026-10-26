"""CERT-In and DPDP compliance checklist, tracked team-wide.

The checklist itself lives in code (ITEMS); the database only stores which items the team has marked
done, with an optional note. This is a planning aid, not legal advice; each item links to its source.
"""
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import database
from config import DATA_DIR

DB_PATH = Path(os.getenv("COMPLIANCE_DATABASE_PATH", str(DATA_DIR / "compliance.db")))

CERT_IN = "https://www.cert-in.org.in/Directions70B.jsp"
MEITY = "https://www.meity.gov.in"

FRAMEWORKS = [
    {"id": "cert-in", "name": "CERT-In Directions 2022", "summary": "Incident reporting and logging duties under Section 70B(6) of the IT Act."},
    {"id": "dpdp", "name": "DPDP Act 2023 and Rules 2025", "summary": "Duties of anyone processing personal data of people in India."},
    {"id": "basics", "name": "Security basics", "summary": "Controls that make the two frameworks above achievable. BharatSec checks several for you."},
]

ITEMS: List[Dict[str, str]] = [
    # CERT-In
    {"id": "certin-poc", "framework": "cert-in", "title": "Name a Point of Contact for CERT-In",
     "why": "CERT-In expects every covered organisation to designate a Point of Contact to interface with it.",
     "how": "Pick a person (and a backup), and keep their name, email and phone on record.", "source": CERT_IN},
    {"id": "certin-6h", "framework": "cert-in", "title": "Be able to report incidents within 6 hours",
     "why": "Listed incidents (data breaches, ransomware, website defacement, unauthorised access and more) must be reported within 6 hours of noticing them.",
     "how": "Write a one-page runbook: who decides, who emails incident@cert-in.org.in, and what the first report contains.", "source": CERT_IN},
    {"id": "certin-logs", "framework": "cert-in", "title": "Keep logs of all ICT systems for 180 days, in India",
     "why": "Logs must be enabled for all ICT systems and kept for a rolling 180 days within Indian jurisdiction.",
     "how": "Turn on logs for servers, firewalls, cloud accounts (e.g. AWS CloudTrail) and SaaS admin consoles, with 180-day retention.", "source": CERT_IN},
    {"id": "certin-ntp", "framework": "cert-in", "title": "Sync system clocks to NIC or NPL time servers",
     "why": "Accurate timestamps are needed to correlate events; CERT-In names NIC and NPL NTP servers.",
     "how": "Point servers and network devices at NIC (samay1.nic.in) or NPL (time.nplindia.org) NTP, or sources traceable to them.", "source": CERT_IN},
    {"id": "certin-kyc", "framework": "cert-in", "title": "If you provide VPN, cloud, VPS or hosting: keep subscriber records 5 years",
     "why": "Data centres, VPS, cloud and VPN providers must keep validated subscriber details for 5 years after cancellation.",
     "how": "Mark as done if this does not apply to your business.", "source": CERT_IN},
    # DPDP
    {"id": "dpdp-notice", "framework": "dpdp", "title": "Publish a clear privacy notice",
     "why": "People must be told, in clear language, what personal data you collect and why before or when you ask for consent.",
     "how": "List each kind of data, its purpose, how to withdraw consent and how to complain.", "source": MEITY},
    {"id": "dpdp-consent", "framework": "dpdp", "title": "Record consent and make withdrawing it as easy as giving it",
     "why": "Processing needs free, specific, informed consent (or a listed legitimate use), and consent can be withdrawn.",
     "how": "Keep a record of who agreed to what and when; add a simple way to withdraw.", "source": MEITY},
    {"id": "dpdp-grievance", "framework": "dpdp", "title": "Publish a contact for privacy requests and grievances",
     "why": "People can ask for access, correction and erasure, and must have a way to raise grievances.",
     "how": "Name a person and an email address on your website, and answer requests promptly.", "source": MEITY},
    {"id": "dpdp-safeguards", "framework": "dpdp", "title": "Put reasonable security safeguards in place",
     "why": "Failing to take reasonable security safeguards can attract penalties of up to ₹250 crore.",
     "how": "Encrypt personal data, restrict and log access, keep backups, and keep access logs for at least a year.", "source": MEITY},
    {"id": "dpdp-breach", "framework": "dpdp", "title": "Have a breach notification plan",
     "why": "Affected people and the Data Protection Board must be told of a personal data breach without delay, with a detailed report to the Board within 72 hours.",
     "how": "Prepare notice templates and decide who sends them; combine with your CERT-In runbook.", "source": MEITY},
    {"id": "dpdp-retention", "framework": "dpdp", "title": "Delete personal data when it is no longer needed",
     "why": "Data must be erased when the purpose is served or consent is withdrawn, unless the law requires keeping it.",
     "how": "Set retention periods per kind of data and a routine to delete or anonymise it.", "source": MEITY},
    {"id": "dpdp-vendors", "framework": "dpdp", "title": "Have contracts with vendors who process data for you",
     "why": "You stay responsible for personal data your processors (hosting, email, CRM, payroll) handle on your behalf.",
     "how": "List your processors and make sure each has a contract covering security and deletion.", "source": MEITY},
    {"id": "dpdp-children", "framework": "dpdp", "title": "Get verifiable parental consent for under-18s",
     "why": "Children's data needs verifiable parental consent, and tracking or targeted ads aimed at children are not allowed.",
     "how": "Mark as done if your service is not used by anyone under 18.", "source": MEITY},
    # Basics
    {"id": "basics-email", "framework": "basics", "title": "Email authentication: SPF, DKIM and DMARC",
     "why": "Stops attackers sending email as your domain, the most common route into phishing and payment fraud.",
     "how": "Run a BharatSec scan; it checks all three and gives the exact records to add.", "source": "/#scan"},
    {"id": "basics-https", "framework": "basics", "title": "HTTPS everywhere with HSTS and modern TLS",
     "why": "Protects data in transit; outdated TLS and missing HSTS are common scan findings.",
     "how": "Run a BharatSec scan and fix the SSL/TLS and header findings it lists.", "source": "/#scan"},
    {"id": "basics-mfa", "framework": "basics", "title": "Multi-factor sign-in on email, cloud, code and registrar accounts",
     "why": "Most account takeovers are stopped by a second factor.",
     "how": "Prefer passkeys or authenticator apps over SMS for admin accounts.", "source": ""},
    {"id": "basics-backups", "framework": "basics", "title": "Tested backups with an offline or immutable copy",
     "why": "Backups are what turns ransomware from a disaster into an inconvenience.",
     "how": "Back up critical data, keep one copy offline or immutable, and test a restore every quarter.", "source": ""},
    {"id": "basics-inventory", "framework": "basics", "title": "Know your internet-facing assets",
     "why": "You cannot protect domains, subdomains and cloud accounts you have forgotten about.",
     "how": "Use BharatSec's subdomain discovery and SOC asset list as your inventory.", "source": "/soc"},
]
ITEM_IDS = {item["id"] for item in ITEMS}


@contextmanager
def _connect() -> Iterator[Any]:
    with database.transaction(DB_PATH, timeout=10) as connection:
        yield connection


def init_db() -> None:
    with _connect() as connection:
        database.schema_lock(connection, "compliance")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS compliance_status (
                item_id TEXT PRIMARY KEY,
                done INTEGER NOT NULL DEFAULT 0,
                note TEXT NOT NULL DEFAULT '',
                updated_by TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            );
            """
        )


def checklist() -> Dict[str, Any]:
    with _connect() as connection:
        rows = {row["item_id"]: dict(row) for row in connection.execute("SELECT * FROM compliance_status").fetchall()}
    items = []
    for item in ITEMS:
        saved = rows.get(item["id"], {})
        items.append({**item, "done": bool(saved.get("done")), "note": saved.get("note", ""),
                      "updated_by": saved.get("updated_by", ""), "updated_at": saved.get("updated_at", "")})
    frameworks = []
    for framework in FRAMEWORKS:
        members = [item for item in items if item["framework"] == framework["id"]]
        done = sum(1 for item in members if item["done"])
        frameworks.append({**framework, "done": done, "total": len(members)})
    total_done = sum(1 for item in items if item["done"])
    return {"frameworks": frameworks, "items": items, "done": total_done, "total": len(items)}


def update(item_id: str, done: bool, note: Optional[str], user_name: str) -> Dict[str, Any]:
    if item_id not in ITEM_IDS:
        raise KeyError(item_id)
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as connection:
        current = connection.execute("SELECT note FROM compliance_status WHERE item_id = ?", (item_id,)).fetchone()
        keep_note = note if note is not None else (current["note"] if current else "")
        connection.execute(
            """INSERT INTO compliance_status (item_id, done, note, updated_by, updated_at) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(item_id) DO UPDATE SET done = excluded.done, note = excluded.note,
                   updated_by = excluded.updated_by, updated_at = excluded.updated_at""",
            (item_id, 1 if done else 0, keep_note[:500], user_name[:80], now),
        )
    return next(item for item in checklist()["items"] if item["id"] == item_id)
