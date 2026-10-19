"""
BharatSec — Pydantic models for scan data
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from enum import Enum
from datetime import datetime


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETE  = "complete"
    ERROR     = "error"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ── Request models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str = Field(..., description="Target domain to scan (e.g. example.com)")
    include_ports: bool = Field(False, description="Include port scanning (requires Nmap)")
    authorized: bool = Field(False, description="Confirm you are authorized to scan this target")


class CopilotTurn(BaseModel):
    role: Literal["user", "assistant"]
    # Assistant turns can be long-form answers, so history turns allow more than a new message.
    content: str = Field(..., min_length=1, max_length=12000)


class CopilotRequest(BaseModel):
    scan_id: str = Field(..., min_length=1, max_length=100)
    message: str = Field(..., min_length=1, max_length=2000)
    history: List[CopilotTurn] = Field(default_factory=list, max_length=12)


class AIAnalyzeRequest(BaseModel):
    finding_id: str
    finding_type: str
    title: str
    description: str
    severity: str
    context: Dict[str, Any] = {}


# ── DNS models ────────────────────────────────────────────────────────────────

class DNSRecord(BaseModel):
    type: str
    value: str
    ttl: Optional[int] = None


class DNSResults(BaseModel):
    a_records:     List[str] = []
    mx_records:    List[str] = []
    txt_records:   List[str] = []
    ns_records:    List[str] = []
    cname_records: List[str] = []
    has_spf:       bool = False
    has_dmarc:     bool = False
    has_dkim:      bool = False
    wildcard_dns:  bool = False   # any subdomain resolves (catch-all DNS record)


# ── SSL models ────────────────────────────────────────────────────────────────

class SSLInfo(BaseModel):
    valid:          bool = False
    issuer:         str = ""
    subject:        str = ""
    expires:        Optional[str] = None
    days_remaining: int = 0
    protocol:       str = ""
    grade:          str = "N/A"
    vulnerabilities: List[str] = []


# ── HTTP / Web models ─────────────────────────────────────────────────────────

class HeadersResult(BaseModel):
    present:   List[str] = []
    missing:   List[str] = []
    all_headers: Dict[str, str] = {}


class WebInfo(BaseModel):
    status_code:     int = 0
    server:          str = ""
    technologies:    List[str] = []
    cms:             str = ""
    https_redirect:  bool = False
    headers:         HeadersResult = HeadersResult()
    response_time_ms: float = 0


# ── Subdomain models ──────────────────────────────────────────────────────────

class SubdomainResult(BaseModel):
    subdomain:   str
    ip:          Optional[str] = None
    status_code: Optional[int] = None
    alive:       bool = False
    open_ports:  List[int] = []


# ── WHOIS models ──────────────────────────────────────────────────────────────

class WHOISInfo(BaseModel):
    registrar:          str = ""
    creation_date:      str = ""
    expiration_date:    str = ""
    days_until_expiry:  int = 0
    name_servers:       List[str] = []
    privacy_protected:  bool = False


# ── Finding model ─────────────────────────────────────────────────────────────

class Finding(BaseModel):
    id:          str
    category:    str
    title:       str
    description: str
    severity:    SeverityLevel
    evidence:    str = ""
    ai_analysis: str = ""
    fix:         str = ""
    effort:      str = "Medium"  # Low / Medium / High
    impact:      str = "Medium"


# ── Risk score model ──────────────────────────────────────────────────────────

class RiskScore(BaseModel):
    overall:          int = 0
    attack_surface:   int = 0
    web_security:     int = 0
    identity_exposure: int = 0
    configuration:    int = 0
    credential_risk:  int = 0
    level:            str = "UNKNOWN"  # SECURE / LOW / MEDIUM / HIGH / CRITICAL
    critical_count:   int = 0
    high_count:       int = 0
    medium_count:     int = 0
    low_count:        int = 0


# ── Full scan result model ────────────────────────────────────────────────────

class ScanResult(BaseModel):
    scan_id:    str
    domain:     str
    status:     ScanStatus = ScanStatus.PENDING
    progress:   int = 0
    started_at: str = ""
    completed_at: str = ""

    # Sub-results
    dns:         DNSResults     = DNSResults()
    ssl:         SSLInfo        = SSLInfo()
    web:         WebInfo        = WebInfo()
    subdomains:  List[SubdomainResult] = []
    whois:       WHOISInfo      = WHOISInfo()
    findings:    List[Finding]  = []
    score:       RiskScore      = RiskScore()

    # AI summary
    ai_summary:      str = ""
    top_priorities:  List[Finding] = []
    attack_paths:    List[Dict[str, Any]] = []
