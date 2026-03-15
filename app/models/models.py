from sqlmodel import SQLModel, Field, Column, JSON
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ─── Target ──────────────────────────────────────────────────────────────────

class Target(SQLModel, table=True):
    """Root domain / bug bounty program."""
    id: Optional[int] = Field(default=None, primary_key=True)
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    domain: str = Field(index=True, unique=True)
    program_name: Optional[str] = None
    in_scope: Optional[list] = Field(default=None, sa_column=Column(JSON))
    out_of_scope: Optional[list] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Scan ─────────────────────────────────────────────────────────────────────

class Scan(SQLModel, table=True):
    """A single recon scan run against a target."""
    id: Optional[int] = Field(default=None, primary_key=True)
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    target_id: int = Field(foreign_key="target.id")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    config: Optional[dict] = Field(default=None, sa_column=Column(JSON))  # modules to run, rate limits etc.
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Subdomain ───────────────────────────────────────────────────────────────

class Subdomain(SQLModel, table=True):
    """Discovered subdomain with enrichment metadata."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    scan_id: int = Field(foreign_key="scan.id")
    fqdn: str = Field(index=True)
    ip_address: Optional[str] = None
    real_ip: Optional[str] = None        # Origin IP behind CDN
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    cdn_detected: bool = False
    waf_detected: Optional[str] = None
    technologies: Optional[list] = Field(default=None, sa_column=Column(JSON))
    is_alive: bool = False
    source: Optional[str] = None         # "subfinder", "bruteforce", "permutation" etc.
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Asset ───────────────────────────────────────────────────────────────────

class Asset(SQLModel, table=True):
    """JS file, endpoint, or other discovered asset."""
    id: Optional[int] = Field(default=None, primary_key=True)
    subdomain_id: int = Field(foreign_key="subdomain.id")
    scan_id: int = Field(foreign_key="scan.id")
    url: str = Field(index=True)
    asset_type: str  # "js", "endpoint", "graphql", "websocket", "form", "upload"
    method: Optional[str] = None
    params: Optional[list] = Field(default=None, sa_column=Column(JSON))
    status_code: Optional[int] = None
    content_hash: Optional[str] = None  # for diff monitoring
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Finding ─────────────────────────────────────────────────────────────────

class Finding(SQLModel, table=True):
    """A potential vulnerability or secret."""
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id")
    subdomain_id: Optional[int] = Field(default=None, foreign_key="subdomain.id")
    finding_type: str   # "secret", "xss", "ssrf", "403_bypass", "idor" etc.
    severity: Severity = Field(default=Severity.INFO)
    title: str
    description: str
    evidence: Optional[str] = None
    risk_score: Optional[float] = None      # 0.0 – 10.0
    confidence: Optional[float] = None     # 0.0 – 1.0
    suggested_next_step: Optional[str] = None
    is_duplicate: bool = False
    is_validated: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
