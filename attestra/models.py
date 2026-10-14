"""Core data model. See docs/ARCHITECTURE.md, section "Common finding schema"."""

from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from attestra.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


ENGAGEMENT_TYPES = ("va", "pt", "vapt", "retest", "continuous")
FRAMEWORKS = ("pci_dss_4", "iso_27001_2022", "soc2")
SEVERITIES = ("critical", "high", "medium", "low", "info")
ENVIRONMENTS = ("production", "staging", "uat", "dev", "demo")

# kind -> label shown in the UI
ASSET_KINDS = {
    "web_app": "Web application (URL)",
    "api": "API (base URL)",
    "host": "Host / IP / CIDR",
    "repo": "Source repository or path",
    "image": "Container image",
    "cloud_account": "Cloud account",
    "mobile_app": "Mobile app",
}

# Test types a client can authorize per target: label, OWASP / standard reference,
# and which result formats Attestra imports as evidence for it.
TEST_TYPES = {
    "web_dast": {"label": "Web app scan (DAST)", "standard": "OWASP Top 10", "imports": ["zap", "nuclei"]},
    "api_dast": {"label": "API security scan", "standard": "OWASP API Security Top 10", "imports": ["zap", "nuclei"]},
    "manual_pt": {"label": "Manual penetration test", "standard": "OWASP WSTG / ASVS", "imports": ["evidence"]},
    "tls": {"label": "TLS / SSL configuration", "standard": "PCI DSS 4.2.1", "imports": ["nuclei"]},
    "network_va": {"label": "Network / host vulnerability assessment", "standard": "CVE / CIS", "imports": ["nuclei", "sarif"]},
    "sca_container": {"label": "Dependencies and container images (SCA)", "standard": "OWASP A06", "imports": ["trivy"]},
    "sast": {"label": "Source code and secrets (SAST)", "standard": "OWASP ASVS", "imports": ["sarif"]},
    "iac_cloud": {"label": "Cloud / IaC configuration", "standard": "CIS Benchmarks", "imports": ["trivy", "sarif"]},
    "mobile": {"label": "Mobile app assessment", "standard": "OWASP MASVS", "imports": ["sarif"]},
}

# Sensible defaults when a target is added without explicit test types.
DEFAULT_TESTS = {
    "web_app": ["web_dast", "tls", "manual_pt"],
    "api": ["api_dast", "tls", "manual_pt"],
    "host": ["network_va", "tls"],
    "repo": ["sast", "sca_container"],
    "image": ["sca_container"],
    "cloud_account": ["iac_cloud"],
    "mobile_app": ["mobile", "manual_pt"],
}

# Finding lifecycle. Every transition is written to the audit log.
TRANSITIONS: dict[str, set[str]] = {
    "new": {"triaged", "false_positive"},
    "triaged": {"validated", "false_positive", "risk_accepted"},
    "validated": {"fixed", "risk_accepted"},
    "risk_accepted": {"validated"},
    "false_positive": {"triaged"},
    "fixed": {"retest_passed", "validated"},
    "retest_passed": set(),
}
OPEN_STATUSES = ("new", "triaged", "validated")


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    industry: Mapped[str] = mapped_column(String(100), default="")
    contact_name: Mapped[str] = mapped_column(String(200), default="")
    contact_email: Mapped[str] = mapped_column(String(200), default="")


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    type: Mapped[str] = mapped_column(String(20))
    frameworks: Mapped[list] = mapped_column(JSON, default=list)
    window_start: Mapped[date | None] = mapped_column(Date)
    window_end: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tenant: Mapped[Tenant] = relationship()
    assets: Mapped[list["Asset"]] = relationship(back_populates="engagement")
    authorizations: Mapped[list["Authorization"]] = relationship(back_populates="engagement")
    findings: Mapped[list["Finding"]] = relationship(back_populates="engagement")


class Authorization(Base):
    """Signed client authorization and rules of engagement (ISO A.8.34, PCI 11.4.1)."""

    __tablename__ = "authorizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    document_name: Mapped[str] = mapped_column(String(300))
    document_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    signer: Mapped[str] = mapped_column(String(200))
    rules_of_engagement: Mapped[str] = mapped_column(Text, default="")
    signed_on: Mapped[date] = mapped_column(Date)
    expires_on: Mapped[date] = mapped_column(Date)
    # Environments the client approved for testing. Empty (records made before v0.1.1) means all.
    environments: Mapped[list | None] = mapped_column(JSON, default=list)

    engagement: Mapped[Engagement] = relationship(back_populates="authorizations")

    def is_valid(self, on: date | None = None) -> bool:
        on = on or date.today()
        return self.signed_on <= on <= self.expires_on

    def covers(self, environment: str) -> bool:
        return not self.environments or environment in self.environments


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    kind: Mapped[str] = mapped_column(String(30))  # see ASSET_KINDS
    identifier: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(200), default="")
    environment: Mapped[str] = mapped_column(String(20), default="production")  # see ENVIRONMENTS
    test_types: Mapped[list | None] = mapped_column(JSON, default=list)  # keys of TEST_TYPES
    intrusive_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1 (low) .. 5 (crown jewel)
    exposure: Mapped[str] = mapped_column(String(20), default="internal")  # internet | internal
    in_cde: Mapped[bool] = mapped_column(Boolean, default=False)  # PCI cardholder data environment
    owner: Mapped[str] = mapped_column(String(200), default="")

    engagement: Mapped[Engagement] = relationship(back_populates="assets")


class ImportRun(Base):
    """One imported scanner result file. Raw bytes are kept and hashed for the evidence chain."""

    __tablename__ = "import_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    tool: Mapped[str] = mapped_column(String(50))
    filename: Mapped[str] = mapped_column(String(300))
    raw_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    imported_by: Mapped[str] = mapped_column(String(200))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    new_findings: Mapped[int] = mapped_column(Integer, default=0)
    updated_findings: Mapped[int] = mapped_column(Integer, default=0)
    unmatched_findings: Mapped[int] = mapped_column(Integer, default=0)  # no in-scope target matched


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("engagement_id", "fingerprint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    tools: Mapped[list] = mapped_column(JSON, default=list)
    rule_ids: Mapped[list] = mapped_column(JSON, default=list)
    cwe: Mapped[int | None] = mapped_column(Integer)
    cves: Mapped[list] = mapped_column(JSON, default=list)
    location: Mapped[str] = mapped_column(String(1000), default="")
    severity: Mapped[str] = mapped_column(String(10))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str] = mapped_column(String(200), default="")
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(20), default="new")
    sla_due: Mapped[date | None] = mapped_column(Date)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    validated_by: Mapped[str] = mapped_column(String(200), default="")
    ticket_ref: Mapped[str] = mapped_column(String(200), default="")

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    asset: Mapped[Asset | None] = relationship()
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="finding")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    kind: Mapped[str] = mapped_column(String(30))  # screenshot | http_pair | log | file | note
    filename: Mapped[str] = mapped_column(String(300))
    path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, default="")
    captured_by: Mapped[str] = mapped_column(String(200))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class ControlAssessment(Base):
    """A person's confirmed status for one framework control. The engine only proposes."""

    __tablename__ = "control_assessments"
    __table_args__ = (UniqueConstraint("engagement_id", "framework", "control_ref"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    framework: Mapped[str] = mapped_column(String(30))
    control_ref: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20))  # met | partial | not_met | not_applicable
    assessor: Mapped[str] = mapped_column(String(200))
    rationale: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    kind: Mapped[str] = mapped_column(String(30))  # technical | executive | compliance
    framework: Mapped[str] = mapped_column(String(30), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft | signed
    generated_by: Mapped[str] = mapped_column(String(200))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_by: Mapped[str] = mapped_column(String(200), default="")
    signature: Mapped[str] = mapped_column(String(200), default="")
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    """Append-only, hash-chained audit log."""

    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    entity: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
