"""Core data model. See docs/ARCHITECTURE.md, section "Common finding schema"."""
# @lat: [[findings#Data model]]
# @lat: [[authorization#Authorization record]]

from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from attestra.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


ENGAGEMENT_TYPES = ("va", "pt", "vapt", "retest", "continuous")
# Core frameworks; v2.1 packs in compliance/data/packs add more at load time.
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
    "tls": {"label": "TLS / SSL configuration", "standard": "PCI DSS 4.2.1", "imports": ["nuclei", "testssl"]},
    "network_va": {"label": "Network / host vulnerability assessment", "standard": "CVE / CIS", "imports": ["nuclei", "sarif", "naabu"]},
    "sca_container": {"label": "Dependencies and container images (SCA)", "standard": "OWASP A06", "imports": ["trivy"]},
    "sast": {"label": "Source code and secrets (SAST)", "standard": "OWASP ASVS", "imports": ["sarif", "gitleaks"]},
    "iac_cloud": {"label": "Cloud / IaC configuration", "standard": "CIS Benchmarks", "imports": ["trivy", "sarif", "checkov", "prowler", "kube_bench"]},
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
    data_region: Mapped[str] = mapped_column(String(50), default="default")
    plan: Mapped[str] = mapped_column(String(50), default="standard")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"))
    username: Mapped[str] = mapped_column(String(100), unique=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(30), default="tester")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tenant: Mapped[Tenant | None] = relationship()


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship()


class TenantMembership(Base):
    __tablename__ = "tenant_memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    role: Mapped[str] = mapped_column(String(30), default="")

    user: Mapped[User] = relationship()
    tenant: Mapped[Tenant] = relationship()


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
    assets: Mapped[list[Asset]] = relationship(back_populates="engagement")
    authorizations: Mapped[list[Authorization]] = relationship(back_populates="engagement")
    findings: Mapped[list[Finding]] = relationship(back_populates="engagement")
    asv_scans: Mapped[list[AsvScan]] = relationship(back_populates="engagement")
    segmentation_tests: Mapped[list[SegmentationTest]] = relationship(back_populates="engagement")
    scan_schedules: Mapped[list[ScanSchedule]] = relationship(back_populates="engagement")
    nonconformities: Mapped[list[Nonconformity]] = relationship(back_populates="engagement")
    risk_acceptances: Mapped[list[RiskAcceptance]] = relationship(back_populates="engagement")
    control_assessments: Mapped[list[ControlAssessment]] = relationship()
    import_runs: Mapped[list[ImportRun]] = relationship()


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
    ownership_token: Mapped[str] = mapped_column(String(64), default="")
    ownership_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    engagement: Mapped[Engagement] = relationship(back_populates="assets")


class ScopeRule(Base):
    """Explicit allow/deny pattern for runner targets (deny beats allow)."""

    __tablename__ = "scope_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    action: Mapped[str] = mapped_column(String(10))  # allow | deny
    kind: Mapped[str] = mapped_column(String(20))  # host | url | path | image | cidr
    pattern: Mapped[str] = mapped_column(String(500))
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship()


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


class ScanRun(Base):
    """A scanner run Attestra dispatched (distinct from manual ImportRun uploads)."""

    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    tool: Mapped[str] = mapped_column(String(50))
    tool_version: Mapped[str] = mapped_column(String(100), default="")
    image_digest: Mapped[str] = mapped_column(String(100), default="")
    profile: Mapped[str] = mapped_column(String(50), default="baseline")  # baseline | active
    status: Mapped[str] = mapped_column(String(20), default="queued")
    requested_by: Mapped[str] = mapped_column(String(200))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_artifact_uri: Mapped[str] = mapped_column(String(500), default="")
    raw_sha256: Mapped[str] = mapped_column(String(64), default="")
    import_run_id: Mapped[int | None] = mapped_column(ForeignKey("import_runs.id"))
    refuse_reason: Mapped[str] = mapped_column(String(500), default="")

    engagement: Mapped[Engagement] = relationship()
    asset: Mapped[Asset] = relationship()


class Job(Base):
    """Durable work queue row for a ScanRun."""

    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|done|failed|cancelled
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    worker_id: Mapped[str] = mapped_column(String(100), default="")
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan_run: Mapped[ScanRun] = relationship()


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
    owasp_top10: Mapped[str] = mapped_column(String(100), default="")
    asvs_ref: Mapped[str] = mapped_column(String(50), default="")
    wstg_ref: Mapped[str] = mapped_column(String(50), default="")

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    asset: Mapped[Asset | None] = relationship()
    evidence: Mapped[list[Evidence]] = relationship(back_populates="finding")
    risk_acceptances: Mapped[list[RiskAcceptance]] = relationship(back_populates="finding")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    kind: Mapped[str] = mapped_column(String(30))  # screenshot | http_pair | log | file | note
    filename: Mapped[str] = mapped_column(String(300))
    path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, default="")
    masking_applied: Mapped[dict] = mapped_column(JSON, default=dict)
    captured_by: Mapped[str] = mapped_column(String(200))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class RetentionPolicy(Base):
    """Per-tenant retention days (PCI default ≥ 365)."""

    __tablename__ = "retention_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "framework"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    framework: Mapped[str] = mapped_column(String(30), default="")  # empty = default
    days: Mapped[int] = mapped_column(Integer, default=365)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)


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


class RiskAcceptance(Base):
    """Time-bounded acceptance of residual risk on a finding."""

    __tablename__ = "risk_acceptances"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    rationale: Mapped[str] = mapped_column(Text, default="")
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_on: Mapped[date] = mapped_column(Date)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    engagement: Mapped[Engagement] = relationship(back_populates="risk_acceptances")
    finding: Mapped[Finding] = relationship(back_populates="risk_acceptances")


class AsvScan(Base):
    """PCI ASV external scan attestation for an engagement."""

    __tablename__ = "asv_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    vendor: Mapped[str] = mapped_column(String(200))
    scan_date: Mapped[date] = mapped_column(Date)
    passing: Mapped[bool] = mapped_column(Boolean, default=False)
    attestation_path: Mapped[str] = mapped_column(String(500), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")

    engagement: Mapped[Engagement] = relationship(back_populates="asv_scans")


class SegmentationTest(Base):
    """PCI segmentation / network segregation test record."""

    __tablename__ = "segmentation_tests"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    boundary: Mapped[str] = mapped_column(String(300))
    method: Mapped[str] = mapped_column(String(200), default="")
    result: Mapped[str] = mapped_column(String(50), default="")  # pass | fail | inconclusive
    tested_on: Mapped[date] = mapped_column(Date)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"))

    engagement: Mapped[Engagement] = relationship(back_populates="segmentation_tests")


class ScanSchedule(Base):
    """Recurring scan calendar (PCI quarterly / monthly)."""

    __tablename__ = "scan_schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    tool: Mapped[str] = mapped_column(String(50))
    cadence: Mapped[str] = mapped_column(String(20), default="quarterly")  # quarterly | monthly
    next_due: Mapped[date] = mapped_column(Date)
    last_enqueued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    quarter_clean: Mapped[bool] = mapped_column(Boolean, default=False)

    engagement: Mapped[Engagement] = relationship(back_populates="scan_schedules")
    asset: Mapped[Asset] = relationship()


class Nonconformity(Base):
    """ISO nonconformity / corrective action tracker."""

    __tablename__ = "nonconformities"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    control_ref: Mapped[str] = mapped_column(String(50))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"))
    corrective_action: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    due: Mapped[date | None] = mapped_column(Date)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retest_id: Mapped[int | None] = mapped_column(Integer)

    engagement: Mapped[Engagement] = relationship(back_populates="nonconformities")


class Retest(Base):
    """Retest of a finding against a ScanRun; guards against false-close."""

    __tablename__ = "retests"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    scan_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"))
    result: Mapped[str] = mapped_column(String(30), default="")  # fixed | still_open | inconclusive
    requested_by: Mapped[str] = mapped_column(String(200), default="")
    requested_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    finalized_by: Mapped[str] = mapped_column(String(200), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    asset_reached: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding] = relationship()
    scan_run: Mapped[ScanRun | None] = relationship()


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    kind: Mapped[str] = mapped_column(String(30))  # technical | executive | compliance | letters...
    framework: Mapped[str] = mapped_column(String(30), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    # draft → submitted → qa_approved → signed; rejected returns to draft
    status: Mapped[str] = mapped_column(String(20), default="draft")
    generated_by: Mapped[str] = mapped_column(String(200))
    generated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    qa_by: Mapped[str] = mapped_column(String(200), default="")
    qa_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    rejection_note: Mapped[str] = mapped_column(Text, default="")
    approved_by: Mapped[str] = mapped_column(String(200), default="")
    approved_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    algorithm: Mapped[str] = mapped_column(String(40), default="")
    signature: Mapped[str] = mapped_column(String(500), default="")
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    docx_path: Mapped[str] = mapped_column(String(500), default="")
    docx_sha256: Mapped[str] = mapped_column(String(64), default="")
    pdf_path: Mapped[str] = mapped_column(String(500), default="")
    pdf_sha256: Mapped[str] = mapped_column(String(64), default="")
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)


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


class TenantRiskWeights(Base):
    """Per-tenant override of scoring.asset_weight / exposure_weight (Phase 7.4)."""

    __tablename__ = "tenant_risk_weights"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), unique=True)
    criticality_weights: Mapped[dict] = mapped_column(JSON, default=dict)  # {"1".."5": weight}
    internet_weight: Mapped[float] = mapped_column(Float, default=1.3)
    cde_weight: Mapped[float] = mapped_column(Float, default=1.3)
    updated_by: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SuppressionRule(Base):
    """Drop matching imported findings until the rule expires or is revoked (Phase 7.4)."""

    __tablename__ = "suppression_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagements.id"))  # None = whole tenant
    tool: Mapped[str] = mapped_column(String(50), default="")
    rule_id: Mapped[str] = mapped_column(String(300), default="")
    location_contains: Mapped[str] = mapped_column(String(500), default="")
    title_contains: Mapped[str] = mapped_column(String(300), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str] = mapped_column(String(200), default="")
    hits: Mapped[int] = mapped_column(Integer, default=0)
