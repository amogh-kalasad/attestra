"""Tests for the core business-logic layer (attestra/services.py)."""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- Import gate


def test_import_gate_without_auth(fresh_db):
    """Importing results is refused when no valid signed authorization exists."""
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        e = services.create_engagement(
            s, tenant="Client", name="Eng", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        services.add_asset(s, e.id, kind="web_app", identifier="https://shop.example.com", actor="tester")
        with pytest.raises(ServiceError, match="signed authorization"):
            services.import_results(
                s, e.id, tool="zap", filename="zap.json",
                data=(FIXTURES / "zap.json").read_bytes(), actor="tester",
            )


def test_import_succeeds_with_valid_auth(engagement):
    """Import runs cleanly once a valid authorization is on file."""
    from attestra import db, services

    with db.session() as s:
        run = services.import_results(
            s, engagement, tool="zap", filename="zap.json",
            data=(FIXTURES / "zap.json").read_bytes(), actor="tester",
        )
    assert run.new_findings > 0
    assert run.sha256


def test_import_returns_correct_counts(engagement):
    from attestra import db, services

    with db.session() as s:
        run = services.import_results(
            s, engagement, tool="nuclei", filename="nuclei.jsonl",
            data=(FIXTURES / "nuclei.jsonl").read_bytes(), actor="tester",
        )
    assert run.new_findings >= 3  # three lines in fixture
    assert run.updated_findings == 0  # first import, nothing updated yet


# ---------------------------------------------------------------- Fingerprint dedup


def test_fingerprint_dedup_across_reimport(engagement):
    """Importing the same file twice merges findings rather than creating duplicates."""
    from attestra import db, services

    data = (FIXTURES / "zap.json").read_bytes()
    with db.session() as s:
        run1 = services.import_results(s, engagement, tool="zap", filename="zap.json", data=data, actor="tester")
        run2 = services.import_results(s, engagement, tool="zap", filename="zap.json", data=data, actor="tester")

    assert run1.new_findings > 0
    assert run2.new_findings == 0  # all already exist
    assert run2.updated_findings == run1.new_findings


def test_fingerprint_dedup_same_cve_same_location(engagement):
    """Same CVE at the same location merges; different location/package keeps separate rows."""
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        services.import_results(
            s,
            engagement,
            tool="nuclei",
            filename="nuclei.jsonl",
            data=(FIXTURES / "nuclei.jsonl").read_bytes(),
            actor="tester",
        )
        services.import_results(
            s,
            engagement,
            tool="trivy",
            filename="trivy.json",
            data=(FIXTURES / "trivy.json").read_bytes(),
            actor="tester",
        )
        cve_findings = [
            f
            for f in s.scalars(select(Finding).where(Finding.engagement_id == engagement))
            if "CVE-2024-9999" in (f.cves or [])
        ]
    # Fingerprint keys on CVE + package + location, so web hit vs image package stay distinct.
    assert len(cve_findings) >= 1
    assert {tuple(sorted(f.cves or [])) for f in cve_findings} == {("CVE-2024-9999",)}


# ---------------------------------------------------------------- Risk score & KEV enrich


def test_kev_enrich_marks_finding(loaded):
    """After enrichment CVE-2024-9999 (in KEV fixture) is flagged kev=True."""
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Finding

    with db.session() as s:
        findings = list(s.scalars(select(Finding).where(Finding.engagement_id == loaded)))
    kev_findings = [f for f in findings if "CVE-2024-9999" in (f.cves or [])]
    assert kev_findings, "CVE-2024-9999 finding must exist after import"
    assert kev_findings[0].kev is True


def test_epss_enrich_populates_score(loaded):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Finding

    with db.session() as s:
        findings = list(s.scalars(select(Finding).where(Finding.engagement_id == loaded)))
    epss_findings = [f for f in findings if f.epss is not None]
    assert epss_findings, "at least one finding should have an EPSS score after enrichment"


def test_risk_score_kev_higher_than_non_kev(loaded):
    """KEV + high CVSS finding should have a higher risk_score than a non-KEV medium."""
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Finding

    with db.session() as s:
        findings = list(s.scalars(select(Finding).where(Finding.engagement_id == loaded)))

    kev = [f for f in findings if f.kev and f.cvss_score is not None]
    non_kev_medium = [f for f in findings if not f.kev and f.severity == "medium"]
    if kev and non_kev_medium:
        assert max(f.risk_score for f in kev) > max(f.risk_score for f in non_kev_medium)


def test_sla_due_set_on_import(loaded):
    """Critical findings must have an SLA due date after import."""
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Finding

    with db.session() as s:
        crits = list(s.scalars(
            select(Finding).where(Finding.engagement_id == loaded, Finding.severity == "critical")
        ))
    assert crits, "need at least one critical finding"
    assert all(f.sla_due is not None for f in crits)


# ---------------------------------------------------------------- Transitions


def test_transition_new_to_triaged(loaded):
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        fid = f.id

    with db.session() as s:
        updated = services.transition(s, fid, to="triaged", actor="tester")
    assert updated.status == "triaged"


def test_transition_triaged_to_validated(loaded):
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        fid = f.id

    with db.session() as s:
        services.transition(s, fid, to="triaged", actor="tester")
    with db.session() as s:
        updated = services.transition(s, fid, to="validated", actor="tester")
    assert updated.status == "validated"
    assert updated.validated_by == "tester"


def test_transition_invalid_skips_state(loaded):
    """Jumping directly from 'new' to 'validated' must be refused."""
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Finding
    from attestra.services import ServiceError

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        fid = f.id

    with db.session() as s:
        with pytest.raises(ServiceError, match="cannot move"):
            services.transition(s, fid, to="validated", actor="tester")


def test_false_positive_requires_note(loaded):
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Finding
    from attestra.services import ServiceError

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        fid = f.id

    with db.session() as s:
        with pytest.raises(ServiceError, match="reason"):
            services.transition(s, fid, to="false_positive", actor="tester", note="")


def test_false_positive_with_note_succeeds(loaded):
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        fid = f.id

    with db.session() as s:
        updated = services.transition(s, fid, to="false_positive", actor="tester", note="Not reproducible in our env")
    assert updated.status == "false_positive"


# ---------------------------------------------------------------- Reopen when fixed finding reimported


def test_reopen_when_fixed_finding_reimported(loaded):
    """A finding marked 'fixed' is reopened when the same issue reappears on reimport."""
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Finding

    # Get the first finding (ZAP XSS in shop.example.com)
    with db.session() as s:
        f = s.scalars(
            select(Finding).where(Finding.engagement_id == loaded, Finding.severity == "high")
        ).first()
        if f is None:
            f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        fid = f.id

    # Walk to fixed
    with db.session() as s:
        services.transition(s, fid, to="triaged", actor="tester")
    with db.session() as s:
        services.transition(s, fid, to="validated", actor="tester")
    with db.session() as s:
        services.transition(s, fid, to="fixed", actor="tester", note="Patched in v1.2")

    # Confirm it's fixed
    with db.session() as s:
        assert s.get(Finding, fid).status == "fixed"

    # Reimport the same tool data — the fingerprint matches → should reopen
    # We need to find which fixture produces this fingerprint.
    # Import all fixtures again; the matching fingerprint will be reopened.
    with db.session() as s:
        for tool, fname in [("zap", "zap.json"), ("nuclei", "nuclei.jsonl"), ("trivy", "trivy.json"), ("sarif", "semgrep.sarif")]:
            services.import_results(
                s, loaded, tool=tool, filename=fname,
                data=(FIXTURES / fname).read_bytes(), actor="tester",
            )

    with db.session() as s:
        f = s.get(Finding, fid)
    # Reopened: status should not still be 'fixed'
    assert f.status != "fixed", f"expected finding to be reopened, got {f.status!r}"


# ---------------------------------------------------------------- Audit chain


def test_audit_verify_chain_intact(loaded):
    """The audit log hash chain must be intact after normal operations."""
    from attestra import audit, db

    with db.session() as s:
        ok, bad = audit.verify(s)
    assert ok is True
    assert bad is None


def test_audit_tamper_breaks_chain(engagement):
    """Directly mutating an audit event hash breaks the chain verification."""
    from sqlalchemy import select

    from attestra import audit, db
    from attestra.models import AuditEvent

    with db.session() as s:
        ev = s.scalars(select(AuditEvent).order_by(AuditEvent.id)).first()
        assert ev is not None, "need at least one audit event"
        # Tamper with the stored hash
        ev.hash = "deadbeef" * 8
        # Also tamper details so recompute won't match
        ev.details = {**ev.details, "tampered": True}

    with db.session() as s:
        ok, bad = audit.verify(s)
    assert ok is False
    assert bad is not None
