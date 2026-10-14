"""Tests for the compliance engine, control assessment, report generation, four-eyes
approval, report verification, and CDE scoping for PCI DSS 4."""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- PCI rollup


def test_pci_rollup_returns_controls(loaded):
    """PCI DSS 4 evaluation returns a list of ControlResult objects."""
    from attestra import db, services

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
    assert results, "expected non-empty PCI DSS control list"
    refs = [r.ref for r in results]
    assert len(refs) == len(set(refs)), "duplicate control refs found"


def test_pci_rollup_status_values(loaded):
    """Every ControlResult status must be one of the known values."""
    from attestra import db, services

    valid = {"met", "partial", "not_met", "no_exceptions", "not_assessed", "not_applicable"}
    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
    for r in results:
        assert r.status in valid, f"invalid status {r.status!r} for {r.ref}"


def test_pci_open_critical_findings_lead_to_not_met(loaded):
    """Critical open findings on CDE assets should drive at least one control to not_met."""
    from attestra import db, services

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
    not_met = [r for r in results if r.status == "not_met"]
    # We have critical CVE-2024-9999 on in_cde assets, so at least one control fails.
    assert not_met, "expected at least one not_met control given critical CDE findings"


def test_iso_rollup_works(loaded):
    """ISO 27001:2022 evaluation runs without error and returns controls."""
    from attestra import db, services

    with db.session() as s:
        results = services.compliance(s, loaded, "iso_27001_2022")
    assert results


def test_soc2_rollup_works(loaded):
    from attestra import db, services

    with db.session() as s:
        results = services.compliance(s, loaded, "soc2")
    assert results


def test_unknown_framework_raises(loaded):
    from attestra import db, services

    with db.session() as s:
        with pytest.raises(ValueError, match="Unknown framework"):
            services.compliance(s, loaded, "nonexistent_fw")


# ---------------------------------------------------------------- Assessor confirm overrides


def test_assessor_confirm_override(loaded):
    """A confirmed control status overrides the engine's proposal."""
    from attestra import db, services

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
    # Find the authorization control to confirm
    auth_ctrl = next((r for r in results if r.ref == "11.4.1"), None)
    if auth_ctrl is None:
        auth_ctrl = results[0]  # fall back to first control

    ref = auth_ctrl.ref
    with db.session() as s:
        a = services.confirm_control(
            s, loaded,
            framework="pci_dss_4",
            ref=ref,
            status="met",
            assessor="assessor@example.com",
            rationale="Reviewed methodology; documentation satisfactory.",
        )
    assert a.status == "met"

    # Re-evaluate: confirmed status should appear in the result
    with db.session() as s:
        updated = services.compliance(s, loaded, "pci_dss_4")
    ctrl = next(r for r in updated if r.ref == ref)
    assert ctrl.confirmed == "met"
    assert ctrl.status == "met"
    assert ctrl.assessor == "assessor@example.com"


def test_confirm_invalid_status_raises(loaded):
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
    ref = results[0].ref

    with db.session() as s:
        with pytest.raises(ServiceError, match="status"):
            services.confirm_control(
                s, loaded, framework="pci_dss_4", ref=ref,
                status="invalid_status", assessor="a", rationale="x",
            )


def test_confirm_requires_rationale(loaded):
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
    ref = results[0].ref

    with db.session() as s:
        with pytest.raises(ServiceError, match="rationale"):
            services.confirm_control(
                s, loaded, framework="pci_dss_4", ref=ref,
                status="met", assessor="a", rationale="",
            )


def test_confirm_unknown_ref_raises(loaded):
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        with pytest.raises(ServiceError, match="not in the pci_dss_4 library"):
            services.confirm_control(
                s, loaded, framework="pci_dss_4", ref="99.99.99",
                status="met", assessor="a", rationale="some reason",
            )


# ---------------------------------------------------------------- Report generation


def test_generate_technical_report(loaded):
    """generate_report produces a Report row with a sha256 and an HTML file on disk."""
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@example.com")
        sha = r.sha256
        path = r.path

    assert sha
    assert Path(path).exists()
    assert Path(path).read_bytes()  # non-empty


def test_generate_executive_report(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="executive", actor="author@example.com")
    assert r.id > 0
    assert r.status == "draft"


def test_generate_compliance_report(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="compliance", framework="pci_dss_4", actor="author@example.com")
    assert r.framework == "pci_dss_4"
    assert Path(r.path).exists()


def test_generate_compliance_report_requires_framework(loaded):
    from attestra import db
    from attestra.reports import generate_report
    from attestra.services import ServiceError

    with db.session() as s:
        with pytest.raises(ServiceError, match="framework is required"):
            generate_report(s, loaded, kind="compliance", framework="", actor="author@example.com")


def test_report_version_increments(loaded):
    """Each successive report of the same kind increments the version number."""
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r1 = generate_report(s, loaded, kind="technical", actor="a")
        r2 = generate_report(s, loaded, kind="technical", actor="a")
    assert r2.version == r1.version + 1


# ---------------------------------------------------------------- Four-eyes approval


def test_approve_report_four_eyes(loaded):
    """A different actor can approve and sign the report."""
    from attestra import db
    from attestra.reports import approve_report, generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@example.com")
        rid = r.id

    with db.session() as s:
        signed = approve_report(s, rid, actor="approver@example.com")
    assert signed.status == "signed"
    assert signed.approved_by == "approver@example.com"
    assert signed.signature


def test_same_actor_cannot_approve(loaded):
    """The four-eyes rule: author and approver must be different people."""
    from attestra import db
    from attestra.auth.keys import create_user
    from attestra.reports import approve_report, generate_report
    from attestra.services import ServiceError

    with db.session() as s:
        user = create_user(s, username="sameuser", role="tester", password="pw-same-1")
        r = generate_report(s, loaded, kind="technical", actor=user.username, user_id=user.id)
        rid = r.id
        uid = user.id

    with db.session() as s:
        with pytest.raises(ServiceError, match="four-eyes"):
            approve_report(s, rid, actor="totally-different-name", user_id=uid)


def test_already_signed_cannot_approve_again(loaded):
    from attestra import db
    from attestra.reports import approve_report, generate_report
    from attestra.services import ServiceError

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="auth@example.com")
        rid = r.id

    with db.session() as s:
        approve_report(s, rid, actor="approv@example.com")

    with db.session() as s:
        with pytest.raises(ServiceError, match="already signed"):
            approve_report(s, rid, actor="third@example.com")


# ---------------------------------------------------------------- Verify report


def test_verify_report_hash_matches(loaded):
    """After generation the report file hash must match the stored sha256."""
    from attestra import db
    from attestra.reports import generate_report, verify_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@example.com")
        rid = r.id

    with db.session() as s:
        result = verify_report(s, rid)
    assert result["hash_matches"] is True
    assert result["status"] == "draft"  # not yet signed


def test_verify_signed_report(loaded):
    """A signed report verifies both hash and HMAC signature."""
    from attestra import db
    from attestra.reports import approve_report, generate_report, verify_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@example.com")
        rid = r.id

    with db.session() as s:
        approve_report(s, rid, actor="approver@example.com")

    with db.session() as s:
        result = verify_report(s, rid)
    assert result["hash_matches"] is True
    assert result["signature_valid"] is True
    assert result["status"] == "signed"


# ---------------------------------------------------------------- CDE scoping for PCI DSS


def test_cde_scoping_excludes_non_cde_findings(fresh_db):
    """Findings on non-CDE assets must not drive PCI DSS control status."""
    from attestra import db, services
    from attestra.compliance.engine import in_framework_scope
    from attestra.models import Asset, Finding

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="CDE Test", name="CDE Test Eng", type="va",
            frameworks=["pci_dss_4"], window_start=None, window_end=None, actor="tester",
        )
        services.add_authorization(
            s, e.id, filename="auth.txt", data=b"auth",
            signer="CISO", signed_on=today - timedelta(days=1),
            expires_on=today + timedelta(days=30),
            rules_of_engagement="ok", environments=["production"], actor="tester",
        )
        # Non-CDE web app
        non_cde = services.add_asset(
            s, e.id, kind="web_app", identifier="https://shop.example.com",
            environment="production", in_cde=False, actor="tester",
        )
        non_cde_id = non_cde.id

        # CDE asset present so the engagement is mixed-scope
        services.add_asset(
            s, e.id, kind="image", identifier="registry.example.com/shop/api",
            environment="production", in_cde=True, actor="tester",
        )
        eid = e.id

    with db.session() as s:
        # Add synthetic findings directly
        from attestra.fingerprint import fingerprint as fp
        from attestra.models import Finding

        non_cde_finding = Finding(
            engagement_id=eid,
            asset_id=non_cde_id,
            fingerprint=fp(location="https://shop.example.com/p", cwe=79, cves=[], title="XSS"),
            title="XSS on non-CDE asset",
            severity="high",
            status="new",
        )
        s.add(non_cde_finding)
        s.flush()
        nid = non_cde_finding.id

    # in_framework_scope must return False for pci_dss_4 when asset.in_cde is False
    with db.session() as s:
        f = s.get(Finding, nid)
        # Load asset explicitly
        from attestra.models import Asset
        a = s.get(Asset, non_cde_id)
        f.asset = a
        assert in_framework_scope(f, "pci_dss_4") is False
