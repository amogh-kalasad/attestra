"""Phase 5: storage immutability, retention, audit append-only, backup, feeds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

from attestra import audit, db, services
from attestra.models import AuditEvent, Evidence, Report
from attestra.ops.backup import BackupError, backup, restore, verify_manifest
from attestra.ops.feeds import load_cached_feeds, load_catalog_meta, refresh_feeds
from attestra.ops.retention import ensure_default_policy, purge_expired
from attestra.reports import generate_report
from attestra.storage.local import LocalStorage, StorageError

FIXTURES = Path(__file__).parent / "fixtures"


# @lat: [[tests#Phase 5 evidence hardening#Storage immutability]]
def test_local_storage_refuses_overwrite(fresh_db, tmp_path):
    store = LocalStorage(root=tmp_path / "store")
    uri = store.put("a/b.txt", b"one")
    assert store.get(uri) == b"one"
    assert store.put("a/b.txt", b"one") == uri
    with pytest.raises(StorageError, match="refusing overwrite"):
        store.put("a/b.txt", b"two")


# @lat: [[tests#Phase 5 evidence hardening#Evidence masking wired]]
def test_add_evidence_masks_before_store(loaded):
    with db.session() as s:
        findings = services.list_findings(s, loaded)
        pan = "4111111111111111"
        ev = services.add_evidence(
            s,
            findings[0].id,
            kind="note",
            filename="cap.txt",
            data=f"captured card {pan}".encode(),
            note="test",
            actor="tester",
        )
        text_out = Path(ev.path).read_text(encoding="utf-8")
        assert pan not in text_out
        assert ev.masking_applied.get("pan", 0) >= 1
        assert "*" in text_out


# @lat: [[tests#Phase 5 evidence hardening#Retention purge]]
def test_purge_expired_skips_legal_hold_and_audits(loaded):
    with db.session() as s:
        eng = services.get_engagement(s, loaded)
        ensure_default_policy(s, eng.tenant_id, days=365)
        findings = services.list_findings(s, loaded)
        ev = services.add_evidence(
            s,
            findings[0].id,
            kind="note",
            filename="old.txt",
            data=b"old evidence",
            note="",
            actor="tester",
        )
        # Past PCI default retention of 365 days
        ev.captured_at = datetime.now(UTC) - timedelta(days=400)
        report = generate_report(s, loaded, kind="technical", actor="lead")
        report.legal_hold = True
        report.generated_at = datetime.now(UTC) - timedelta(days=400)
        hold_id = report.id
        ev_id = ev.id

    with db.session() as s:
        dry = purge_expired(s, dry_run=True, actor="admin")
        assert dry["candidates"]["evidence"] >= 1
        assert dry["deleted"]["evidence"] == 0

    with db.session() as s:
        result = purge_expired(s, dry_run=False, actor="admin")
        assert result["deleted"]["evidence"] >= 1
        assert s.get(Evidence, ev_id) is None
        assert s.get(Report, hold_id) is not None
        events = list(s.scalars(select(AuditEvent).where(AuditEvent.action == "retention.purge")))
        assert events


# @lat: [[tests#Phase 5 evidence hardening#Append-only audit]]
def test_audit_events_append_only(fresh_db):
    with db.session() as s:
        audit.record(s, "t", "test.action", "x", 1)
        ev_id = s.scalars(select(AuditEvent).order_by(AuditEvent.id.desc())).first().id
    with db.session() as s:
        with pytest.raises((OperationalError, Exception)):
            s.execute(text("UPDATE audit_events SET actor='evil' WHERE id=:id"), {"id": ev_id})
            s.commit()


# @lat: [[tests#Phase 5 evidence hardening#Download audit]]
def test_evidence_download_creates_audit_event(client, loaded, auth_headers):
    with db.session() as s:
        findings = services.list_findings(s, loaded)
        ev = services.add_evidence(
            s,
            findings[0].id,
            kind="note",
            filename="dl.txt",
            data=b"download me",
            note="",
            actor="tester",
        )
        eid = ev.id

    r = client.get(f"/api/evidence/{eid}/download", headers=auth_headers)
    assert r.status_code == 200
    assert r.content == b"download me"

    with db.session() as s:
        rows = list(
            s.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "evidence.download",
                    AuditEvent.entity_id == eid,
                )
            )
        )
        assert len(rows) >= 1


# @lat: [[tests#Phase 5 evidence hardening#Audit export]]
def test_audit_export_json_and_csv(client, auth_headers):
    r = client.get("/api/audit/export?format=json", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert "proof" in body and "events" in body
    assert "chain_ok" in body["proof"]

    r2 = client.get("/api/audit/export?format=csv", headers=auth_headers)
    assert r2.status_code == 200
    assert "chain_ok=" in r2.text
    assert "prev_hash" in r2.text


# @lat: [[tests#Phase 5 evidence hardening#Backup restore]]
def test_backup_restore_tamper_refused(fresh_db, tmp_path, engagement):
    dest = tmp_path / "bak"
    info = backup(dest)
    assert Path(info["manifest"]).is_file()
    ok, errs = verify_manifest(dest)
    assert ok and not errs

    db_file = dest / "attestra.db"
    db_file.write_bytes(db_file.read_bytes() + b"x")
    ok2, _ = verify_manifest(dest)
    assert not ok2
    with pytest.raises(BackupError, match="refused"):
        restore(dest)

    dest2 = tmp_path / "bak2"
    backup(dest2)
    out = restore(dest2)
    assert out["restored_files"] >= 1


# @lat: [[tests#Phase 5 evidence hardening#Feed refresh offline]]
def test_enrich_refresh_offline_fixtures(fresh_db, engagement):
    kev = (FIXTURES / "kev.json").read_bytes()
    epss = (FIXTURES / "epss.csv").read_bytes()

    class _Resp:
        def __init__(self, data: bytes):
            self._data = data

        def read(self):
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(url, timeout=60):
        if "kev" in url or "known_exploited" in url:
            return _Resp(kev)
        return _Resp(epss)

    with patch("attestra.ops.feeds.urlopen", fake_urlopen):
        meta = refresh_feeds()
    assert meta.get("kev_date") or meta.get("kev_fetched_at")
    cached_kev, cached_epss = load_cached_feeds()
    assert cached_kev and cached_epss
    assert load_catalog_meta()

    with db.session() as s:
        result = services.enrich(s, kev_json=cached_kev, epss_csv=cached_epss, actor="cli")
        assert result["kev_entries"] >= 1
