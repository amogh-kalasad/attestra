"""Phase 6.7: scheduler API/UI and CI/CD gate."""
from __future__ import annotations

import importlib.util
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def _first_asset(eid):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        return s.scalars(select(Asset).where(Asset.engagement_id == eid).order_by(Asset.id)).first().id


def _fake_scan(monkeypatch):
    from attestra import services
    from attestra.models import ScanRun

    def fake_request(s, eid, *, asset_id, tool, profile="baseline", actor="system"):
        run = ScanRun(engagement_id=eid, asset_id=asset_id, tool=tool, profile=profile, status="queued", requested_by=actor)
        s.add(run)
        s.flush()
        return run

    monkeypatch.setattr(services, "request_scan", fake_request)


def test_schedule_crud_via_api(client, engagement):
    aid = _first_asset(engagement)
    r = client.post(f"/api/engagements/{engagement}/schedules",
                    json={"asset_id": aid, "tool": "nuclei", "cadence": "quarterly", "next_due": str(date.today())})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert [x["id"] for x in client.get(f"/api/engagements/{engagement}/schedules").json()] == [sid]

    r = client.patch(f"/api/engagements/{engagement}/schedules/{sid}", json={"cadence": "monthly"})
    assert r.status_code == 200 and r.json()["cadence"] == "monthly"
    assert client.patch(f"/api/engagements/{engagement}/schedules/{sid}", json={"cadence": "weekly"}).status_code == 409

    assert client.delete(f"/api/engagements/{engagement}/schedules/{sid}").status_code == 204
    assert client.get(f"/api/engagements/{engagement}/schedules").json() == []
    assert client.delete(f"/api/engagements/{engagement}/schedules/{sid}").status_code == 404


def test_run_due_only_this_engagement(client, engagement, monkeypatch):
    from attestra import db, services

    _fake_scan(monkeypatch)
    aid = _first_asset(engagement)
    with db.session() as s:
        services.add_scan_schedule(s, engagement, asset_id=aid, tool="nuclei", cadence="monthly",
                                   next_due=date.today() - timedelta(days=1), actor="lead")
        services.add_scan_schedule(s, engagement, asset_id=aid, tool="zap", cadence="quarterly",
                                   next_due=date.today() + timedelta(days=10), actor="lead")
    r = client.post(f"/api/engagements/{engagement}/schedules/run-due")
    assert r.status_code == 200, r.text
    assert [x["tool"] for x in r.json()["enqueued"]] == ["nuclei"]
    with db.session() as s:
        assert services.enqueue_due_schedules(s, engagement_id=engagement + 999) == []


def test_gate_fails_on_high_and_passes_on_threshold(client, engagement):
    data = (FIXTURES / "trivy.json").read_bytes()
    r = client.post(f"/api/engagements/{engagement}/imports", data={"tool": "trivy"}, files={"file": ("trivy.json", data)})
    assert r.status_code == 201, r.text

    g = client.get(f"/api/engagements/{engagement}/gate", params={"fail_on": "high", "tool": "trivy"}).json()
    assert g["passed"] is False and g["blocking_count"] >= 1
    assert all(b["severity"] in ("critical", "high") for b in g["blocking"])

    loose = client.get(f"/api/engagements/{engagement}/gate",
                       params={"fail_on": "high", "tool": "trivy", "max_findings": g["blocking_count"]}).json()
    assert loose["passed"] is True
    other = client.get(f"/api/engagements/{engagement}/gate", params={"fail_on": "high", "tool": "zap"}).json()
    assert other["passed"] is True
    assert client.get(f"/api/engagements/{engagement}/gate", params={"fail_on": "bogus"}).status_code == 409


def test_gate_ignores_closed_findings(engagement):
    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        services.import_results(s, engagement, tool="trivy", filename="trivy.json",
                                data=(FIXTURES / "trivy.json").read_bytes(), actor="t")
        from sqlalchemy import select
        for f in s.scalars(select(Finding).where(Finding.engagement_id == engagement)):
            f.status = "false_positive"
        s.flush()
        assert services.ci_gate(s, engagement, fail_on="info")["passed"] is True


def test_gate_requires_auth(client, engagement):
    client.headers.pop("Authorization", None)
    assert client.get(f"/api/engagements/{engagement}/gate").status_code == 401


def test_ci_client_exit_codes(client, engagement, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("attestra_ci", ROOT / "integrations" / "ci" / "attestra_ci.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def fake_request(method, url, token, *, body=None, ctype=None, timeout=120):
        path = url.split("://", 1)[1].split("/", 1)[1]
        path = "/" + path
        if method == "POST":
            r = client.post(path, content=body, headers={"Content-Type": ctype, "Authorization": f"Bearer {token}"})
        else:
            r = client.get(path, headers={"Authorization": f"Bearer {token}"})
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
        return r.json()

    monkeypatch.setattr(mod, "_request", fake_request)
    token = client.headers["Authorization"][7:]
    base = ["--url", "http://testserver", "--token", token, "--engagement", str(engagement),
            "--file", f"trivy={FIXTURES / 'trivy.json'}"]
    assert mod.main(base + ["--fail-on", "high"]) == 1
    assert "FAIL" in capsys.readouterr().out
    assert mod.main(base + ["--no-gate"]) == 0
    assert mod.main(["--url", "x"]) == 2


@pytest.mark.parametrize("rel", ["integrations/ci/github/attestra-gate.yml", "integrations/ci/gitlab/attestra-gate.gitlab-ci.yml"])
def test_ci_templates_present_and_valid_yaml(rel):
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))
    assert doc
    assert "attestra_ci.py" in (ROOT / rel).read_text(encoding="utf-8")


def test_ui_schedule_section_renders(fresh_db, engagement):
    from fastapi.testclient import TestClient

    from attestra import db
    from attestra.api import app
    from attestra.auth.keys import create_user

    with db.session() as s:
        create_user(s, username="ui", role="lead", password="ui-pass-123", display_name="UI")
    with TestClient(app) as c:
        r = c.post("/login", data={"username": "ui", "password": "ui-pass-123"}, follow_redirects=False)
        assert r.status_code in (302, 303)
        aid = _first_asset(engagement)
        r = c.post(f"/engagements/{engagement}/schedules",
                   data={"asset_id": aid, "tool": "nuclei", "cadence": "monthly", "next_due": str(date.today())},
                   follow_redirects=False)
        assert r.status_code == 303 and "error" not in r.headers["location"]
        page = c.get(f"/engagements/{engagement}")
        assert page.status_code == 200
        assert 'id="schedules"' in page.text and "nuclei" in page.text
