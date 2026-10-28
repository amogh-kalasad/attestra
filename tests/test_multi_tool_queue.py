"""Engagement page: queue several tools in one submit; each passes the gate on its own."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select

from attestra import db
from attestra.api import app
from attestra.auth.keys import create_user
from attestra.models import Asset, Engagement, Job, ScanRun


def _client(engagement: int) -> TestClient:
    with db.session() as s:
        tid = s.get(Engagement, engagement).tenant_id
        u = create_user(s, username="mt-lead", role="lead", password="pw-1234567890", display_name="MT Lead")
        u.tenant_id = tid
    c = TestClient(app)
    c.post("/login", data={"username": "mt-lead", "password": "pw-1234567890"}, follow_redirects=False)
    return c


def _repo(engagement: int) -> int:
    with db.session() as s:
        return s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.identifier == "services/payments")
        ).first().id


def _flash(r) -> dict[str, str]:
    assert r.status_code == 303, r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    return {k: v[0] for k, v in q.items()}


def _runs(engagement: int) -> list[ScanRun]:
    with db.session() as s:
        return list(s.scalars(select(ScanRun).where(ScanRun.engagement_id == engagement).order_by(ScanRun.id)))


def test_queue_several_tools_creates_one_job_each(engagement):
    c = _client(engagement)
    r = c.post(
        f"/engagements/{engagement}/scans",
        data={"asset_id": str(_repo(engagement)), "tool": ["semgrep", "gitleaks", "checkov"], "profile": "baseline"},
        follow_redirects=False,
    )
    flash = _flash(r)
    runs = _runs(engagement)
    assert [x.tool for x in runs] == ["semgrep", "gitleaks", "checkov"]
    assert {x.status for x in runs} == {"queued"}
    with db.session() as s:
        assert len(list(s.scalars(select(Job)))) == 3
    assert "3 scans queued" in flash["msg"]
    for x in runs:
        assert f"#{x.id} {x.tool}" in flash["msg"]
    assert "error" not in flash


def test_mixed_success_and_refusal_reported_per_tool(engagement):
    c = _client(engagement)
    r = c.post(
        f"/engagements/{engagement}/scans",
        data={"asset_id": str(_repo(engagement)), "tool": ["semgrep", "zap"], "profile": "baseline"},
        follow_redirects=False,
    )
    flash = _flash(r)
    runs = {x.tool: x for x in _runs(engagement)}
    assert runs["semgrep"].status == "queued"
    assert runs["zap"].status == "refused"
    assert "1 scan queued" in flash["msg"] and "semgrep" in flash["msg"]
    assert flash["error"].startswith("Not queued: zap:")


def test_duplicate_tools_are_queued_once(engagement):
    c = _client(engagement)
    c.post(
        f"/engagements/{engagement}/scans",
        data={"asset_id": str(_repo(engagement)), "tool": ["semgrep", "semgrep"], "profile": "baseline"},
        follow_redirects=False,
    )
    assert [x.tool for x in _runs(engagement)] == ["semgrep"]


def test_single_tool_path_unchanged(engagement):
    c = _client(engagement)
    r = c.post(
        f"/engagements/{engagement}/scans",
        data={"asset_id": str(_repo(engagement)), "tool": "semgrep", "profile": "baseline"},
        follow_redirects=False,
    )
    run = _runs(engagement)[0]
    assert _flash(r)["msg"] == f"Scan #{run.id} queued (semgrep/baseline)."


def test_single_tool_refusal_shows_reason(engagement):
    c = _client(engagement)
    r = c.post(
        f"/engagements/{engagement}/scans",
        data={"asset_id": str(_repo(engagement)), "tool": "zap", "profile": "baseline"},
        follow_redirects=False,
    )
    flash = _flash(r)
    assert "msg" not in flash and "zap scans a" in flash["error"]


def test_no_tool_or_unknown_tool_rejected(engagement):
    c = _client(engagement)
    url = f"/engagements/{engagement}/scans"
    aid = str(_repo(engagement))
    assert _flash(c.post(url, data={"asset_id": aid}, follow_redirects=False))["error"] == "Choose at least one tool."
    bad = _flash(c.post(url, data={"asset_id": aid, "tool": ["semgrep", "rm -rf"]}, follow_redirects=False))
    assert bad["error"].startswith("Choose a tool from the list")
    assert _runs(engagement) == []


def test_engagement_page_renders_tool_checkboxes(engagement):
    c = _client(engagement)
    html = c.get(f"/engagements/{engagement}").text
    assert 'id="scan_tools"' in html
    assert html.count('type="checkbox" name="tool"') == 9
    assert 'data-kinds="repo"' in html and 'data-kinds="web_app api host"' in html
    assert 'data-kind="repo"' in html
    assert "Queue selected scans" in html
    assert 'id="scan_tool"' not in html  # old single select is gone


def test_static_js_filters_tools_by_target_kind():
    from pathlib import Path

    import attestra

    js = (Path(attestra.__file__).parent / "web" / "static" / "attestra.js").read_text(encoding="utf-8")
    assert "function toolFilter()" in js and "scan_tools_error" in js
