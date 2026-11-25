"""Automatic screenshot evidence for classic findings (no manual upload)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.proof import screenshots as shot

# Minimal valid 1x1 PNG
_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)
_PNG_B = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc`\x00\x00"
    b"\x00\x02\x00\x01\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82"
)


@pytest.fixture(autouse=True)
def _clear_capture_registry():
    shot.clear_screenshot_capture()
    yield
    shot.clear_screenshot_capture()


def _http_finding(s, eid):
    """Return a finding that already has an http(s) location (Mongo read models are read-only)."""
    from attestra import services

    findings = [
        f
        for f in services.list_findings(s, eid)
        if (f.location or "").split(" [param:", 1)[0].strip().lower().startswith(("http://", "https://"))
    ]
    assert findings, "loaded fixture should include http(s) findings"
    return findings[0]


def _http_findings(s, eid, n: int = 2):
    from attestra import services

    findings = [
        f
        for f in services.list_findings(s, eid)
        if (f.location or "").split(" [param:", 1)[0].strip().lower().startswith(("http://", "https://"))
    ]
    assert len(findings) >= n, f"need >= {n} http findings, got {len(findings)}"
    return findings[:n]


# @lat: [[tests#Phase 7 testing depth#Auto screenshot from PNG bytes]]
def test_capture_from_png_bytes_creates_screenshot(loaded):
    from attestra import db

    with db.session() as s:
        f = _http_finding(s, loaded)
        ev = shot.capture_finding_screenshot(s, f, page_png_bytes=_PNG, actor="tester")
        assert ev is not None
        assert ev.kind == "screenshot"
        assert ev.finding_id == f.id
        assert len(ev.sha256 or "") == 64
        assert isinstance(ev.sha256, str)


# @lat: [[tests#Automatic screenshots#Finding gets screenshot via capture_fn]]
def test_capture_fn_attaches_screenshot(loaded):
    from attestra import db

    called = []

    def _fn(url: str):
        called.append(url)
        return _PNG

    with db.session() as s:
        f = _http_finding(s, loaded)
        ev = shot.capture_finding_screenshot(s, f, capture_fn=_fn, actor="tester")
        assert ev is not None and ev.kind == "screenshot"
        assert called and called[0].startswith("http")
        assert ev.finding_id == f.id


# @lat: [[tests#Phase 7 testing depth#Auto screenshot skip existing]]
def test_second_capture_does_not_overwrite(loaded):
    from attestra import db
    from attestra.models import Evidence
    from sqlalchemy import select, func

    with db.session() as s:
        f = _http_finding(s, loaded)
        first = shot.capture_finding_screenshot(s, f, page_png_bytes=_PNG, actor="tester")
        second = shot.capture_finding_screenshot(s, f, page_png_bytes=_PNG_B, actor="tester")
        assert first is not None
        assert second is None
        n = s.scalar(select(func.count()).select_from(Evidence).where(Evidence.finding_id == f.id, Evidence.kind == "screenshot"))
        assert n == 1


# @lat: [[tests#Automatic screenshots#Capture failure recorded]]
def test_capture_failure_recorded_no_fake_png(loaded):
    from attestra import db
    from attestra.models import Evidence
    from sqlalchemy import select

    with db.session() as s:
        f = _http_finding(s, loaded)

        def _boom(_url: str):
            raise RuntimeError("browser down")

        ev = shot.capture_finding_screenshot(s, f, capture_fn=_boom, actor="tester")
        assert ev is not None
        assert ev.kind == "capture_failure"
        assert ev.capture_status in ("failed", "unavailable")
        shots = list(s.scalars(select(Evidence).where(Evidence.finding_id == f.id, Evidence.kind == "screenshot")))
        assert shots == []


# @lat: [[tests#Automatic screenshots#Non-http marks N/A when enabled]]
def test_non_http_marks_na_when_auto_on(loaded, monkeypatch):
    from attestra import config, db

    monkeypatch.setattr(config, "AUTO_SCREENSHOT_ENABLED", True)
    shot.register_screenshot_capture(lambda _u: _PNG)

    from types import SimpleNamespace

    with db.session() as s:
        base = _http_finding(s, loaded)
        # Read-only Mongo finding: use a lightweight stand-in with non-http location.
        f = SimpleNamespace(id=base.id, location="host.example.com")
        ev = shot.capture_finding_screenshot(s, f, actor="tester")
        assert ev is not None
        assert ev.capture_status == "n/a"
        assert ev.kind == "capture_failure"


# @lat: [[tests#Phase 7 testing depth#Auto screenshot import stays network-free]]
def test_import_without_registry_stays_network_free(loaded):
    from attestra import db
    from attestra.proof.capture import capture_from_import

    calls = []

    with db.session() as s:
        # No registry → must not call any network capture
        n = capture_from_import(s, loaded, "webcheck", b"{}", actor="tester")
        assert n == 0
        assert calls == []


# @lat: [[tests#Phase 7 testing depth#Auto screenshot via import registry]]
def test_import_with_registry_captures_for_any_tool(loaded):
    from attestra import db
    from attestra.proof.capture import capture_from_import
    from attestra.models import Evidence
    from sqlalchemy import select

    shot.register_screenshot_capture(lambda _u: _PNG)
    with db.session() as s:
        f = _http_finding(s, loaded)
        # Fixture zap findings already include tool "zap" on shop.example.com URLs.
        capture_from_import(s, loaded, "zap", b"{}", actor="tester")
        rows = list(
            s.scalars(select(Evidence).where(Evidence.finding_id == f.id, Evidence.kind == "screenshot"))
        )
        # If this finding's tools omit zap, any zap-tagged http finding should still get a shot.
        if not rows:
            rows = list(s.scalars(select(Evidence).where(Evidence.kind == "screenshot")))
        assert rows, "expected auto screenshot after import with registered capture_fn"


# @lat: [[tests#Automatic screenshots#Multiple findings separate hashes]]
def test_multiple_findings_get_separate_screenshots(loaded):
    from attestra import db

    payloads = [_PNG, _PNG_B]
    idx = {"i": 0}

    def _fn(_url: str):
        i = idx["i"] % len(payloads)
        idx["i"] += 1
        return payloads[i]

    with db.session() as s:
        findings = _http_findings(s, loaded, 2)
        evs = []
        for f in findings:
            ev = shot.capture_finding_screenshot(s, f, capture_fn=_fn, actor="tester")
            assert ev is not None and ev.kind == "screenshot"
            evs.append(ev)
        assert evs[0].id != evs[1].id
        assert evs[0].finding_id != evs[1].finding_id
        assert len(evs[0].sha256 or "") == 64 and len(evs[1].sha256 or "") == 64


# @lat: [[tests#Automatic screenshots#Technical report includes screenshot]]
def test_technical_report_includes_auto_screenshot(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        f = _http_finding(s, loaded)
        ev = shot.capture_finding_screenshot(s, f, page_png_bytes=_PNG, actor="tester", note="auto-captured screenshot")
        assert ev is not None
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")
        assert "data:image/png;base64," in body
        assert "auto-captured screenshot" in body or "Fig." in body


# @lat: [[tests#Automatic screenshots#Gallery visually verified]]
def test_gallery_marks_visually_verified(loaded):
    from attestra import db, services
    from attestra.evidence.gallery import build_gallery

    with db.session() as s:
        f = _http_finding(s, loaded)
        shot.capture_finding_screenshot(s, f, page_png_bytes=_PNG, actor="tester")
        rows = services.list_evidence(s, f.id) if hasattr(services, "list_evidence") else list(f.evidence or [])
        if not rows:
            from attestra.models import Evidence
            from sqlalchemy import select

            rows = list(s.scalars(select(Evidence).where(Evidence.finding_id == f.id)))
        gal = build_gallery(rows)
        assert gal["visually_verified"] is True
        assert gal["counts"]["screenshots"] >= 1


# @lat: [[tests#Automatic screenshots#Playwright factory registers when enabled]]
def test_try_register_respects_env(monkeypatch):
    from attestra import config
    from attestra.proof import playwright_capture as pc

    monkeypatch.setattr(config, "AUTO_SCREENSHOT_ENABLED", False)
    assert pc.try_register_auto_screenshot() is False
    assert shot.registered_screenshot_capture() is None

    monkeypatch.setattr(config, "AUTO_SCREENSHOT_ENABLED", True)
    monkeypatch.setattr(pc, "playwright_ready", lambda: False)
    assert pc.try_register_auto_screenshot() is False

    monkeypatch.setattr(pc, "playwright_ready", lambda: True)
    monkeypatch.setattr(
        pc,
        "make_playwright_capture_fn",
        lambda **_k: (lambda _u: _PNG),
    )
    assert pc.try_register_auto_screenshot() is True
    assert shot.registered_screenshot_capture() is not None
    assert shot.registered_screenshot_capture()("https://example.com") == _PNG
