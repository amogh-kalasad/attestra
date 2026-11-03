"""Elite Phase E5: browser screenshot capture (Playwright or injected capture_fn)."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from attestra import config, db, services
from attestra.automated_vapt.capture.browser_capture import (
    capture_screenshot,
    stable_screenshot_name,
)
from attestra.automated_vapt.core import orchestrator as orch
from attestra.automated_vapt.core import scope_validator
from attestra.services import ServiceError

_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", True)


# @lat: [[tests#Elite Phase E5 browser capture#Injected capture returns png]]
def test_injected_capture_returns_png(elite_flag):
    scope = scope_validator.build_scope_from_asset("http://localhost:8765/", allow_private=True)

    def _fn(url: str) -> bytes:
        assert url.startswith("http://localhost:8765")
        return _TINY_PNG

    result = capture_screenshot(
        "http://localhost:8765/",
        scope=scope,
        capture_fn=_fn,
        check_dns=False,
    )
    assert result.screenshot_png.startswith(b"\x89PNG")
    assert result.to_dict()["png_magic_ok"] is True


# @lat: [[tests#Elite Phase E5 browser capture#Out of scope browser refused]]
def test_out_of_scope_browser_refused(elite_flag):
    scope = scope_validator.build_scope_from_asset("http://localhost:8765/", allow_private=True)
    with pytest.raises(ServiceError, match="out of scope"):
        capture_screenshot(
            "https://evil.example/",
            scope=scope,
            capture_fn=lambda _u: _TINY_PNG,
            check_dns=False,
        )


# @lat: [[tests#Elite Phase E5 browser capture#Stable screenshot filename]]
def test_stable_screenshot_filename(elite_flag):
    name = stable_screenshot_name(
        engagement_id=12,
        execution_id=34,
        test_case_id="T02",
        label="full-page",
    )
    assert name == "e12_x34_T02_full-page.png"


# @lat: [[tests#Elite Phase E5 browser capture#Orchestrator T02 injected]]
def test_orchestrator_t02_injected(fresh_db, elite_flag):
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Elite E5 Client",
            name="Elite E5",
            type="vapt",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=30),
            actor="tester",
        )
        services.add_authorization(
            s,
            e.id,
            filename="roe.txt",
            data=b"authorized",
            signer="Client",
            signed_on=today - timedelta(days=1),
            expires_on=today + timedelta(days=30),
            rules_of_engagement="local",
            environments=["dev"],
            actor="tester",
        )
        a = services.add_asset(
            s,
            e.id,
            kind="web_app",
            identifier="http://localhost:8765/",
            name="Mock",
            environment="dev",
            actor="tester",
        )
        ex = orch.create_execution(
            s,
            engagement_id=e.id,
            asset_id=a.id,
            test_case_ids=["T02"],
            actor="tester",
            allow_private=True,
        )
        xid = ex.id

    with db.session() as s:
        done = orch.run_execution(
            s,
            xid,
            actor="tester",
            extra={
                "browser_capture_fn": lambda _u: _TINY_PNG,
                "execution_id": xid,
            },
        )
        assert done.status == "COMPLETED"
        t02 = orch.execution_public_dict(done)["result"]["cases"][0]
        assert t02["status"] == "PASSED"
        assert t02["screenshot"]["png_magic_ok"] is True
        assert "T02" in t02["screenshot"]["filename"]
