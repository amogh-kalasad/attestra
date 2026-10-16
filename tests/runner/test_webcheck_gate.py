"""Gate accepts webcheck for web targets and refuses it for repo targets."""
from __future__ import annotations

import pytest

from attestra.runner.gate import GateError, check, tool_kind_problem


def test_tool_kind_webcheck_web_app_ok():
    assert tool_kind_problem("webcheck", "web_app") is None
    assert tool_kind_problem("webcheck", "api") is None
    assert tool_kind_problem("webcheck", "host") is None


def test_tool_kind_webcheck_repo_refused():
    problem = tool_kind_problem("webcheck", "repo")
    assert problem is not None
    assert "webcheck" in problem


def test_gate_accepts_webcheck_for_web_app(engagement, monkeypatch):
    """Gate returns a pin for webcheck on a web_app asset (DNS stubbed)."""
    from attestra import db
    from attestra.runner.dns_pin import PinnedTarget
    from sqlalchemy import select
    from attestra.models import Asset

    monkeypatch.setattr(
        "attestra.runner.gate.pin_url",
        lambda url, scope: PinnedTarget(host="shop.example.com", ip="93.184.216.34", port=443, scheme="https"),
    )
    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        pin = check(s, engagement, asset.id, tool="webcheck", profile="baseline", actor="tester")
    assert isinstance(pin, PinnedTarget)
    assert pin.host == "shop.example.com"


def test_gate_refuses_webcheck_for_repo(engagement):
    from attestra import db
    from sqlalchemy import select
    from attestra.models import Asset

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")
        ).first()
        with pytest.raises(GateError, match="webcheck"):
            check(s, engagement, asset.id, tool="webcheck", profile="baseline", actor="tester")
