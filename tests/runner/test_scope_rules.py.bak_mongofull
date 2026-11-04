"""Tests for scope rule deny-beats-allow and audit on remove."""
from __future__ import annotations

import pytest


def test_deny_host_beats_allow(engagement):
    """A deny rule for a host beats the allow-list entry."""
    from attestra import db, services
    from attestra.runner.authorization import AuthorizationError, scope_for_engagement, validate_url_target

    with db.session() as s:
        services.add_scope_rule(
            s, engagement, action="deny", kind="host", pattern="shop.example.com", actor="tester"
        )

    with db.session() as s:
        scope = scope_for_engagement(s, engagement)
        with pytest.raises(AuthorizationError, match="denied by scope rule"):
            validate_url_target(scope, "https://shop.example.com/")


def test_allow_rule_still_works_without_deny(engagement):
    """Without a deny rule, the in-scope host is allowed."""
    from attestra import db
    from attestra.runner.authorization import scope_for_engagement, validate_url_target

    with db.session() as s:
        scope = scope_for_engagement(s, engagement)
        # Should not raise
        validate_url_target(scope, "https://shop.example.com/")


def test_remove_scope_rule_audited(engagement):
    """Removing a scope rule creates an audit event."""
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import AuditEvent

    with db.session() as s:
        rule = services.add_scope_rule(
            s, engagement, action="deny", kind="host", pattern="bad.example.com", actor="tester"
        )
        rule_id = rule.id

    with db.session() as s:
        services.remove_scope_rule(s, rule_id, actor="tester")

    with db.session() as s:
        events = list(s.scalars(select(AuditEvent).where(AuditEvent.action == "scope_rule.remove")))
        assert len(events) >= 1
        assert any(e.entity_id == rule_id for e in events)


def test_deny_url_pattern_blocks_specific_path(engagement):
    from attestra import db, services
    from attestra.runner.authorization import AuthorizationError, scope_for_engagement, validate_url_target

    with db.session() as s:
        services.add_scope_rule(
            s, engagement, action="deny", kind="url", pattern="*/admin*", actor="tester"
        )

    with db.session() as s:
        scope = scope_for_engagement(s, engagement)
        with pytest.raises(AuthorizationError):
            validate_url_target(scope, "https://shop.example.com/admin/users")
