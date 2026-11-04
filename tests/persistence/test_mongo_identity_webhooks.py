"""Mongo identity/settings/webhook repositories, Mongo-native services and the identity mirror.

Runs against a throwaway ``attestra_test_*`` database (``mongo_test_db``), never the live DB.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

pytest.importorskip("pymongo")
pytestmark = pytest.mark.mongo

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731 - documentation IP stand-in, no network


@pytest.fixture
def fernet_key(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ATTESTRA_CREDENTIAL_FERNET_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL", raising=False)


@pytest.fixture
def world(mongo_test_db):
    from attestra.persistence.mongo.repositories import EngagementRepository, FindingRepository, TenantRepository
    from attestra.users import mongo_service as ms

    db = mongo_test_db
    a = TenantRepository(db).create("tenant-a")["id"]
    b = TenantRepository(db).create("tenant-b")["id"]
    ea = EngagementRepository(db).create(a, "eng-a", "web")["id"]
    fa = FindingRepository(db).create(ea, "fp-a", "XSS", severity="high", status="new")
    admin = ms.create_user(db, username="root", role="admin", password="Correct-Horse-9")
    lead = ms.create_user(db, username="lead-a", role="lead", password="Correct-Horse-9", tenant_id=a)
    from attestra.persistence.mongo.repositories import MembershipRepository

    MembershipRepository(db).ensure(lead["id"], a, "lead")
    tb = ms.create_user(db, username="tester-b", role="tester", password="Correct-Horse-9", tenant_id=b)
    return {"db": db, "a": a, "b": b, "ea": ea, "fa": fa, "admin": ms._principal(admin),
            "lead": ms._principal(lead), "tb": tb}


# ---------------------------------------------------------------- secrets codec


def test_codec_roundtrip_and_fail_closed(fernet_key, monkeypatch):
    from attestra.persistence.mongo import secrets_codec as sc

    enc = sc.encrypt_secret("s3cret-value")
    assert enc.startswith(sc.PREFIX) and "s3cret-value" not in enc
    assert sc.decrypt_secret(enc) == "s3cret-value"
    monkeypatch.delenv("ATTESTRA_CREDENTIAL_FERNET_KEY")
    with pytest.raises(sc.SecretCodecError):
        sc.encrypt_secret("x")
    doc = sc.protect_webhook_endpoint({"_id": 1, "secret": "plain"})
    assert "secret" not in doc and doc["secret_enc"] is None and doc["secret_unavailable"] is True


def test_transform_encrypts_webhook_secret(fernet_key):
    from attestra.migration.transform import row_to_document
    from attestra.persistence.mongo.secrets_codec import decrypt_secret

    doc = row_to_document("webhook_endpoints", {"id": 7, "tenant_id": 1, "url": "https://x.example/h", "secret": "ab" * 32})
    assert "secret" not in doc and doc["_id"] == 7
    assert decrypt_secret(doc["secret_enc"]) == "ab" * 32


# ---------------------------------------------------------------- webhook repositories + service


def test_endpoint_secret_encrypted_at_rest_and_signing(world, fernet_key):
    from attestra.webhooks import formats
    from attestra.webhooks import mongo_service as wh

    db = world["db"]
    ep, secret = wh.create_endpoint(db, None, world["a"], url="https://hooks.example.com/x", actor="root",
                                    events=["finding.created"], resolver=PUBLIC)
    raw = db.webhook_endpoints.find_one({"_id": ep["id"]})
    assert "secret" not in raw and secret not in str(raw)
    assert "secret_enc" not in ep
    sent = []

    def sender(e, body, headers):
        sent.append((e.url, body, headers))
        return 204

    queued = wh.emit(db, "finding.created", tenant_id=world["a"], data={"x": 1})
    assert len(queued) == 1
    done = wh.dispatch_due(db, sender=sender)
    assert [d["status"] for d in done] == ["delivered"]
    url, body, headers = sent[0]
    assert formats.verify(secret, body, headers[formats.TS_HEADER], headers[formats.SIG_HEADER])
    # second dispatch has nothing to claim
    assert wh.dispatch_due(db, sender=sender) == []


def test_endpoint_create_fails_closed_without_key(world, monkeypatch):
    from attestra.webhooks import mongo_service as wh
    from attestra.webhooks.service import WebhookError

    monkeypatch.delenv("ATTESTRA_CREDENTIAL_FERNET_KEY", raising=False)
    monkeypatch.delenv("ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL", raising=False)
    with pytest.raises(WebhookError):
        wh.create_endpoint(world["db"], None, world["a"], url="https://hooks.example.com/x", actor="root", resolver=PUBLIC)
    assert world["db"].webhook_endpoints.count_documents({}) == 0


def test_delivery_backoff_and_failure(world, fernet_key):
    from attestra.persistence.mongo.serialization import utcnow
    from attestra.webhooks import mongo_service as wh
    from attestra.webhooks.service import BACKOFF_SECONDS, MAX_ATTEMPTS

    db = world["db"]
    wh.create_endpoint(db, None, world["a"], url="https://hooks.example.com/x", actor="root", resolver=PUBLIC)
    wh.emit(db, "scan.finished", tenant_id=world["a"], data={})
    now = utcnow()
    d = wh.dispatch_due(db, sender=lambda *a: 500, now=now)[0]
    assert d["status"] == "pending" and d["attempts"] == 1 and d["last_error"] == "HTTP 500"
    assert wh.dispatch_due(db, sender=lambda *a: 500, now=now) == []  # not due yet
    for i in range(1, MAX_ATTEMPTS):
        now = now + timedelta(seconds=BACKOFF_SECONDS[min(i, len(BACKOFF_SECONDS)) - 1] + 1)
        d = wh.dispatch_due(db, sender=lambda *a: 500, now=now)[0]
    assert d["status"] == "failed" and d["attempts"] == MAX_ATTEMPTS


def test_rules_assign_notify_and_tenant_scope(world, fernet_key):
    from attestra.persistence.mongo.repositories import FindingAssignmentRepository
    from attestra.webhooks import mongo_service as wh
    from attestra.webhooks.service import WebhookError

    db, a, b = world["db"], world["a"], world["b"]
    ep, _ = wh.create_endpoint(db, frozenset({a}), a, url="https://hooks.example.com/r", actor="lead-a",
                               events=["report.signed"], resolver=PUBLIC)
    # tenant-b caller cannot see or deactivate tenant-a endpoint, nor create in tenant a
    assert wh.list_endpoints(db, frozenset({b})) == []
    with pytest.raises(LookupError):
        wh.deactivate_endpoint(db, frozenset({b}), ep["id"], actor="x")
    with pytest.raises(LookupError):
        wh.create_endpoint(db, frozenset({b}), a, url="https://hooks.example.com/r", actor="x", resolver=PUBLIC)
    with pytest.raises(WebhookError):
        wh.create_rule(db, frozenset({b}), b, action="notify", actor="x", endpoint_id=ep["id"])
    wh.create_rule(db, None, a, action="assign", actor="root", assignee="alice", min_severity="high")
    wh.create_rule(db, None, a, action="notify", actor="root", endpoint_id=ep["id"], min_severity="critical")
    f = world["fa"]
    out = wh.emit(db, "finding.created", tenant_id=a, data=wh.finding_data(f), finding=f)
    assert out == []  # endpoint only subscribes to report.signed; notify rule needs critical
    assert [x["assignee"] for x in FindingAssignmentRepository(db).list_for_finding(f["id"])] == ["alice"]
    assert FindingAssignmentRepository(db, tenant_ids=frozenset({b})).list_for_finding(f["id"]) == []


def test_rotate_secret(world, fernet_key):
    from attestra.persistence.mongo.repositories import WebhookEndpointRepository
    from attestra.webhooks import mongo_service as wh

    db = world["db"]
    ep, s1 = wh.create_endpoint(db, None, world["a"], url="https://hooks.example.com/x", actor="root", resolver=PUBLIC)
    s2 = wh.rotate_secret(db, None, ep["id"], actor="root")
    assert s1 != s2 and WebhookEndpointRepository(db).reveal_secret(ep["id"]) == s2
    with pytest.raises(LookupError):
        WebhookEndpointRepository(db, tenant_ids=frozenset({world["b"]})).reveal_secret(ep["id"])


# ---------------------------------------------------------------- users


def test_invite_accept_single_use_and_membership(world):
    from attestra.users import mongo_service as ms
    from attestra.users.service import UserAdminError

    db = world["db"]
    inv, raw = ms.create_invite(db, world["lead"], email="New@Example.com", role="tester", tenant_id=world["a"])
    stored = db.user_invites.find_one({"_id": inv["id"]})
    assert raw not in str(stored) and stored["email"] == "new@example.com"
    assert ms.peek(db, raw, "invite")["role"] == "tester"
    with pytest.raises(UserAdminError):
        ms.create_invite(db, world["lead"], email="x@example.com", role="admin", tenant_id=world["a"])
    with pytest.raises(UserAdminError):
        ms.create_invite(db, world["lead"], email="x@example.com", role="tester", tenant_id=world["b"])
    user = ms.accept_invite(db, raw, username="newbie", password="Another-Good-Pass1")
    assert user["tenant_id"] == world["a"]
    assert db.tenant_memberships.count_documents({"user_id": user["id"], "tenant_id": world["a"]}) == 1
    with pytest.raises(UserAdminError, match="already been used"):
        ms.accept_invite(db, raw, username="newbie2", password="Another-Good-Pass1")
    assert ms.authenticate_password(db, "NEWBIE", "Another-Good-Pass1").user_id == user["id"]
    names = {u["username"] for u in ms.list_users(db, world["lead"])}
    assert "newbie" in names and "tester-b" not in names


def test_reset_role_active_and_last_admin(world):
    from attestra.users import mongo_service as ms
    from attestra.users.service import UserAdminError

    db, admin = world["db"], world["admin"]
    tb = world["tb"]
    inv, raw = ms.create_reset(db, admin, tb["id"])
    ms.complete_reset(db, raw, password="Reset-Password-77")
    assert ms.authenticate_password(db, "tester-b", "Reset-Password-77") is not None
    with pytest.raises(UserAdminError):
        ms.complete_reset(db, raw, password="Reset-Password-78")
    with pytest.raises(LookupError):  # lead of tenant a cannot touch tenant b user
        ms.set_active(db, world["lead"], tb["id"], False)
    ms.set_active(db, admin, tb["id"], False)
    assert ms.authenticate_password(db, "tester-b", "Reset-Password-77") is None
    with pytest.raises(UserAdminError, match="last admin"):
        ms.set_role(db, admin, admin.user_id, "lead")
    with pytest.raises(UserAdminError, match="last admin"):
        ms.disable_by_username(db, admin, "ROOT")
    assert ms.set_role(db, admin, tb["id"], "reviewer")["role"] == "reviewer"


def test_api_keys_and_cli_set_password(world):
    from attestra.users import mongo_service as ms

    db = world["db"]
    row, raw = ms.create_api_key(db, world["tb"])
    assert "key_hash" not in row and raw not in str(db.api_keys.find_one({"_id": row["id"]}))
    p = ms.authenticate_api_key(db, raw)
    assert p.username == "tester-b"
    listed = ms.list_api_keys(db, username="tester-b")
    assert listed[0]["status"] == "active" and listed[0]["last_used_at"]
    ms.revoke_api_key(db, row["id"], actor="root")
    assert ms.authenticate_api_key(db, raw) is None
    assert db.audit_events.count_documents({"action": "api_key.revoke"}) == 1
    ms.set_password(db, "Tester-B", "Brand-New-Pass-42", actor="cli:test")
    assert ms.authenticate_password(db, "tester-b", "Brand-New-Pass-42") is not None


# ---------------------------------------------------------------- settings


def test_settings_repositories(world):
    from attestra.alerts.service import settings_dict
    from attestra.certification.service import format_address
    from attestra.persistence.mongo.repositories import (
        CertificationAuthorityRepository,
        EmailAlertSentRepository,
        EmailAlertSettingsRepository,
    )
    from attestra.persistence.mongo.repositories.settings import as_row
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    db, a, b = world["db"], world["a"], world["b"]
    repo = EmailAlertSettingsRepository(db, tenant_ids=frozenset({a}))
    doc = repo.update(a, actor="lead-a", recipients=["sec@example.com"], notify_sla_missed=False)
    out = settings_dict(as_row(doc), a)
    assert out["recipients"] == ["sec@example.com"] and out["notify_sla_missed"] is False
    assert repo.recipients_for(a, "notify_new_high") == ["sec@example.com"]
    assert repo.recipients_for(a, "notify_sla_missed") == []
    with pytest.raises(TenantAccessDenied):
        repo.get(b)
    sent = EmailAlertSentRepository(db)
    assert sent.mark_sent(a, "sla_missed", "finding", 1) is True
    assert sent.mark_sent(a, "sla_missed", "finding", 1) is False
    ca = CertificationAuthorityRepository(db).update(actor="root", legal_name="Acme CA", city="Pune", country="IN")
    assert format_address(as_row(ca)) == "Pune, IN"
    with pytest.raises(TenantAccessDenied):
        CertificationAuthorityRepository(db, tenant_ids=frozenset({a})).update(actor="x", legal_name="evil")

