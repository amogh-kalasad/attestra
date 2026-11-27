"""Customer self-service registration and welcome email."""
# @lat: [[interfaces#Customer self-service registration]]

from __future__ import annotations

from email.message import EmailMessage

import pytest

from attestra.users import mailer
from attestra.users import registration as reg
from attestra.users.service import UserAdminError, MIN_PASSWORD_LENGTH


@pytest.fixture
def enable_signup(monkeypatch):
    monkeypatch.setenv("ATTESTRA_CUSTOMER_SELF_SERVICE_REGISTRATION", "1")


@pytest.fixture
def captured_mail(monkeypatch):
    sent: list[EmailMessage] = []

    def _deliver(msg: EmailMessage) -> None:
        sent.append(msg)

    mailer.set_deliver(_deliver)
    yield sent
    mailer.set_deliver(None)


def test_flag_off_blocks_register(monkeypatch):
    monkeypatch.setenv("ATTESTRA_CUSTOMER_SELF_SERVICE_REGISTRATION", "0")
    assert reg.self_service_registration_enabled() is False


def test_welcome_email_content(captured_mail, monkeypatch):
    monkeypatch.setenv("ATTESTRA_PUBLIC_URL", "http://127.0.0.1:8000")
    ok = mailer.send_welcome(
        "owner@example.com",
        username="jordan.lead",
        organization_name="Acme Co",
        display_name="Jordan",
    )
    assert ok is True
    assert len(captured_mail) == 1
    msg = captured_mail[0]
    assert msg["Subject"] == "Welcome to Attestra"
    body = msg.get_body(preferencelist=("plain",)).get_content()
    assert "jordan.lead" in body
    assert "Acme Co" in body
    assert "http://127.0.0.1:8000/login" in body
    assert "password" not in body.lower() or "Password updated" not in body


def test_register_customer_success_and_login_role(mongo_test_db, enable_signup, captured_mail, monkeypatch):
    monkeypatch.setenv("ATTESTRA_PUBLIC_URL", "http://example.test")
    out = reg.register_customer(
        mongo_test_db,
        username="self.customer1",
        password="LiveTest-Own-12345",
        email="self.customer1@example.com",
        organization_name="Self Service Org One",
        display_name="Self Customer",
        contact_name="Self Customer",
    )
    user = out["user"]
    tenant = out["tenant"]
    assert user["role"] == "lead"
    assert user["role"] != "admin"
    assert int(user["tenant_id"]) == int(tenant["id"])
    assert tenant["name"] == "Self Service Org One"
    assert tenant["contact_email"] == "self.customer1@example.com"
    assert tenant.get("plan") == "standard"
    assert out["emailed"] is True
    assert captured_mail and "Welcome to Attestra" in captured_mail[0]["Subject"]

    # Password auth works
    from attestra.users import mongo_service

    principal = mongo_service.authenticate_password(mongo_test_db, "self.customer1", "LiveTest-Own-12345")
    assert principal is not None
    assert principal.role == "lead"
    assert principal.tenant_id == tenant["id"]


def test_register_duplicate_username(mongo_test_db, enable_signup, captured_mail):
    reg.register_customer(
        mongo_test_db,
        username="self.dupuser",
        password="LiveTest-Own-12345",
        email="dupuser1@example.com",
        organization_name="Dup User Org A",
    )
    with pytest.raises(UserAdminError, match="username is taken"):
        reg.register_customer(
            mongo_test_db,
            username="self.dupuser",
            password="LiveTest-Own-12345",
            email="dupuser2@example.com",
            organization_name="Dup User Org B",
        )


def test_register_duplicate_org(mongo_test_db, enable_signup, captured_mail):
    reg.register_customer(
        mongo_test_db,
        username="self.orgdup1",
        password="LiveTest-Own-12345",
        email="orgdup1@example.com",
        organization_name="Shared Org Name LLC",
    )
    with pytest.raises(UserAdminError, match="organization name"):
        reg.register_customer(
            mongo_test_db,
            username="self.orgdup2",
            password="LiveTest-Own-12345",
            email="orgdup2@example.com",
            organization_name="Shared Org Name LLC",
        )


def test_register_invalid_password(mongo_test_db, enable_signup):
    with pytest.raises(UserAdminError):
        reg.register_customer(
            mongo_test_db,
            username="self.weak",
            password="short",
            email="weak@example.com",
            organization_name="Weak Pass Org",
        )
    assert MIN_PASSWORD_LENGTH >= 12


def test_register_invalid_email(mongo_test_db, enable_signup):
    with pytest.raises(UserAdminError, match="email"):
        reg.register_customer(
            mongo_test_db,
            username="self.bademail",
            password="LiveTest-Own-12345",
            email="not-an-email",
            organization_name="Bad Email Org",
        )


def test_credits_allocate_still_admin_only():
    """Self-registered leads must not gain credits.allocate (subscription change)."""
    from attestra.auth.roles import has_permission

    assert has_permission("lead", "credits.allocate") is False
    assert has_permission("admin", "credits.allocate") is True
