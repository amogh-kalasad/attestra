"""API key and password hashing tests."""
# @lat: [[tests#Phase 2 auth tests#tests/auth/test_keys.py]]

from __future__ import annotations


def test_hash_api_key_never_equals_raw(fresh_db):
    from attestra.auth.keys import generate_api_key, hash_api_key

    raw = generate_api_key()
    assert hash_api_key(raw) != raw
    assert len(hash_api_key(raw)) == 64


def test_revoked_key_fails(fresh_db):
    from attestra import db
    from attestra.auth.keys import authenticate_api_key, create_api_key, create_user, revoke_api_key

    with db.session() as s:
        user = create_user(s, username="kuser", role="tester", password="pw-kuser-1")
        row, raw = create_api_key(s, user)
        assert authenticate_api_key(s, raw) is not None
        revoke_api_key(s, row.id)
        assert authenticate_api_key(s, raw) is None


def test_password_roundtrip(fresh_db):
    from attestra import db
    from attestra.auth.keys import authenticate_password, create_user

    with db.session() as s:
        create_user(s, username="alice", role="lead", password="s3cret-alice")
        assert authenticate_password(s, "alice", "s3cret-alice") is not None
        assert authenticate_password(s, "alice", "wrong") is None


def test_four_eyes_by_user_id(fresh_db, loaded):
    import pytest

    from attestra import db
    from attestra.auth.keys import create_user
    from attestra.reports import approve_report, generate_report
    from attestra.services import ServiceError

    with db.session() as s:
        author = create_user(s, username="author1", role="tester", password="pw-author-1")
        other = create_user(s, username="other1", role="reviewer", password="pw-other-1")
        r = generate_report(s, loaded, kind="technical", actor=author.username, user_id=author.id)
        rid = r.id
        with pytest.raises(ServiceError, match="four-eyes"):
            approve_report(s, rid, actor="spoofed-name", user_id=author.id)
        signed = approve_report(s, rid, actor=other.username, user_id=other.id)
        assert signed.status == "signed"
