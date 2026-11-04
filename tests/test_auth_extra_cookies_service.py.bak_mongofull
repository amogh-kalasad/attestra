"""Extra Cookies persistence: encrypted via the credential store; names only in row / audit / UI dict."""
from __future__ import annotations

import pytest

from tests.test_auth_scan_queue import _lead, auth_env  # noqa: F401 - fixture re-export


def _audit_text(s, action):
    from attestra.models import AuditEvent

    ev = s.query(AuditEvent).filter(AuditEvent.action == action).all()
    assert ev
    return str([getattr(e, "detail", None) or getattr(e, "details", None) for e in ev])


def test_create_update_clear_extra_cookies(engagement, auth_env):  # noqa: F811
    from attestra import credentials, db, services
    from attestra.auth_web import profiles

    with db.session() as s:
        p = _lead(s, engagement)
        row = profiles.create_profile(
            s, engagement, label="api", method="header", config_json={"header_name": "Authorization"},
            secret_value="tok-value", extra_cookies="refreshToken=RTSECRETVALUE1",
            principal=p, actor="lead",
        )
        s.commit()
        assert row.extra_cookies_ref and "RTSECRETVALUE1" not in row.extra_cookies_ref
        assert row.extra_cookie_names == "refreshToken"
        assert credentials.get_secret(row.extra_cookies_ref) == "refreshToken=RTSECRETVALUE1"
        d = profiles.profile_dict(row)
        assert d["has_extra_cookies"] is True and d["extra_cookie_names"] == ["refreshToken"]
        assert "RTSECRETVALUE1" not in str(d)
        assert "RTSECRETVALUE1" not in _audit_text(s, "auth_profile.create")

        ref1 = row.extra_cookies_ref
        profiles.update_extra_cookies(s, engagement, row.id, extra_cookies="refreshToken=NEWVALUE22; b=BVALUE33", principal=p)
        s.commit()
        assert row.extra_cookies_ref == ref1  # rotated in place
        assert credentials.get_secret(ref1) == "refreshToken=NEWVALUE22; b=BVALUE33"
        assert row.extra_cookie_names == "refreshToken, b"
        at = _audit_text(s, "auth_profile.extra_cookies")
        assert "NEWVALUE22" not in at and "BVALUE33" not in at and "refreshToken" in at

        with pytest.raises(services.ServiceError) as ei:
            profiles.update_extra_cookies(s, engagement, row.id, extra_cookies="bad name=SECRETX99", principal=p)
        assert "SECRETX99" not in str(ei.value)
        assert row.extra_cookie_names == "refreshToken, b"  # unchanged after a rejected update

        profiles.update_extra_cookies(s, engagement, row.id, extra_cookies="", principal=p)
        s.commit()
        assert row.extra_cookies_ref == "" and row.extra_cookie_names == ""
        with pytest.raises(Exception):
            credentials.get_secret(ref1)  # ciphertext destroyed on clear


def test_rejects_bad_input_and_method_none(engagement, auth_env):  # noqa: F811
    from attestra import db, services
    from attestra.auth_web import profiles

    with db.session() as s:
        p = _lead(s, engagement)
        with pytest.raises(services.ServiceError):
            profiles.create_profile(s, engagement, label="n", method="none", extra_cookies="a=1", principal=p)
        with pytest.raises(services.ServiceError):
            profiles.create_profile(
                s, engagement, label="c", method="cookie", config_json={"cookie_name": "sid"},
                secret_value="v", extra_cookies="sid=dup", principal=p,
            )
        with pytest.raises(services.ServiceError):
            profiles.create_profile(
                s, engagement, label="m", method="header", secret_value="v",
                extra_cookies="; ".join(f"c{i}=v" for i in range(11)), principal=p,
            )


def test_delete_profile_destroys_extra_cookie_secret(engagement, auth_env):  # noqa: F811
    from attestra import credentials, db
    from attestra.auth_web import profiles

    with db.session() as s:
        p = _lead(s, engagement)
        row = profiles.create_profile(
            s, engagement, label="d", method="header", secret_value="tok", extra_cookies="r=VALUE1234", principal=p,
        )
        s.commit()
        ref = row.extra_cookies_ref
        profiles.delete_profile(s, engagement, row.id, principal=p)
        s.commit()
        with pytest.raises(Exception):
            credentials.get_secret(ref)
