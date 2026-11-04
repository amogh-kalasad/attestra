"""Extra Headers persistence: create/update via the profile service (validation, audit names only)."""
from __future__ import annotations

import pytest

from tests.test_auth_scan_queue import _lead, auth_env  # noqa: F401 - fixture re-export


def test_create_and_update_extra_headers(engagement, auth_env):  # noqa: F811
    from attestra import db, services
    from attestra.auth_web import profiles
    from attestra.models import AuditEvent

    with db.session() as s:
        p = _lead(s, engagement)
        row = profiles.create_profile(
            s, engagement, label="api", method="header", config_json={"header_name": "Authorization"},
            secret_value="tok-value", extra_headers=" x-portal-host :  stage.example.com \n\n",
            principal=p, actor="lead",
        )
        s.commit()
        assert row.extra_headers == "x-portal-host: stage.example.com"
        assert profiles.profile_dict(row)["extra_headers"] == "x-portal-host: stage.example.com"

        profiles.update_extra_headers(s, engagement, row.id, extra_headers="X-Tenant-Id: t1", principal=p)
        s.commit()
        assert row.extra_headers == "X-Tenant-Id: t1"
        ev = s.query(AuditEvent).filter(AuditEvent.action == "auth_profile.extra_headers").all()
        assert ev and "t1" not in str([getattr(e, "detail", None) or getattr(e, "details", None) for e in ev])

        with pytest.raises(services.ServiceError):
            profiles.update_extra_headers(s, engagement, row.id, extra_headers="Authorization: Bearer x", principal=p)
        with pytest.raises(services.ServiceError):
            profiles.create_profile(
                s, engagement, label="bad", method="header", secret_value="t",
                extra_headers="Cookie: a=b", principal=p,
            )
        profiles.update_extra_headers(s, engagement, row.id, extra_headers="", principal=p)
        s.commit()
        assert row.extra_headers == ""


def test_own_named_header_is_rejected(engagement, auth_env):  # noqa: F811
    from attestra import db, services
    from attestra.auth_web import profiles

    with db.session() as s:
        p = _lead(s, engagement)
        with pytest.raises(services.ServiceError):
            profiles.create_profile(
                s, engagement, label="k", method="header", config_json={"header_name": "X-Api-Key"},
                secret_value="t", extra_headers="x-api-key: other", principal=p,
            )
