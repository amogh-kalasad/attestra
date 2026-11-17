"""D-01 session lifecycle (SESSLIFE) and D-02 wiring into SESSION."""

from __future__ import annotations

import base64
import json

from fastapi.testclient import TestClient

from attestra.automated_vapt.core.response_classifier import ResponseClass as RC
from attestra.automated_vapt.testing import session_lifecycle as sl
from tests.automated_vapt.fixtures import create_secure_app, create_session_expiry_app

BASE = "http://localhost:8765/"


# @lat: [[run-validity-and-policy#Session lifecycle]]
def test_assess_rotation_pure():
    assert sl.assess_rotation({"sessionid": "a"}, {"sessionid": "b"})["result"] == sl.ROTATED
    assert sl.assess_rotation({"sessionid": "a"}, {"sessionid": "a"})["result"] == sl.NOT_ROTATED
    assert sl.assess_rotation({}, {})["result"] == sl.NOT_ASSESSED
    # Values never appear in the result.
    assert "secretval" not in json.dumps(sl.assess_rotation({"sid": "secretval"}, {"sid": "secretval"}))


def test_assess_logout_pure():
    assert sl.assess_logout(RC.APP_OK)["result"] == sl.NOT_INVALIDATED
    assert sl.assess_logout(RC.AUTH_REDIRECT)["result"] == sl.INVALIDATED
    assert sl.assess_logout(RC.WAF_BLOCK)["result"] == sl.NOT_ASSESSED


def test_cookie_lifetime_and_expiry_posture():
    assert sl.cookie_lifetime_s("sid=x; Max-Age=60; Path=/") == 60
    assert sl.cookie_lifetime_s("sid=x; Path=/") is None
    post = sl.expiry_posture(["sessionid=x; Max-Age=99999999", "theme=dark; Max-Age=99999999"])
    assert post["long_lived_session_cookies"] == ["sessionid"]
    assert [c["name"] for c in post["session_cookies"]] == ["sessionid"]


def test_lab_good_app_rotates_and_invalidates():
    client = TestClient(create_session_expiry_app(max_requests=50), base_url=BASE)
    r = sl.run(client, BASE)
    obs = r["observations"]
    assert obs["rotation"]["result"] == sl.ROTATED, obs
    assert obs["logout"]["result"] == sl.INVALIDATED, obs
    assert r["finding_candidate"] is False


def test_lab_static_cookie_app_is_flagged():
    # Common mock sets mock_session=<username> on every login and only clears the client cookie on logout.
    client = TestClient(create_secure_app(), base_url=BASE)
    r = sl.run(client, BASE)
    assert r["finding_candidate"] is True
    assert r["observations"]["rotation"]["result"] == sl.NOT_ROTATED


def test_engagement_mode_is_passive_and_never_passes():
    from types import SimpleNamespace

    from attestra.automated_vapt.core.session_auth import SessionAuth
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    calls: list[str] = []

    def h(request):
        calls.append(f"{request.method} {request.url.path}")
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/{p:path}", h, methods=["GET", "POST"])])
    client = TestClient(app, base_url="http://app.test/")
    auth = SessionAuth(profile_id=7, status="ready", note="t", headers={"Authorization": "Bearer tok-abc"}, redact_values=("tok-abc",))
    ctx = SimpleNamespace(extra={"httpx_client": client, "_session_auth": auth, "_capture_urls": ["http://app.test/dash"]})
    r = sl.run(client, "http://app.test/", ctx=ctx)
    assert r["observations"]["identity"] == "profile#7"
    assert r["observations"]["logout"]["result"] == sl.NOT_ASSESSED
    assert r.get("status_hint") == "INCONCLUSIVE" and r.get("skip_reason")
    assert not any("logout" in c or c.startswith("POST") for c in calls)
    assert "tok-abc" not in json.dumps(r, default=str)


def test_no_session_is_not_tested():
    import httpx

    with httpx.Client() as raw:
        r = sl.run(raw, "http://127.0.0.1:9/")
    assert r["status_hint"] == "NOT_TESTED"


def _jwt(payload: dict, alg: str = "HS256") -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': alg, 'typ': 'JWT'})}.{enc(payload)}.c2ln"


def test_session_module_reports_jwt_posture():
    from types import SimpleNamespace

    from attestra.automated_vapt.core.session_auth import SessionAuth
    from attestra.automated_vapt.testing import session_security_tests
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    tok = _jwt({"sub": "u1"})  # no exp: high-severity posture issue
    app = Starlette(routes=[Route("/{p:path}", lambda r: JSONResponse({}), methods=["GET"])])
    client = TestClient(app, base_url="http://app.test/")
    auth = SessionAuth(profile_id=1, status="ready", note="t", headers={"Authorization": f"Bearer {tok}"}, redact_values=(tok,))
    ctx = SimpleNamespace(extra={"httpx_client": client, "_session_auth": auth, "_capture_urls": ["http://app.test/a"]})
    r = session_security_tests.run(client, "http://app.test/", ctx=ctx)
    assert "missing_exp" in r["observations"]["jwt_posture"]["high_issues"]
    assert r["finding_candidate"] is True
    assert tok not in json.dumps(r["observations"], default=str)
