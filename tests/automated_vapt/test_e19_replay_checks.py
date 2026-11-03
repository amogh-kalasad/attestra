"""E19: T19 auth-bypass / T20 IDOR / T21 input-validation replay checks (mocked HTTP)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from attestra.automated_vapt.core import js_api_discovery as jsd
from attestra.automated_vapt.core import replay_checks as rc
from attestra.automated_vapt.core.session_auth import SessionAuth
from attestra.automated_vapt.core.test_registry import get_test_case
from attestra.proof.pair import HttpPair

ROOT = "https://demo.example/"


def _pair(url: str, status: int, body: str, *, auth_header: str | None = None) -> HttpPair:
    req = {"user-agent": "test"}
    if auth_header:
        req["authorization"] = auth_header
    return HttpPair(
        method="GET",
        url=url,
        request_headers=req,
        request_body="",
        status=status,
        response_headers={"content-type": "application/json"},
        response_body=body,
        source="test",
    )


class FakeTx:
    def __init__(self, pair: HttpPair):
        self.pair = pair
        self.report_pair = pair.redacted()


def _ctx(*, auth_status: str = "ready", endpoints=None, api_urls=None, responses=None):
    """Build a TestContext-like object; ``responses`` maps url -> list of (status, body) per call."""
    auth = SessionAuth(
        profile_id=2,
        status=auth_status,
        note="login check passed" if auth_status == "ready" else "login check got HTTP 401",
        headers={"Authorization": "Bearer SECRETtokenXYZ"} if auth_status == "ready" else {},
        redact_values=("SECRETtokenXYZ",),
    )
    eps = endpoints or []
    return SimpleNamespace(
        target_base_url=ROOT,
        profile="baseline",
        allow_private=True,  # skip DNS in unit tests
        engagement_id=1,
        extra={
            "_session_auth": auth,
            "_capture_api_urls": list(api_urls or []),
            "_js_api": {
                "endpoints_list": [e.to_dict() if isinstance(e, jsd.ApiEndpoint) else e for e in eps],
            },
            "_http_pairs": [],
            # responses consumed by the patched capture_request below
            "_fake_responses": dict(responses or {}),
        },
    )


@pytest.fixture
def patch_capture(monkeypatch):
    """Replace capture_request with a queue that walks a per-URL response queue."""

    def install(ctx):
        queues = {u: list(v) for u, v in ctx.extra["_fake_responses"].items()}

        def fake_capture(method, url, **kwargs):
            assert method == "GET"
            # never leak the real secret into assertions via kwargs logging — just use it
            hdrs = kwargs.get("headers") or {}
            q = queues.setdefault(url, [])
            if not q:
                status, body = 404, '{"status":"error"}'
            else:
                status, body = q.pop(0)
            auth_h = hdrs.get("Authorization") or hdrs.get("authorization")
            return FakeTx(_pair(url, status, body, auth_header=auth_h))

        monkeypatch.setattr(
            "attestra.automated_vapt.capture.http_capture.capture_request",
            fake_capture,
        )
        return queues

    return install


def _ep(path, *, methods=("GET",), dynamic=False, path_param=False, query_keys=()):
    return jsd.ApiEndpoint(
        path=path,
        methods=set(methods),
        dynamic=dynamic,
        path_param=path_param,
        query_keys=set(query_keys),
    )


# ------------------------------------------------------------------ helpers unit tests


def test_registry_lists_t19_t20_t21():
    for tid in ("T19", "T20", "T21", "T22"):
        assert get_test_case(tid) is not None

def test_harvest_ids_and_neighbours():
    body = '{"status":"Success","data":[{"project_id":10,"name":"A"},{"project_id":12,"name":"B"}],"clientId":"c1"}'
    got = rc.harvest_ids(body)
    assert got["project_id"] == {"10", "12"}
    assert got["client_id"] == {"c1"}  # camelCase normalized
    n = rc.neighbour_ids({"10", "12"}, span=1)
    assert "9" in n and "11" in n and "13" in n
    assert "10" not in n and "12" not in n


def test_responses_similar_rejects_spa_and_empty():
    auth = rc.CaptureResult(url=ROOT, status=200, body='{"status":"Success","data":[{"project_id":1}]}')
    assert auth.substantive
    spa = rc.CaptureResult(url=ROOT, status=200, body="<!doctype html><html><body>app</body></html>")
    assert not spa.substantive
    empty = rc.CaptureResult(url=ROOT, status=200, body='{"status":"Success","data":[]}')
    assert not empty.substantive
    unauth_data = rc.CaptureResult(
        url=ROOT, status=200, body='{"status":"Success","data":[{"project_id":1},{"project_id":2}]}'
    )
    assert rc.responses_similar(auth, unauth_data)
    denied = rc.CaptureResult(url=ROOT, status=401, body='{"message":"Unauthorized"}')
    assert not rc.responses_similar(auth, denied)


def test_input_finding_detects_5xx_stack_and_xss():
    assert rc.input_finding(500, "oops", "x")[0]
    assert rc.input_finding(200, "Traceback (most recent call last):\n File", "x")[0]
    assert rc.input_finding(200, "PG::SyntaxError: ERROR:  syntax error at", "x")[0]
    ok, _ = rc.input_finding(200, f"hello {rc._REFLECT_SCRIPT} world", rc._REFLECT_SCRIPT)
    assert ok
    assert not rc.input_finding(200, '{"ok":true}', "'")[0]


# ------------------------------------------------------------------ T19


def test_t19_skips_when_auth_not_ready(patch_capture):
    ctx = _ctx(auth_status="failed", api_urls=[ROOT + "api/projects/get-projects-overview"])
    patch_capture(ctx)
    out = rc.run_auth_bypass(ctx, sleep_s=0)
    assert out["status"] == "SKIPPED"
    assert out["validation"] == {}


def test_t19_finding_when_no_auth_returns_data(patch_capture):
    url = ROOT + "api/projects/get-projects-overview"
    body = '{"status":"Success","data":[{"project_id":1,"name":"Alpha"}]}'
    ctx = _ctx(
        api_urls=[url],
        responses={
            # auth baseline, no-auth probe, invalid-token probe
            url: [(200, body), (200, body), (401, '{"message":"Unauthorized"}')],
        },
    )
    patch_capture(ctx)
    out = rc.run_auth_bypass(ctx, sleep_s=0)
    assert out["status"] == "FINDING"
    assert out["finding_count"] == 1
    assert out["validation"]["status"] == "CONFIRMED"
    assert out["validation"]["cwe"] == 287
    assert out["endpoints"][0]["finding"] is True
    assert out["endpoints"][0]["meta"]["probe"] == "no_auth"
    # evidence pairs present and redacted (no raw secret)
    assert out["evidence_pairs"]
    blob = str(out["evidence_pairs"][0].request_headers)
    assert "SECRETtokenXYZ" not in blob


def test_t19_passed_when_auth_required(patch_capture):
    url = ROOT + "api/admin/get-all-clients"
    body = '{"status":"Success","data":[{"client_id":1}]}'
    ctx = _ctx(
        api_urls=[url],
        responses={
            url: [
                (200, body),
                (401, '{"message":"Unauthorized"}'),
                (401, '{"message":"Unauthorized"}'),
            ],
        },
    )
    patch_capture(ctx)
    out = rc.run_auth_bypass(ctx, sleep_s=0)
    assert out["status"] == "PASSED"
    assert out["finding_count"] == 0
    assert out["endpoints"][0]["status"] == "PASSED"


# ------------------------------------------------------------------ T20


def test_t20_finding_on_foreign_id(patch_capture):
    overview = ROOT + "api/projects/get-projects-overview"
    risks_owned = ROOT + "api/projects/get-projects-risks/10"
    risks_foreign = ROOT + "api/projects/get-projects-risks/11"
    overview_body = '{"status":"Success","data":[{"project_id":10,"name":"Mine"}]}'
    risks_body = '{"status":"Success","data":[{"project_id":10,"risk":"x"}]}'
    foreign_body = '{"status":"Success","data":[{"project_id":11,"risk":"other"}]}'
    ep = _ep("/api/projects/get-projects-risks", dynamic=True, path_param=True)
    ctx = _ctx(
        api_urls=[overview],
        endpoints=[ep, _ep("/api/projects/get-projects-overview")],
        responses={
            overview: [(200, overview_body)],
            risks_owned: [(200, risks_body)],
            risks_foreign: [(200, foreign_body)],
        },
    )
    patch_capture(ctx)
    out = rc.run_idor(ctx, sleep_s=0, cap=20)
    assert out["status"] == "FINDING"
    assert out["validation"]["status"] == "POTENTIAL"
    assert out["validation"]["cwe"] == 639
    assert out["harvested_count"] >= 1
    assert any(e["finding"] for e in out["endpoints"])


def test_t20_passed_when_foreign_denied(patch_capture):
    overview = ROOT + "api/projects/get-projects-overview"
    risks_owned = ROOT + "api/projects/get-projects-risks/5"
    overview_body = '{"status":"Success","data":[{"project_id":5}]}'
    risks_body = '{"status":"Success","data":[{"project_id":5,"risk":"x"}]}'
    ep = _ep("/api/projects/get-projects-risks", dynamic=True, path_param=True)
    # every foreign neighbour returns 403
    responses = {
        overview: [(200, overview_body)],
        risks_owned: [(200, risks_body)],
    }
    for n in (2, 3, 4, 6, 7, 8):
        responses[ROOT + f"api/projects/get-projects-risks/{n}"] = [
            (403, '{"message":"Forbidden"}')
        ]
    ctx = _ctx(api_urls=[overview], endpoints=[ep], responses=responses)
    patch_capture(ctx)
    out = rc.run_idor(ctx, sleep_s=0, cap=20)
    assert out["status"] == "PASSED"
    assert out["finding_count"] == 0


# ------------------------------------------------------------------ T21


def test_t21_finding_on_500_and_stack(patch_capture):
    search = ROOT + "api/admin/search?q=1"
    boom = ROOT + "api/admin/search?q=%27"  # urlencoded single quote — capture uses raw payload URL
    ep = _ep("/api/admin/search", dynamic=True, query_keys=["q"])
    # The probe URL is built with urlencode, so quote becomes %27
    from urllib.parse import urlencode

    probe = ROOT + "api/admin/search?" + urlencode([("q", "'")])
    ctx = _ctx(
        api_urls=[],  # force path via endpoints only; owned id harvest skipped
        endpoints=[ep],
        responses={
            search: [(200, '{"status":"Success","data":[]}')],
            probe: [(500, "Traceback (most recent call last):\n File /app/db.py")],
        },
    )
    patch_capture(ctx)
    out = rc.run_input_validation(ctx, sleep_s=0, cap=20)
    assert out["status"] == "FINDING"
    assert out["validation"]["status"] == "CONFIRMED"
    assert out["validation"]["cwe"] == 20
    assert any(e["finding"] for e in out["endpoints"])


def test_t21_passed_when_clean(patch_capture):
    from urllib.parse import urlencode

    ep = _ep("/api/admin/search", dynamic=True, query_keys=["q"])
    seed = ROOT + "api/admin/search?q=1"
    responses = {seed: [(200, '{"status":"Success","data":[]}')]}
    for _label, payload in rc.INPUT_PAYLOADS:
        responses[ROOT + "api/admin/search?" + urlencode([("q", payload)])] = [
            (400, '{"message":"bad request"}')
        ]
    ctx = _ctx(api_urls=[], endpoints=[ep], responses=responses)
    patch_capture(ctx)
    out = rc.run_input_validation(ctx, sleep_s=0, cap=30)
    assert out["status"] == "PASSED"
    assert out["finding_count"] == 0


def test_t21_skips_without_auth(patch_capture):
    ctx = _ctx(auth_status="failed", endpoints=[_ep("/api/admin/search", query_keys=["q"])])
    patch_capture(ctx)
    out = rc.run_input_validation(ctx, sleep_s=0)
    assert out["status"] == "SKIPPED"
