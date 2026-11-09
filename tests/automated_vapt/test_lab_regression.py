"""Phase 4 lab regression: fixtures encode expected findings, non-findings and skip reasons.

Fast, offline. Each block pins one behaviour later phases rely on:
WAF challenge noise, header conflicts, session expiry, and the enriched vulnerable app
(JSON id harvest, write bodies, upload, SSRF fetcher) against its secure twin.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from attestra.auth_web.crawl import CrawlResult, FetchResult, crawl
from attestra.auth_web.limits import CrawlLimits
from attestra.auth_web.scope import scope_from_seeds
from attestra.automated_vapt.core.replay_checks import harvest_ids
from attestra.finding_validation.classify import classify_observation
from attestra.finding_validation.headers import hsts_present_in_evidence, permissions_policy_present_in_evidence
from attestra.finding_validation.statuses import INFORMATIONAL, NOT_REPRODUCIBLE, UNVALIDATED
from tests.automated_vapt.conftest import login
from tests.automated_vapt.fixtures import (
    create_header_conflict_app,
    create_secure_app,
    create_session_expiry_app,
    create_vulnerable_app,
    create_waf_challenge_app,
)
from tests.automated_vapt.fixtures.mock_waf_challenge_app import CHALLENGE_SCRIPT_PATH, CLEARANCE_TOKEN

BASE = "http://lab.example.test"


def _raw_headers(resp) -> str:
    return "\n".join(f"{k}: {v}" for k, v in resp.headers.multi_items())


# ---------------------------------------------------------------- WAF challenge


@pytest.fixture
def waf() -> TestClient:
    return TestClient(create_waf_challenge_app(), base_url=BASE)


# @lat: [[tests#Lab fixtures and regression#WAF challenge gates the origin]]
def test_waf_challenge_gates_until_cleared(waf):
    r = waf.get("/")
    assert r.status_code == 403
    assert "Just a moment" in r.text
    assert r.headers.get("cf-mitigated") == "challenge"
    cookies = [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    assert any(c.startswith("cf_clearance=") for c in cookies)
    assert all("samesite" not in c.lower() for c in cookies)
    assert waf.get(CHALLENGE_SCRIPT_PATH).headers["access-control-allow-origin"] == "*"
    cleared = waf.get("/app", cookies={"cf_clearance": CLEARANCE_TOKEN})
    assert cleared.status_code == 200 and "Origin app" in cleared.text


# @lat: [[tests#Lab fixtures and regression#WAF noise classifies informational]]
def test_waf_fixture_noise_classifies_informational(waf):
    r = waf.get("/")
    evidence = _raw_headers(r)
    cookie = classify_observation(
        title="Cookie without SameSite Attribute", param="cf_clearance", location=f"{BASE}/", evidence_texts=[evidence]
    )
    assert cookie["validation_status"] == INFORMATIONAL
    script_url = BASE + CHALLENGE_SCRIPT_PATH
    cache = classify_observation(title="Storable and Cacheable Content", rule_ids=["10049"], location=script_url)
    assert cache["validation_status"] == INFORMATIONAL
    cors = classify_observation(
        title="Cross-Domain Misconfiguration", location=script_url, evidence_texts=["Access-Control-Allow-Origin: *"]
    )
    assert cors["validation_status"] == INFORMATIONAL
    hsts = classify_observation(title="Strict-Transport-Security Header Not Set", location=script_url)
    assert hsts["validation_status"] == INFORMATIONAL


def test_crawler_sees_challenge_not_origin(waf):
    def fetch(url: str) -> FetchResult:
        path = url[len(BASE):] or "/"
        r = waf.get(path)
        return FetchResult(url=url, status_code=r.status_code, body=r.text)

    scope = scope_from_seeds([f"{BASE}/"])
    res: CrawlResult = crawl([f"{BASE}/"], scope, CrawlLimits(max_routes=5, max_depth=1), fetch=fetch, check_dns=False)
    seed = next(r for r in res.records if r.url.rstrip("/") == BASE)
    assert seed.status == "visited" and seed.http_status == 403
    assert any("/cdn-cgi/challenge-platform/" in r.url for r in res.records)
    assert not any(r.url.endswith("/app") for r in res.records)


# ---------------------------------------------------------------- header conflicts


@pytest.fixture
def conflict() -> TestClient:
    return TestClient(create_header_conflict_app(), base_url=BASE)


# @lat: [[tests#Lab fixtures and regression#Header conflicts across paths]]
def test_header_conflict_paths(conflict):
    with_h, without_h = conflict.get("/with-hsts"), conflict.get("/without-hsts")
    assert "strict-transport-security" in with_h.headers
    assert "strict-transport-security" not in without_h.headers
    assert hsts_present_in_evidence([_raw_headers(with_h)])
    assert not hsts_present_in_evidence([_raw_headers(without_h)])
    doc, asset = conflict.get("/"), conflict.get("/static/app.js")
    assert permissions_policy_present_in_evidence([_raw_headers(doc)])
    assert not permissions_policy_present_in_evidence([_raw_headers(asset)])


def test_header_conflict_classification(conflict):
    with_h = _raw_headers(conflict.get("/with-hsts"))
    contradicted = classify_observation(
        title="Strict-Transport-Security Header Not Set", location=f"{BASE}/without-hsts", evidence_texts=[with_h]
    )
    assert contradicted["validation_status"] == NOT_REPRODUCIBLE
    # Same claim with only the failing response as evidence stays open (capped Low).
    without_h = _raw_headers(conflict.get("/without-hsts"))
    open_claim = classify_observation(
        title="Strict-Transport-Security Header Not Set", location=f"{BASE}/without-hsts", evidence_texts=[without_h]
    )
    assert open_claim["validation_status"] == UNVALIDATED and open_claim["severity"] == "low"
    doc = _raw_headers(conflict.get("/"))
    pp = classify_observation(title="Permissions Policy Header Not Set", location=f"{BASE}/static/app.js", evidence_texts=[doc])
    assert pp["validation_status"] == NOT_REPRODUCIBLE
    ping = _raw_headers(conflict.get("/api/ping"))
    cj = classify_observation(title="Missing Anti-clickjacking Header", location=f"{BASE}/api/ping", evidence_texts=[ping])
    assert cj["validation_status"] == NOT_REPRODUCIBLE


# ---------------------------------------------------------------- session expiry


# @lat: [[tests#Lab fixtures and regression#Session expiry after N requests]]
def test_session_expires_after_budget_and_refreshes():
    app = create_session_expiry_app(max_requests=2)
    c = TestClient(app, base_url=BASE)
    login(c, "account_a", "account-a-pass")
    assert app.state.expiry.relogin_count == 1
    assert c.get("/api/me").status_code == 200
    assert c.get("/api/me").status_code == 200
    expired = c.get("/api/me")
    assert expired.status_code == 401 and expired.json()["error"] == "SESSION_EXPIRED"
    html = c.get("/app", follow_redirects=False)
    assert html.status_code == 302 and html.headers["location"].startswith("/login")
    # Refresh on a known (even expired) cookie re-arms the budget; relogin issues a new serial.
    assert c.post("/api/session/refresh").json() == {"refreshed": True}
    assert c.get("/api/me").status_code == 200
    app.state.expiry.force_expire_all()
    assert c.get("/api/projects").status_code == 401
    login(c, "account_a", "account-a-pass")
    assert app.state.expiry.relogin_count == 2
    assert c.get("/api/projects").json()["items"][0]["projectId"] == "proj-a"


def test_session_refresh_unknown_cookie_is_401():
    c = TestClient(create_session_expiry_app(), base_url=BASE)
    assert c.post("/api/session/refresh", cookies={"mock_session": "nope.0"}).status_code == 401
    assert c.get("/api/me").status_code == 401


# ---------------------------------------------------------------- enriched vulnerable vs secure


@pytest.fixture
def vuln() -> TestClient:
    c = TestClient(create_vulnerable_app(), base_url=BASE)
    login(c, "account_a", "account-a-pass")
    return c


@pytest.fixture
def secure() -> TestClient:
    c = TestClient(create_secure_app(), base_url=BASE)
    login(c, "account_a", "account-a-pass")
    return c


# @lat: [[tests#Lab fixtures and regression#JSON list harvest and write bodies]]
def test_json_list_harvest_and_write_bodies(vuln, secure):
    body = vuln.get("/api/projects").text
    ids = harvest_ids(body)
    assert ids["project_id"] == {"proj-a", "proj-b"}
    assert "proj-a" in ids.get("id", set())
    # Secure twin only lists the caller's own projects.
    assert harvest_ids(secure.get("/api/projects").text)["project_id"] == {"proj-a"}

    created = vuln.post("/api/projects", json={"name": "Lab project"})
    assert created.status_code == 201 and created.json()["projectId"].startswith("proj-")
    # Cross-owner PUT succeeds on the vulnerable app (T22 positive control) and 404s on secure.
    assert vuln.put("/api/projects/proj-b", json={"name": "renamed"}).status_code == 200
    assert secure.put("/api/projects/proj-b", json={"name": "renamed"}).status_code == 404
    assert secure.put("/api/projects/proj-a", json={"name": "mine"}).status_code == 200
    assert vuln.post("/api/projects", json={}).status_code == 422
    assert secure.post("/api/projects", json={"name": "x", "id": "proj-b"}).json()["projectId"] == "proj-new"


# @lat: [[tests#Lab fixtures and regression#Upload and SSRF fetcher controls]]
def test_upload_served_verbatim_only_on_vulnerable(vuln, secure):
    anon = TestClient(create_vulnerable_app(), base_url=BASE)
    marker = b"<html>attestra-upload-marker</html>"
    r = anon.post("/api/upload", files={"file": ("probe.html", marker, "text/html")})
    assert r.status_code == 201 and r.json()["url"] == "/uploads/probe.html"
    served = anon.get("/uploads/probe.html")
    assert served.status_code == 200 and served.content == marker
    assert served.headers["content-type"].startswith("text/html")
    anon_secure = TestClient(create_secure_app(), base_url=BASE)
    assert anon_secure.post("/api/upload", files={"file": ("probe.html", marker, "text/html")}).status_code == 401
    assert secure.post("/api/upload", files={"file": ("probe.html", marker, "text/html")}).status_code == 403


def test_ssrf_fetcher_reaches_internal_only_on_vulnerable(vuln, secure):
    r = vuln.get("/api/fetch", params={"url": "http://169.254.169.254/latest/meta-data/?token=cnry123"})
    assert r.status_code == 200
    assert "internal-service-banner" in r.json()["body"] and "canary=cnry123" in r.json()["body"]
    ext = vuln.get("/api/fetch", params={"url": "https://canary.example.test/x?token=cnry999"})
    assert "canary=cnry999" in ext.json()["body"]
    assert vuln.get("/api/fetch", params={"url": "not a url"}).status_code == 400
    assert secure.get("/api/fetch", params={"url": "http://169.254.169.254/"}).status_code == 400
    assert secure.get("/api/fetch", params={"url": "https://cdn.example.test/a.js"}).status_code == 200
