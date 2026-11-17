"""C-04: imported inventory feeds capture (GET/HEAD only) and spec coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.automated_vapt.api_inventory import compute_coverage, parse_spec
from attestra.automated_vapt.core.capture_urls import build_capture_urls
from attestra.automated_vapt.core.js_api_discovery import endpoints_from_inventory

SPECS = Path(__file__).parent / "fixtures" / "api_specs"
ROOT = "https://app.example.test/"


def _inv(name="openapi3.json"):
    return parse_spec((SPECS / name).read_bytes(), name, allowed_origins=[ROOT])


def test_disabled_flag_merges_nothing(monkeypatch):
    monkeypatch.delenv("ATTESTRA_API_IMPORT_ENABLED", raising=False)
    info: dict = {}
    urls, source = build_capture_urls(session=None, asset=None, target_base_url=ROOT, info=info, api_inventory=_inv())
    assert urls == [ROOT] and "+spec" not in source
    assert info["api_inventory"] == {"merged": 0, "disabled": True}


def test_mutating_and_templated_ops_never_enter_capture(monkeypatch):
    monkeypatch.setenv("ATTESTRA_API_IMPORT_ENABLED", "1")
    info: dict = {}
    urls, source = build_capture_urls(session=None, asset=None, target_base_url=ROOT, info=info, api_inventory=_inv())
    assert source.endswith("+spec")
    assert "https://app.example.test/api/users" in urls
    assert "https://app.example.test/api/health" in urls
    assert not any("{" in u or u.endswith("/import") for u in urls)
    counts = info["api_inventory"]
    assert counts["excluded_mutating"] == 3 and counts["excluded_templated"] == 1
    assert set(info["api_urls"]) <= set(urls)


def test_out_of_scope_servers_excluded(monkeypatch):
    monkeypatch.setenv("ATTESTRA_API_IMPORT_ENABLED", "1")
    info: dict = {}
    urls, _ = build_capture_urls(session=None, asset=None, target_base_url=ROOT, info=info, api_inventory=_inv("postman.json"))
    assert not any("evil.example.org" in u for u in urls)
    assert info["api_inventory"]["out_of_scope"] >= 1


def test_spec_coverage_tested_vs_untested(monkeypatch):
    monkeypatch.setenv("ATTESTRA_API_IMPORT_ENABLED", "1")
    inv = _inv()
    cov = compute_coverage(inv, ["https://app.example.test/api/users"], root=ROOT)
    assert cov["present"] is True and cov["tested"] == 1
    assert cov["untested"] == 2  # /health and /ext
    assert cov["excluded_mutating"] == 3 and cov["excluded_templated"] == 1
    statuses = {(r["method"], r["path"]): r["status"] for r in cov["operations"]}
    assert statuses[("DELETE", "/users/{id}")] == "excluded_mutating"
    assert compute_coverage(None, []) == {"present": False}


def test_inventory_endpoints_never_capture_safe_when_mutating():
    eps = {(e.path, tuple(sorted(e.methods))): e for e in endpoints_from_inventory(_inv().operations)}
    assert all(e.source == "spec" for e in eps.values())
    post = eps[("/users", ("GET", "POST"))]
    assert not post.capture_safe and not post.gettable
    tmpl = eps[("/users/{id}", ("DELETE", "GET"))]
    assert tmpl.path_param and not tmpl.capture_safe


@pytest.mark.parametrize("path,expected", [("/graphql", True), ("/api/graphql", True), ("/api/graphqlx", False), ("/api/users", False)])
def test_graphql_tag(path, expected):
    from attestra.automated_vapt.core.js_api_discovery import ApiEndpoint

    ep = ApiEndpoint(path=path, methods={"POST"})
    assert ep.graphql is expected and ep.to_dict()["graphql"] is expected
