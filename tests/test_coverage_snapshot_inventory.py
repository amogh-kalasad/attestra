"""Unit tests for coverage snapshot endpoint unions (crawl, ledger, ZAP, JS)."""

from attestra.automated_vapt.coverage.snapshot import (
    _authenticated_endpoint_keys,
    _endpoint_sets,
    _js_paths_from_cache,
    _ledger_status_tested,
    _normalize_endpoint,
)


class _Route:
    def __init__(self, url, status="discovered", authenticated=False):
        self.url = url
        self.status = status
        self.authenticated = authenticated


def test_normalize_drops_host_query_and_slash():
    assert _normalize_endpoint("https://my.harmonypm.ai/admin/?x=1#y") == "/admin"
    assert _normalize_endpoint("/api/foo/") == "/api/foo"
    assert _normalize_endpoint("api/bar") == "/api/bar"
    assert _normalize_endpoint("/") == "/"
    assert _normalize_endpoint("") == ""
    assert _normalize_endpoint("   ") == ""


def test_endpoint_sets_unions_all_sources():
    discovered, tested = _endpoint_sets(
        routes=[_Route("https://ex.com/only-crawl", "discovered")],
        ledger_rows=[
            {"target_endpoint": "https://ex.com/api/a", "execution_status": "PASSED"},
            {"target_endpoint": "https://ex.com/api/b", "execution_status": "SKIPPED"},
            {"target_endpoint": "", "execution_status": "PASSED"},  # case-level, ignore
        ],
        zap_urls={"/page", "/api/a"},
        js_paths={"/api/c", "/api/b"},
    )
    assert "/only-crawl" in discovered and "/only-crawl" not in tested
    assert "/api/a" in tested  # ledger PASSED and ZAP
    assert "/api/b" in discovered and "/api/b" not in tested  # SKIPPED + JS
    assert "/page" in tested  # ZAP requested
    assert "/api/c" in discovered and "/api/c" not in tested  # JS only
    assert "" not in discovered


def test_ledger_failed_and_finding_count_as_tested():
    assert _ledger_status_tested({"execution_status": "FAILED"})
    assert _ledger_status_tested({"execution_status": "FINDING"})
    assert not _ledger_status_tested({"execution_status": "SKIPPED"})
    assert not _ledger_status_tested({"execution_status": "DEFERRED"})
    assert not _ledger_status_tested({"execution_status": "BLOCKED"})


def test_js_paths_from_cache_shapes():
    assert _js_paths_from_cache({"endpoints": [{"path": "/api/x"}, {"url": "https://h/y"}]}) == {
        "/api/x",
        "/y",
    }
    assert _js_paths_from_cache(["/z/", {"path": "/w"}]) == {"/z", "/w"}
    assert _js_paths_from_cache(None) == set()


def test_authenticated_keys_from_zap_and_ledger():
    routes = [_Route("https://ex.com/a", authenticated=True)]
    ledger = [
        {"target_endpoint": "/b", "auth_context": {"status": "ready", "profile_id": 7}},
        {"target_endpoint": "/c", "auth_context": "anonymous"},
    ]
    keys = _authenticated_endpoint_keys(routes, ledger, zap_urls={"/page"}, zap_authenticated=True)
    assert "/a" in keys
    assert "/b" in keys
    assert "/c" not in keys
    assert "/page" in keys
