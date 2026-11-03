"""E18: API endpoint discovery from same-origin JS bundles + T01 session auth helpers."""

from __future__ import annotations

from attestra.automated_vapt.core import js_api_discovery as jsd
from attestra.automated_vapt.core.session_auth import SessionAuth

ROOT = "https://demo.example/"

BUNDLE = """
B=async()=>{let e=await w.A.get("/api/projects/get-projects-overview");}
a.post("/api/projects/close-project",x);
a.get(`/api/projects/get-projects-risks/${id}`);
a.get("/api/projects/get-project-timeline/"+id);
fetch("/api/admin/get-all-clients");
fetch("/api/x/save",{method:"POST",body:b});
s="/api/auth/logout/";
a.get("/api/auth/refresh-token");
u="https://other.example/api/a/b";
v="https://demo.example/api/token/get-clients";
a.get("/api/admin/search?q="+q);
a.get("/api/projects/user-stats?clientId="+cid);
n="/api";
a.get("/api/users/:id/profile");
i="/api/fonts/x.png";
"""


def _by_path(eps):
    return {e.path: e for e in eps}


def test_extracts_methods_and_paths():
    eps = _by_path(jsd.extract_api_endpoints(BUNDLE, ROOT, source="page.js"))
    assert eps["/api/projects/get-projects-overview"].methods == {"GET"}
    assert eps["/api/projects/close-project"].methods == {"POST"}
    assert eps["/api/admin/get-all-clients"].methods == {"GET"}  # fetch without method
    assert eps["/api/x/save"].methods == {"POST"}
    assert "/api/token/get-clients" in eps  # same-origin absolute URL
    assert "page.js" in eps["/api/projects/get-projects-overview"].files


def test_drops_other_origin_static_and_bare_prefix():
    eps = _by_path(jsd.extract_api_endpoints(BUNDLE, ROOT))
    assert not any("other.example" in p or p == "/api/a/b" for p in eps)
    assert "/api" not in eps
    assert "/api/fonts/x.png" not in eps


def test_dynamic_segments_and_idor_candidates():
    eps = _by_path(jsd.extract_api_endpoints(BUNDLE, ROOT))
    assert eps["/api/projects/get-projects-risks"].dynamic  # ${id}
    assert eps["/api/projects/get-projects-risks"].path_param
    assert eps["/api/projects/get-projects-risks"].idor_candidate
    assert eps["/api/projects/get-project-timeline"].dynamic  # trailing "/" + id
    assert eps["/api/projects/get-project-timeline"].path_param
    assert eps["/api/admin/search"].dynamic  # ?q=
    assert "q" in eps["/api/admin/search"].query_keys
    assert eps["/api/projects/user-stats"].idor_candidate
    assert "clientId" in eps["/api/projects/user-stats"].id_query_keys
    assert eps["/api/users"].dynamic  # :id placeholder
    assert eps["/api/users"].path_param


def test_capture_safe_only_static_get_without_unsafe_words():
    eps = jsd.extract_api_endpoints(BUNDLE, ROOT)
    safe = sorted(e.path for e in eps if e.capture_safe)
    assert safe == ["/api/admin/get-all-clients", "/api/projects/get-projects-overview"]
    paths = _by_path(eps)
    assert not paths["/api/auth/refresh-token"].capture_safe  # GET but state-changing word
    assert not paths["/api/auth/logout"].capture_safe
    assert not paths["/api/token/get-clients"].capture_safe  # method unknown
    assert paths["/api/token/get-clients"].gettable  # method unknown still gettable


def test_is_unsafe_path():
    assert jsd.is_unsafe_path("https://demo.example/api/auth/refresh-token")
    assert jsd.is_unsafe_path("/api/auth/logout")
    assert not jsd.is_unsafe_path("https://demo.example/api/projects/get-projects-overview")


def test_js_urls_same_origin_and_app_chunks_first():
    lines = [
        "https://demo.example/_next/static/chunks/webpack-1.js",
        "https://demo.example/_next/static/chunks/1255-abc.js",
        "https://cdn.other.example/x.js",
        "https://demo.example/_next/static/chunks/app/projects/page-9.js",
        "https://demo.example/fonts/a.ttf",
        "https://demo.example/_next/static/chunks/1255-abc.js",
    ]
    out = jsd.js_urls_from(lines, ROOT)
    assert out[0].endswith("/app/projects/page-9.js")
    assert out[-1].endswith("webpack-1.js")
    assert len(out) == 3


def test_discover_from_js_fetch_cap_and_cache(tmp_path):
    calls: list[str] = []

    def fetch(url):
        calls.append(url)
        return 200, BUNDLE

    lines = [f"https://demo.example/_next/static/chunks/{i}.js" for i in range(5)]
    cache = tmp_path / jsd.CACHE_NAME
    res = jsd.discover_from_js(lines, ROOT, fetch=fetch, max_files=3, cache_path=cache)
    assert len(calls) == 3
    assert res.files_fetched == 3
    assert "/api/projects/get-projects-overview" in res.safe_get_paths
    assert cache.exists()
    again = jsd.discover_from_js(lines, ROOT, fetch=fetch, cache_path=cache)
    assert again.cached and len(calls) == 3
    assert again.safe_get_paths == res.safe_get_paths
    # cache round-trips the new idor fields
    assert any(e.idor_candidate for e in again.endpoints)


def test_discover_skips_failed_fetches():
    def fetch(url):
        if url.endswith("0.js"):
            raise OSError("boom")
        return 404, ""

    lines = [f"https://demo.example/_next/static/chunks/{i}.js" for i in range(2)]
    res = jsd.discover_from_js(lines, ROOT, fetch=fetch)
    assert res.files_fetched == 0 and res.files_failed == 2 and res.endpoints == []


def test_session_auth_headers_only_same_origin_and_scrub():
    a = SessionAuth(profile_id=2, status="ready", headers={"Authorization": "Bearer abcdefgh"}, redact_values=("abcdefgh",))
    assert a.headers_for("https://demo.example/api/x", ROOT) == {"Authorization": "Bearer abcdefgh"}
    assert a.headers_for("https://evil.example/api/x", ROOT) == {}
    assert "abcdefgh" not in a.scrub("token=abcdefgh")
    pub = a.public()
    assert pub["injected"] == ["Authorization"] and "abcdefgh" not in str(pub)
    failed = SessionAuth(profile_id=2, status="failed", headers={"Authorization": "x"})
    assert failed.headers_for("https://demo.example/", ROOT) == {}
