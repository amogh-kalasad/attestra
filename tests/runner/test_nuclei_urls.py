"""nuclei URL coverage (reuse a ZAP crawl / quick crawl) and host-error skipping (-nmhe)."""
from __future__ import annotations

import json
from types import SimpleNamespace

from attestra.runner import crawl, nuclei_urls
from attestra.runner.authorization import AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners import nuclei as nuclei_mod
from attestra.runner.scanners.base import ScannerAdapter, ScannerResult
from attestra.runner.scanners.nuclei import NucleiAdapter

ROOT = "https://demo.example.com/"
PIN = PinnedTarget(host="demo.example.com", ip="93.184.216.34", port=443, scheme="https")

ZAP_LIST = [
    "https://demo.example.com",
    "https://demo.example.com/",
    "https://demo.example.com/_next",
    "https://demo.example.com/_next/static/chunks/app/layout-f596520d95dd2f74.js",
    "https://demo.example.com/_next/static/chunks/app/user/verify/page-174885c594ee3c31.js",
    "https://demo.example.com/_next/static/chunks/app/(dash)/projects/page-0a1b2c3d.js",
    "https://demo.example.com/_next/static/chunks/app/projects/%5Bid%5D/page-0a1b2c3d.js",
    "https://demo.example.com/_next/static/css/2c50c33f1e1a23e8.css",
    "https://demo.example.com/cdn-cgi",
    "https://demo.example.com/cdn-cgi/challenge-platform/h/g/scripts/jsd/main.js",
    "https://demo.example.com/fonts",
    "https://demo.example.com/fonts/Rubik-Bold.ttf",
    "https://demo.example.com/robots.txt",
    "https://demo.example.com/user",
    "https://demo.example.com/user/codeverification.txt?_rsc=19ozy",
    "https://demo.example.com/user/verify",
    "https://demo.example.com/search?q=1&_rsc=abc",
    "https://other.example.net/login",
]


def _plan(urls=()):
    return crawl.CrawlPlan(root_url=ROOT, start_urls=list(urls))


def _scope(**kw) -> AuthorizedScope:
    base = dict(
        name="t", allowed_hosts=frozenset({"demo.example.com"}), allowed_urls=("https://demo.example.com",),
        allowed_paths=(), allowed_images=(),
    )
    base.update(kw)
    return AuthorizedScope(**base)


# ---------------------------------------------------------------- filtering


def test_next_routes_from_chunk_paths():
    assert nuclei_urls.next_routes("/_next/static/chunks/app/user/verify/page-174885c5.js") == ["/user/verify"]
    assert nuclei_urls.next_routes("/_next/static/chunks/app/page-174885c5.js") == ["/"]
    assert nuclei_urls.next_routes("/_next/static/chunks/app/(auth)/login/page-174885c5.js") == ["/login"]
    assert nuclei_urls.next_routes("/_next/static/chunks/app/p/%5Bid%5D/page-174885c5.js") == []
    assert nuclei_urls.next_routes("/_next/static/chunks/pages/settings/index-174885c5ab.js") == ["/settings"]
    assert nuclei_urls.next_routes("/_next/static/chunks/pages/_app-174885c5ab.js") == []


def test_filter_zap_list_keeps_pages_only():
    got = nuclei_urls.rank(nuclei_urls.filter_urls(ZAP_LIST, ROOT))
    assert got == [
        "https://demo.example.com/user",
        "https://demo.example.com/projects",
        "https://demo.example.com/search?q=1",
        "https://demo.example.com/user/verify",
    ]


def test_filter_respects_scope():
    scope = _scope(allowed_urls=("https://demo.example.com/user",))
    got = nuclei_urls.filter_urls(ZAP_LIST, ROOT, scope)
    assert got and all(u.startswith("https://demo.example.com/user") for u in got)


# ---------------------------------------------------------------- quick crawl


def _site(log):
    pages = {
        "https://demo.example.com/": (200, "text/html", """<html><a href="/projects">P</a>
            <a href="https://evil.example.net/x">x</a><a href="/img/logo.png">l</a>
            <script src="/_next/static/chunks/app/user/verify/page-174885c5.js"></script>
            <script src="/_next/static/abc123/_buildManifest.js"></script>
            <a href="/old">old</a></html>""", ""),
        "https://demo.example.com/projects": (200, "text/html; charset=utf-8", '<a href="/projects/new?x=1#top">n</a>', ""),
        "https://demo.example.com/projects/new?x=1": (200, "text/html", "<p>new</p>", ""),
        "https://demo.example.com/old": (302, "text/html", "", "https://demo.example.com/settings"),
        "https://demo.example.com/settings": (200, "text/html", "ok", ""),
        "https://demo.example.com/_next/static/abc123/_buildManifest.js": (
            200, "application/javascript", 'self.__BUILD_MANIFEST={"/reports":["a.js"],"/_app":[],"/p/[id]":[]}', ""),
        "https://demo.example.com/_next/static/chunks/app/user/verify/page-174885c5.js": (
            200, "application/javascript", 'push("/dashboard/overview")', ""),
        "https://demo.example.com/sitemap.xml": (200, "application/xml", "<urlset><url><loc>https://demo.example.com/about</loc></url></urlset>", ""),
    }

    def fetch(url, headers):
        log.append((url, dict(headers)))
        if url not in pages:
            return 404, "text/html", "", ""
        return pages[url]

    return fetch


def test_crawl_site_finds_same_host_routes_and_sends_headers():
    log = []
    found, notes = nuclei_urls.crawl_site(ROOT, fetch=_site(log), headers={"Authorization": "Bearer T"}, max_pages=30, budget_s=60)
    for u in ("/projects", "/projects/new?x=1", "/settings", "/user/verify", "/reports", "/about", "/dashboard/overview"):
        assert "https://demo.example.com" + u in found, u
    assert not any("evil" in u or u.endswith(".png") or "/_next/" in u for u in found)
    assert all(u.startswith("https://demo.example.com/") for u, _ in log)  # never another host
    assert all(h.get("Authorization") == "Bearer T" for _, h in log)
    assert any("quick crawl" in n for n in notes)


def test_crawl_site_respects_page_budget():
    log = []
    nuclei_urls.crawl_site(ROOT, fetch=_site(log), max_pages=2, budget_s=60)
    assert len(log) == 2


def test_auth_headers_from_secret_file(tmp_path):
    from attestra.auth_web import scan_auth

    path = scan_auth.write_nuclei_secret_file(tmp_path, ROOT, {"Authorization": "Bearer T"}, {"sid": "S"})
    assert nuclei_urls.auth_headers_from_secret_file(path, "demo.example.com") == {"Authorization": "Bearer T", "Cookie": "sid=S"}
    assert nuclei_urls.auth_headers_from_secret_file(path, "other.example.com") == {}
    assert nuclei_urls.auth_headers_from_secret_file(None, "demo.example.com") == {}


# ---------------------------------------------------------------- nuclei flags / list


def test_nuclei_disables_host_error_skipping_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("ATTESTRA_NUCLEI_MAX_HOST_ERRORS", raising=False)
    argv = NucleiAdapter().build_argv(PIN, out_file=tmp_path / "nuclei-out.jsonl")
    assert "-nmhe" in argv and "-mhe" not in argv
    monkeypatch.setenv("ATTESTRA_NUCLEI_MAX_HOST_ERRORS", "0")
    assert "-nmhe" in NucleiAdapter().build_argv(PIN, out_file=tmp_path / "nuclei-out.jsonl")


def test_nuclei_max_host_errors_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_MAX_HOST_ERRORS", "200")
    argv = NucleiAdapter().build_argv(PIN, out_file=tmp_path / "nuclei-out.jsonl")
    assert argv[argv.index("-mhe") + 1] == "200" and "-nmhe" not in argv
    dargs = NucleiAdapter().docker_args(PIN, out_file=tmp_path / "nuclei-out.jsonl")
    assert "-mhe" in dargs


def test_nuclei_list_merges_start_and_discovered_urls(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_MAX_URLS", "4")
    plan = _plan(["https://demo.example.com/projects"])
    plan.discovered_urls = [
        "https://demo.example.com/projects/", "https://demo.example.com/a", "https://demo.example.com/b",
        "https://demo.example.com/c",
    ]
    argv = NucleiAdapter().build_argv(PIN, out_file=tmp_path / "nuclei-out.jsonl", crawl=plan)
    assert "-u" not in argv
    assert (tmp_path / "nuclei-targets.txt").read_text().split() == [
        ROOT, "https://demo.example.com/projects", "https://demo.example.com/a", "https://demo.example.com/b",
    ]


# ---------------------------------------------------------------- scan(): discovery + summary


def _fake_super_scan(captured):
    def fake(self, pin, *, out_dir, cancel=None, profile="baseline", **opts):
        out_file = out_dir / "nuclei-out.jsonl"
        out_dir.mkdir(parents=True, exist_ok=True)
        opts.pop("redact_values", None)
        captured["argv"] = self.build_argv(pin, out_file=out_file, profile=profile, **opts)
        return ScannerResult(tool="nuclei", extra={"returncode": 0, "stderr": ""})

    return fake


def test_scan_runs_quick_crawl_when_no_zap_list(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_CRAWL", "1")
    captured = {}
    monkeypatch.setattr(ScannerAdapter, "scan", _fake_super_scan(captured))
    seen = {}

    def fake_crawl(root, seeds, *, fetch, headers, scope, cancel):
        seen["headers"] = headers
        return ["https://demo.example.com/projects", "https://demo.example.com/settings"], ["quick crawl: 3 request(s), 2 URL(s) found"]

    monkeypatch.setattr(nuclei_urls, "crawl_site", fake_crawl)
    plan = _plan()
    NucleiAdapter().scan(PIN, out_dir=tmp_path, crawl=plan)
    argv = captured["argv"]
    assert "-list" in argv and "-nmhe" in argv
    assert (tmp_path / "nuclei-targets.txt").read_text().split() == [
        ROOT, "https://demo.example.com/projects", "https://demo.example.com/settings",
    ]
    summary = json.loads((tmp_path / crawl.SUMMARY_NAME).read_text())
    assert summary["url_source"] == "nuclei-crawl"
    assert summary["urls_scanned"] == 3 and summary["urls_discovered"] == 2
    assert summary["max_host_errors"] == "off (-nmhe)"
    assert seen["headers"] == {}


def test_scan_falls_back_to_root_when_crawl_finds_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_CRAWL", "1")
    captured = {}
    monkeypatch.setattr(ScannerAdapter, "scan", _fake_super_scan(captured))
    monkeypatch.setattr(nuclei_urls, "crawl_site", lambda *a, **k: ([], ["quick crawl: 1 request(s), 0 URL(s) found"]))
    NucleiAdapter().scan(PIN, out_dir=tmp_path, crawl=_plan())
    assert captured["argv"][captured["argv"].index("-u") + 1] == ROOT
    summary = json.loads((tmp_path / crawl.SUMMARY_NAME).read_text())
    assert summary["url_source"] == "root-only" and summary["urls_scanned"] == 1


def test_scan_survives_crawl_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_CRAWL", "1")
    captured = {}
    monkeypatch.setattr(ScannerAdapter, "scan", _fake_super_scan(captured))

    def boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(nuclei_urls, "crawl_site", boom)
    NucleiAdapter().scan(PIN, out_dir=tmp_path, crawl=_plan())
    assert "-u" in captured["argv"]


def test_scan_skips_crawl_when_zap_list_attached(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_CRAWL", "1")
    captured = {}
    monkeypatch.setattr(ScannerAdapter, "scan", _fake_super_scan(captured))
    monkeypatch.setattr(nuclei_urls, "crawl_site", lambda *a, **k: (_ for _ in ()).throw(AssertionError("crawled")))
    plan = _plan()
    plan.discovered_urls, plan.url_source = ["https://demo.example.com/user/verify"], "zap-scan-13"
    NucleiAdapter().scan(PIN, out_dir=tmp_path, crawl=plan)
    summary = json.loads((tmp_path / crawl.SUMMARY_NAME).read_text())
    assert summary["url_source"] == "zap-scan-13" and summary["urls_scanned"] == 2


def test_crawl_off_by_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_CRAWL", "0")
    assert nuclei_urls.crawl_enabled() is False
    monkeypatch.delenv("ATTESTRA_NUCLEI_CRAWL")
    assert nuclei_urls.crawl_enabled() is False  # unit tests never touch the network by default


# ---------------------------------------------------------------- worker wiring: reuse ZAP list


def test_scan_kwargs_reuses_finished_zap_urls(engagement):
    from sqlalchemy import select

    from attestra import config, db
    from attestra.models import Asset, ScanRun, utcnow

    with db.session() as s:
        a = s.scalars(select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")).first()
        a.identifier = "https://demo.example.com"
        s.flush()
        old = ScanRun(engagement_id=engagement, asset_id=a.id, tool="zap", status="running", requested_by="t")
        zr = ScanRun(engagement_id=engagement, asset_id=a.id, tool="zap", status="done", requested_by="t", ended_at=utcnow())
        s.add_all([old, zr])
        s.flush()
        for r in (old, zr):
            d = config.DATA_DIR / "raw" / f"scan-{r.id}"
            d.mkdir(parents=True, exist_ok=True)
            (d / "zap-urls.txt").write_text("\n".join(ZAP_LIST if r is zr else ["https://demo.example.com/running"]))
        run = SimpleNamespace(id=999, tool="nuclei", engagement_id=engagement)
        kw = crawl.scan_kwargs(s, run, PIN, a)
        plan = kw["crawl"]
        assert plan.url_source == f"zap-scan-{zr.id}"
        assert "https://demo.example.com/user/verify" in plan.discovered_urls
        assert "https://demo.example.com/running" not in plan.discovered_urls
        # ZAP itself never gets a reused list
        zkw = crawl.scan_kwargs(s, SimpleNamespace(id=1000, tool="zap", engagement_id=engagement), PIN, a)
        assert zkw["crawl"].discovered_urls == []


def test_scan_kwargs_no_zap_list_leaves_discovery_to_nuclei(engagement, monkeypatch):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        a = s.scalars(select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")).first()
        a.identifier = "https://demo.example.com"
        s.flush()
        kw = crawl.scan_kwargs(s, SimpleNamespace(id=5, tool="nuclei", engagement_id=engagement), PIN, a)
        assert kw["crawl"].discovered_urls == [] and kw["crawl"].url_source == ""