"""Crawl settings: typed path kept, Extra Start URLs (same host), ZAP AJAX spider argv, nuclei -list."""
from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from attestra.runner import crawl
from attestra.runner.authorization import AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners import zap_crawl
from attestra.runner.scanners.nuclei import NucleiAdapter
from attestra.runner.scanners.zap import ZapAdapter

PIN = PinnedTarget(host="demo.example.com", ip="93.184.216.34", port=443, scheme="https")


def _scope(**kw) -> AuthorizedScope:
    base = dict(
        name="t", allowed_hosts=frozenset({"demo.example.com"}), allowed_urls=("https://demo.example.com",),
        allowed_paths=(), allowed_images=(),
    )
    base.update(kw)
    return AuthorizedScope(**base)


def _plan(urls=(), spider=5, ajax=5):
    return crawl.CrawlPlan(root_url="https://demo.example.com/", start_urls=list(urls), spider_minutes=spider, ajax_minutes=ajax)


# ---------------------------------------------------------------- seed validation


def test_seed_text_accepts_paths_and_same_host_urls():
    seeds = crawl.parse_seed_text(
        "/projects\n\n# comment\nhttps://demo.example.com/settings?tab=1&x=2\n/projects\n", "https://demo.example.com"
    )
    assert seeds == ["https://demo.example.com/projects", "https://demo.example.com/settings?tab=1&x=2"]


@pytest.mark.parametrize(
    "line",
    [
        "https://evil.example.net/projects",  # other host
        "https://sub.demo.example.com/x",  # sub-domain is another host
        "http://demo.example.com/x",  # other scheme
        "https://demo.example.com:8443/x",  # other port
        "https://user:pw@demo.example.com/x",  # credentials
        "ftp://demo.example.com/x",
        "projects",  # not a URL or /path
        "/has space",
    ],
)
def test_seed_text_rejects_other_hosts_and_bad_lines(line):
    with pytest.raises(crawl.CrawlSettingsError):
        crawl.parse_seed_text(line, "https://demo.example.com")


def test_seed_text_must_stay_under_target_path_prefix():
    assert crawl.parse_seed_text("/app/projects", "https://demo.example.com/app") == ["https://demo.example.com/app/projects"]
    with pytest.raises(crawl.CrawlSettingsError, match="outside"):
        crawl.parse_seed_text("/other", "https://demo.example.com/app")


def test_seed_limit():
    text = "\n".join(f"/p{i}" for i in range(crawl.MAX_SEEDS + 1))
    with pytest.raises(crawl.CrawlSettingsError, match="at most"):
        crawl.parse_seed_text(text, "https://demo.example.com")


def test_minutes_validation():
    assert crawl.parse_minutes("", "Spider Minutes", allow_zero=False) is None
    assert crawl.parse_minutes("0", "AJAX", allow_zero=True) == 0
    with pytest.raises(crawl.CrawlSettingsError):
        crawl.parse_minutes("0", "Spider Minutes", allow_zero=False)
    with pytest.raises(crawl.CrawlSettingsError):
        crawl.parse_minutes("61", "Spider Minutes", allow_zero=False)
    with pytest.raises(crawl.CrawlSettingsError):
        crawl.parse_minutes("abc", "Spider Minutes", allow_zero=False)


# ---------------------------------------------------------------- path retention


def test_typed_path_is_kept_as_start_url():
    urls, notes = crawl.start_urls_for(PIN, "https://demo.example.com/projects", "", _scope())
    assert urls == ["https://demo.example.com/projects"]
    assert notes == []


def test_root_only_target_has_no_extra_start_urls():
    urls, _ = crawl.start_urls_for(PIN, "https://demo.example.com/", "", _scope())
    assert urls == []


def test_start_urls_drop_other_hosts_and_scope_denies():
    seeds = "/projects\nhttps://evil.example.net/x\n/admin/payments\n"
    scope = _scope(deny_urls=("/admin/*",))
    urls, notes = crawl.start_urls_for(PIN, "https://demo.example.com", seeds, scope)
    assert urls == ["https://demo.example.com/projects"]
    assert any("another scheme/host/port" in n for n in notes)
    assert any("out-of-scope" in n for n in notes)


def test_effective_minutes_env_and_override(monkeypatch):
    monkeypatch.setenv("ATTESTRA_ZAP_SPIDER_MINUTES", "7")
    monkeypatch.setenv("ATTESTRA_ZAP_AJAX_MINUTES", "0")
    assert crawl.effective_minutes(SimpleNamespace(crawl_spider_minutes=None, crawl_ajax_minutes=None)) == (7, 0)
    assert crawl.effective_minutes(SimpleNamespace(crawl_spider_minutes=3, crawl_ajax_minutes=9)) == (3, 9)


def test_fit_to_timeout_scales_crawl():
    assert crawl.fit_to_timeout(5, 5, timeout_s=1800, active=False)[:2] == (5, 5)
    s, a, note = crawl.fit_to_timeout(30, 30, timeout_s=1800, active=True)  # cap 12 min for active
    assert s + a <= 12 and s >= 1 and a >= 1 and "reduced" in note


# ---------------------------------------------------------------- ZAP argv


def _zap_argv(tmp_path, monkeypatch, plan=None, profile="baseline", deny=()):
    import attestra.config as cfg

    monkeypatch.setitem(
        cfg.SCANNER_IMAGES, "zap", "ghcr.io/zaproxy/zaproxy@sha256:" + "a" * 64
    )
    return ZapAdapter().build_argv(PIN, out_file=tmp_path / "zap-report.json", profile=profile, crawl=plan, deny_urls=deny)


def test_zap_argv_ajax_spider_and_minutes(tmp_path, monkeypatch):
    argv = _zap_argv(tmp_path, monkeypatch, _plan(["https://demo.example.com/projects"], spider=4, ajax=6))
    assert argv[argv.index("-m") + 1] == "4"
    assert "-j" in argv and "--ajax-spider" in argv
    assert argv[argv.index("--hook") + 1] == "/zap/wrk/" + zap_crawl.HOOK_NAME
    assert "--shm-size=1g" in argv and argv.index("--shm-size=1g") < argv.index("-t")
    assert argv[argv.index("-t") + 1] == "https://demo.example.com/"
    cfg = json.loads((tmp_path / zap_crawl.CONFIG_NAME).read_text())
    assert cfg["start_urls"] == ["https://demo.example.com/projects"]
    assert cfg["ajax_minutes"] == 6 and cfg["spider_minutes"] == 4 and cfg["host"] == "demo.example.com"
    assert (tmp_path / zap_crawl.HOOK_NAME).read_text().startswith('"""Attestra crawl hooks')


def test_zap_argv_ajax_off(tmp_path, monkeypatch):
    argv = _zap_argv(tmp_path, monkeypatch, _plan(spider=2, ajax=0))
    assert argv[argv.index("-m") + 1] == "2"
    assert "-j" not in argv and "--shm-size=1g" not in argv


def test_zap_argv_defaults_from_env_without_plan(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_ZAP_SPIDER_MINUTES", "3")
    monkeypatch.setenv("ATTESTRA_ZAP_AJAX_MINUTES", "2")
    argv = _zap_argv(tmp_path, monkeypatch, None)
    assert argv[argv.index("-m") + 1] == "3" and "-j" in argv


def test_zap_argv_respects_timeout(tmp_path, monkeypatch):
    import attestra.config as cfg

    monkeypatch.setattr(cfg, "SCANNER_TIMEOUT_S", 600)
    monkeypatch.setenv("ATTESTRA_SCANNER_TIMEOUT_ZAP", "1200")  # 20 min, baseline crawl cap 5
    argv = _zap_argv(tmp_path, monkeypatch, _plan(spider=30, ajax=30))
    spider = int(argv[argv.index("-m") + 1])
    conf = json.loads((tmp_path / zap_crawl.CONFIG_NAME).read_text())
    assert spider + conf["ajax_minutes"] <= 5


def test_zap_deny_rules_become_excludes(tmp_path, monkeypatch):
    _zap_argv(tmp_path, monkeypatch, _plan(), deny=("/admin/*",))
    conf = json.loads((tmp_path / zap_crawl.CONFIG_NAME).read_text())
    assert conf["deny_regexes"] and conf["deny_regexes"][0].startswith("^https?://[^/]+")


def test_zap_argv_has_no_urls_of_seeds(tmp_path, monkeypatch):
    argv = _zap_argv(tmp_path, monkeypatch, _plan(["https://demo.example.com/a?x=1&y=2"]))
    assert not any("&" in a for a in argv)  # seeds go in the mounted file, never on argv


# ---------------------------------------------------------------- hook behaviour (fake ZAP API)


class _FakeSpider:
    def __init__(self):
        self.scanned, self.max_duration = [], []

    def set_option_max_duration(self, v):
        self.max_duration.append(v)

    def scan(self, url, contextname=None):
        self.scanned.append(url)
        return "1"

    def status(self, sid):
        return "100"

    def exclude_from_scan(self, rx):
        pass

    def stop(self, sid):
        pass


class _FakeAjax:
    status = "stopped"

    def __init__(self):
        self.scanned = []

    def set_option_max_duration(self, v):
        pass

    def scan(self, url, contextname=None):
        self.scanned.append(url)
        return "OK"


class _FakeCore:
    def __init__(self):
        self.sites = ["https://demo.example.com", "https://cdn.other.net"]
        self.deleted, self.excluded = [], []

    def exclude_from_proxy(self, rx):
        self.excluded.append(rx)

    def delete_site_node(self, url):
        self.deleted.append(url)

    def urls(self):
        return ["https://demo.example.com/", "https://demo.example.com/projects", "https://cdn.other.net/x.js"]


def _load_hook(tmp_path, cfg: dict, monkeypatch):
    (tmp_path / zap_crawl.CONFIG_NAME).write_text(json.dumps(cfg))
    src = zap_crawl.HOOK_SOURCE.replace('_WRK = "/zap/wrk/"', f'_WRK = {str(tmp_path) + "/"!r}')
    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda s: None)
    ns: dict = {}
    exec(compile(src, "attestra_zap_hooks.py", "exec"), ns)
    return ns


def test_hook_spiders_seeds_and_drops_other_hosts(tmp_path, monkeypatch):
    conf = zap_crawl.crawl_config(
        _plan(["https://demo.example.com/projects", "https://demo.example.com/a", "https://demo.example.com/b"], spider=5, ajax=6),
        host_header="demo.example.com", scheme="https",
    )
    ns = _load_hook(tmp_path, conf, monkeypatch)
    zap = SimpleNamespace(spider=_FakeSpider(), ajaxSpider=_FakeAjax(), core=_FakeCore(), urlopen=lambda u: "ok")
    ns["zap_started"](zap, "https://demo.example.com/")
    assert zap.core.excluded and "cdn.other.net" not in zap.core.excluded[0]
    import re

    rx = re.compile(zap.core.excluded[0])
    assert rx.match("https://cdn.other.net/x.js") and not rx.match("https://demo.example.com/x")
    ns["zap_spider"](zap, "https://demo.example.com/")
    ns["zap_spider_wrap"](None)
    assert zap.spider.scanned == conf["start_urls"]
    # AJAX: root + 2 seeds share the 6 minutes
    assert ns["zap_ajax_spider"](zap, "https://demo.example.com/", 5) == (zap, "https://demo.example.com/", 2)
    ns["zap_ajax_spider_wrap"](None)
    assert zap.ajaxSpider.scanned == conf["start_urls"][:2]
    ns["zap_get_alerts"](zap, "https://demo.example.com/", [], {})
    assert zap.core.deleted == ["https://cdn.other.net"]
    result = json.loads((tmp_path / zap_crawl.RESULT_NAME).read_text())
    assert result == {"urls_discovered": 2, "other_hosts_removed": 1}
    assert (tmp_path / zap_crawl.URLS_NAME).read_text().splitlines() == [
        "https://demo.example.com/", "https://demo.example.com/projects"
    ]


# ---------------------------------------------------------------- nuclei list


def test_nuclei_root_only_uses_u(tmp_path):
    argv = NucleiAdapter().build_argv(PIN, out_file=tmp_path / "nuclei-out.jsonl", crawl=_plan())
    assert argv[argv.index("-u") + 1] == "https://demo.example.com/" and "-list" not in argv


def test_nuclei_start_urls_use_list_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_NUCLEI_MAX_URLS", "3")
    plan = _plan([f"https://demo.example.com/p{i}" for i in range(5)])
    argv = NucleiAdapter().build_argv(PIN, out_file=tmp_path / "nuclei-out.jsonl", crawl=plan)
    assert "-u" not in argv
    listed = (tmp_path / "nuclei-targets.txt").read_text().split()
    assert argv[argv.index("-list") + 1] == str(tmp_path / "nuclei-targets.txt")
    assert listed == ["https://demo.example.com/", "https://demo.example.com/p0", "https://demo.example.com/p1"]
    dargs = NucleiAdapter().docker_args(PIN, out_file=tmp_path / "nuclei-out.jsonl", crawl=plan)
    assert dargs[dargs.index("-list") + 1] == "/out/nuclei-targets.txt"


# ---------------------------------------------------------------- worker wiring + UI


def test_scan_kwargs_build_plan_from_asset(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        a = s.scalars(select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")).first()
        a.identifier = "https://shop.example.com/account"
        a.crawl_seed_urls = "https://shop.example.com/account/orders\n/cart"
        a.crawl_spider_minutes = 2
        a.crawl_ajax_minutes = 0
        s.flush()
        pin = PinnedTarget(host="shop.example.com", ip="93.184.216.34", port=443, scheme="https")
        run = SimpleNamespace(tool="zap", engagement_id=engagement)
        kw = crawl.scan_kwargs(s, run, pin, a)
        # a typed path narrows the engagement scope prefix, so /cart is dropped with a note
        assert kw["crawl"].start_urls == ["https://shop.example.com/account", "https://shop.example.com/account/orders"]
        assert any("out-of-scope" in n and "/cart" in n for n in kw["crawl"].notes)
        assert (kw["crawl"].spider_minutes, kw["crawl"].ajax_minutes) == (2, 0)
        assert crawl.scan_kwargs(s, SimpleNamespace(tool="testssl", engagement_id=engagement), pin, a) == {}


def _ui_client(engagement):
    from fastapi.testclient import TestClient

    from attestra import db
    from attestra.api import app
    from attestra.auth.keys import create_user
    from attestra.models import Engagement

    with db.session() as s:
        tid = s.get(Engagement, engagement).tenant_id
        u = create_user(s, username="crawl-lead", role="lead", password="pw-1234567890", display_name="Crawl Lead")
        u.tenant_id = tid
    c = TestClient(app)
    c.post("/login", data={"username": "crawl-lead", "password": "pw-1234567890"}, follow_redirects=False)
    return c


def _flash(r):
    assert r.status_code == 303, r.text
    return {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}


def _form(**kw):
    base = {"kind": "web_app", "identifier": "https://app.example.com/projects", "environment": "staging",
            "exposure": "internet"}
    base.update(kw)
    return base


def test_ui_add_target_with_crawl_settings(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    c = _ui_client(engagement)
    page = c.get(f"/engagements/{engagement}")
    assert "Crawl Settings" in page.text and "Extra Start URLs" in page.text
    r = c.post(f"/engagements/{engagement}/targets", data=_form(
        crawl_seed_urls="/projects/42\n/projects/archive", crawl_spider_minutes="8", crawl_ajax_minutes="0"),
        follow_redirects=False)
    assert "error" not in _flash(r)
    with db.session() as s:
        a = s.scalars(select(Asset).where(Asset.identifier == "https://app.example.com/projects")).one()
        assert a.crawl_seed_urls.splitlines() == [
            "https://app.example.com/projects/42", "https://app.example.com/projects/archive"
        ]
        assert (a.crawl_spider_minutes, a.crawl_ajax_minutes) == (8, 0)
        aid = a.id
    page = c.get(f"/engagements/{engagement}/targets/{aid}")
    assert page.status_code == 200 and "Save Crawl Settings" in page.text and "projects/archive" in page.text
    r = c.post(f"/engagements/{engagement}/targets/{aid}/crawl-settings",
               data={"crawl_seed_urls": "/projects/1", "crawl_spider_minutes": "", "crawl_ajax_minutes": "4"},
               follow_redirects=False)
    assert "error" not in _flash(r)
    with db.session() as s:
        a = s.get(Asset, aid)
        assert a.crawl_seed_urls == "https://app.example.com/projects/1"
        assert (a.crawl_spider_minutes, a.crawl_ajax_minutes) == (None, 4)


def test_ui_rejects_seed_on_other_host(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    c = _ui_client(engagement)
    r = c.post(f"/engagements/{engagement}/targets",
               data=_form(crawl_seed_urls="https://evil.example.net/"), follow_redirects=False)
    assert "same scheme, host and port" in _flash(r).get("error", "")
    with db.session() as s:  # nothing half-created
        assert s.scalars(select(Asset).where(Asset.identifier == "https://app.example.com/projects")).first() is None


def test_scan_page_shows_crawl_summary(engagement, tmp_path):
    from sqlalchemy import select

    from attestra import config, db
    from attestra.models import Asset, ScanRun

    with db.session() as s:
        a = s.scalars(select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")).first()
        run = ScanRun(engagement_id=engagement, asset_id=a.id, tool="zap", status="done", requested_by="t")
        s.add(run)
        s.flush()
        rid = run.id
    out = config.DATA_DIR / "raw" / f"scan-{rid}"
    out.mkdir(parents=True)
    (out / crawl.SUMMARY_NAME).write_text(json.dumps({
        "tool": "zap", "root_url": "https://shop.example.com/", "start_urls": ["https://shop.example.com/cart"],
        "spider_minutes": 5, "ajax_minutes": 5, "notes": [], "urls_discovered": 137, "other_hosts_removed": 2,
    }))
    c = _ui_client(engagement)
    page = c.get(f"/engagements/{engagement}/scans/{rid}")
    assert page.status_code == 200
    assert "URLs Discovered" in page.text and "137" in page.text and "https://shop.example.com/cart" in page.text
