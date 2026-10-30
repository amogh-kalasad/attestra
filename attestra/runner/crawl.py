"""Crawl settings for URL scans: start URLs (seeds) and crawl minutes.

The gate pins a target to ``scheme://host[:port]/``. This module adds the extra starting
points a crawler and nuclei should use on that same host:

* the path the user typed in the target URL (e.g. ``https://app.example.com/projects``),
* optional per-target "Extra Start URLs" (one per line; absolute same-host URLs or ``/paths``).

Every start URL must use the pinned scheme, host and port and must pass the engagement
scope (deny rules and path prefixes) at scan time; anything else is dropped with a note.

Crawl minutes: ``ATTESTRA_ZAP_SPIDER_MINUTES`` (traditional spider, default 5) and
``ATTESTRA_ZAP_AJAX_MINUTES`` (AJAX spider in a headless browser, default 5, 0 = off),
overridable per target. The total is capped so the crawl fits in the ZAP scan timeout.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

MAX_SEEDS = 20
MAX_MINUTES = 60
DEFAULT_SPIDER_MINUTES = 5
DEFAULT_AJAX_MINUTES = 5
DEFAULT_NUCLEI_MAX_URLS = 10
_UNSAFE = re.compile(r"[\s<>\"'\\`]")


class CrawlSettingsError(ValueError):
    """Invalid crawl settings entered on a target."""


@dataclass
class CrawlPlan:
    root_url: str
    start_urls: list[str] = field(default_factory=list)  # extra starting points (root excluded)
    spider_minutes: int = DEFAULT_SPIDER_MINUTES
    ajax_minutes: int = DEFAULT_AJAX_MINUTES
    notes: list[str] = field(default_factory=list)
    # nuclei only: extra same-host URLs (a finished ZAP crawl or nuclei's quick crawl) and where
    # they came from; see attestra/runner/nuclei_urls.py.
    discovered_urls: list[str] = field(default_factory=list)
    url_source: str = ""
    # Engagement scope used to re-check discovered URLs (not serialized).
    scope: object = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict:
        return {
            "root_url": self.root_url,
            "start_urls": list(self.start_urls),
            "spider_minutes": self.spider_minutes,
            "ajax_minutes": self.ajax_minutes,
            "notes": list(self.notes),
        }


# ------------------------------------------------------------------ minutes


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if raw.isdigit():
        return min(int(raw), MAX_MINUTES)
    return default


def default_spider_minutes() -> int:
    return max(1, _env_int("ATTESTRA_ZAP_SPIDER_MINUTES", DEFAULT_SPIDER_MINUTES))


def default_ajax_minutes() -> int:
    return _env_int("ATTESTRA_ZAP_AJAX_MINUTES", DEFAULT_AJAX_MINUTES)


def nuclei_max_urls() -> int:
    raw = os.environ.get("ATTESTRA_NUCLEI_MAX_URLS", "").strip()
    return max(1, min(int(raw), 100)) if raw.isdigit() else DEFAULT_NUCLEI_MAX_URLS


def nuclei_max_host_errors() -> int:
    """``ATTESTRA_NUCLEI_MAX_HOST_ERRORS``: 0 (default) = never skip a host after errors (-nmhe).

    nuclei's own default skips a host for the rest of the scan after 30 errors, which also
    happens when templates time out against third-party login redirects (e.g. Microsoft login).
    """
    raw = os.environ.get("ATTESTRA_NUCLEI_MAX_HOST_ERRORS", "").strip()
    return min(int(raw), 100000) if raw.isdigit() else 0


def parse_minutes(value, label: str, *, allow_zero: bool) -> int | None:
    """Form value -> minutes (None = use the default). Raises CrawlSettingsError."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if not text.isdigit():
        raise CrawlSettingsError(f"{label} must be a whole number of minutes")
    n = int(text)
    low = 0 if allow_zero else 1
    if not low <= n <= MAX_MINUTES:
        raise CrawlSettingsError(f"{label} must be between {low} and {MAX_MINUTES} minutes")
    return n


def effective_minutes(asset) -> tuple[int, int]:
    spider = getattr(asset, "crawl_spider_minutes", None)
    ajax = getattr(asset, "crawl_ajax_minutes", None)
    spider = default_spider_minutes() if spider in (None, "") else max(1, min(int(spider), MAX_MINUTES))
    ajax = default_ajax_minutes() if ajax in (None, "") else max(0, min(int(ajax), MAX_MINUTES))
    return spider, ajax


def fit_to_timeout(spider: int, ajax: int, *, timeout_s: int, active: bool) -> tuple[int, int, str]:
    """Scale crawl minutes down so ZAP can still finish within ``timeout_s``.

    Baseline: crawl may use the timeout minus 15 minutes (start-up + passive scan).
    Active: crawl may use at most 40% of the timeout, leaving the rest for the attack phase.
    """
    total_min = max(1, int(timeout_s) // 60)
    cap = max(2, int(total_min * 0.4)) if active else max(2, total_min - 15)
    if spider + ajax <= cap:
        return spider, ajax, ""
    scale = cap / float(spider + ajax)
    new_spider = max(1, int(spider * scale))
    new_ajax = max(1, int(ajax * scale)) if ajax else 0
    while new_spider + new_ajax > cap and new_spider > 1:
        new_spider -= 1
    note = (
        f"crawl time reduced from {spider}+{ajax} to {new_spider}+{new_ajax} minutes "
        f"to fit the {total_min}-minute ZAP timeout"
    )
    return new_spider, new_ajax, note


# ------------------------------------------------------------------ start URLs


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    port = p.port or (443 if scheme == "https" else 80)
    return scheme, (p.hostname or "").lower(), port


def _clean(url: str) -> str:
    p = urlsplit(url)
    path = p.path or "/"
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))


def _base_scope(identifier: str):
    """Scope with only this target: same rules the engagement scope applies to its URL."""
    from attestra.runner.authorization import AuthorizedScope

    host = (urlsplit(identifier).hostname or "").lower()
    return AuthorizedScope(
        name="target",
        allowed_hosts=frozenset({host}),
        allowed_urls=(identifier.strip().rstrip("/"),),
        allowed_paths=(),
        allowed_images=(),
    )


def parse_seed_text(text: str | None, identifier: str) -> list[str]:
    """Validate the Extra Start URLs textarea for a target.

    One URL per line; blank lines and ``#`` comments are ignored; ``/path`` lines are joined
    to the target's origin. Every URL must use the target's scheme, host and port and stay
    under the target's path prefix. Raises CrawlSettingsError listing the bad lines.
    """
    from attestra.runner.authorization import AuthorizationError, validate_url_target

    ident = (identifier or "").strip()
    base = urlsplit(ident)
    if base.scheme not in ("http", "https") or not base.hostname:
        if (text or "").strip():
            raise CrawlSettingsError("Extra Start URLs only apply to web application or API targets with a full URL")
        return []
    origin = f"{base.scheme.lower()}://{base.netloc.lower()}"
    want = _origin(ident)
    scope = _base_scope(ident)
    out: list[str] = []
    bad: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        url = origin + line if line.startswith("/") else line
        if _UNSAFE.search(url) or len(url) > 2000:
            bad.append(f"{line} (contains spaces or characters that are not allowed)")
            continue
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            bad.append(f"{line} (not a full http(s) URL or /path)")
            continue
        if p.username or p.password:
            bad.append(f"{line} (credentials in URLs are not allowed)")
            continue
        if _origin(url) != want:
            bad.append(f"{line} (must be on {origin}, the same scheme, host and port as the target)")
            continue
        try:
            validate_url_target(scope, url)
        except AuthorizationError as exc:
            bad.append(f"{line} ({exc})")
            continue
        clean = _clean(url)
        if clean not in out:
            out.append(clean)
    if bad:
        raise CrawlSettingsError("Extra Start URLs rejected: " + "; ".join(bad[:5]) + ("; ..." if len(bad) > 5 else ""))
    if len(out) > MAX_SEEDS:
        raise CrawlSettingsError(f"Extra Start URLs: at most {MAX_SEEDS} URLs per target")
    return out


def root_url(pin) -> str:
    return f"{pin.scheme}://{pin.host_header}/"


def start_urls_for(pin, identifier: str, seed_text: str | None, scope=None) -> tuple[list[str], list[str]]:
    """Extra start URLs for a pinned target: the typed path first, then the seeds.

    Returns ``(urls, notes)``. The root URL itself is never included (scanners always start
    there). URLs on another scheme/host/port or refused by ``scope`` are dropped with a note.
    """
    from attestra.runner.authorization import AuthorizationError, authorize_target

    root = root_url(pin)
    want = _origin(root)
    notes: list[str] = []
    candidates: list[str] = []
    ident = (identifier or "").strip()
    p = urlsplit(ident)
    if p.scheme in ("http", "https") and ((p.path not in ("", "/")) or p.query):
        candidates.append(urlunsplit((pin.scheme, pin.host_header, p.path or "/", p.query, "")))
    for raw in (seed_text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        candidates.append(root.rstrip("/") + line if line.startswith("/") else line)
    urls: list[str] = []
    for url in candidates:
        if _UNSAFE.search(url):
            notes.append(f"skipped start URL with unsafe characters: {url[:200]}")
            continue
        if _origin(url) != want:
            notes.append(f"skipped start URL on another scheme/host/port: {url[:200]}")
            continue
        if scope is not None:
            try:
                authorize_target(scope, url, "url")
            except AuthorizationError as exc:
                notes.append(f"skipped out-of-scope start URL {url[:200]}: {exc}")
                continue
        clean = _clean(url)
        if clean != root and clean not in urls:
            urls.append(clean)
    if len(urls) > MAX_SEEDS:
        notes.append(f"only the first {MAX_SEEDS} start URLs are used")
        urls = urls[:MAX_SEEDS]
    return urls, notes


def plan_for(pin, asset, scope=None) -> CrawlPlan:
    spider, ajax = effective_minutes(asset)
    urls, notes = start_urls_for(pin, getattr(asset, "identifier", ""), getattr(asset, "crawl_seed_urls", ""), scope)
    return CrawlPlan(root_url=root_url(pin), start_urls=urls, spider_minutes=spider, ajax_minutes=ajax, notes=notes)


def scan_kwargs(s, run, target, asset) -> dict:
    """Extra adapter kwargs for zap / nuclei runs (``crawl`` plan). Never raises."""
    try:
        from attestra.runner.dns_pin import PinnedTarget

        if run.tool not in ("zap", "nuclei") or not isinstance(target, PinnedTarget) or asset is None:
            return {}
        try:
            from attestra.runner.authorization import scope_for_engagement

            scope = scope_for_engagement(s, run.engagement_id)
        except Exception:  # noqa: BLE001 - the gate already passed; fall back to same-host checks
            scope = None
        plan = plan_for(target, asset, scope)
        plan.scope = scope
        if run.tool == "nuclei":
            _attach_zap_urls(s, run, target, asset, plan)
        return {"crawl": plan}
    except Exception:  # noqa: BLE001 - crawl extras must never stop a scan
        return {}


def _attach_zap_urls(s, run, target, asset, plan: CrawlPlan) -> None:
    """nuclei: reuse the URL list of a finished ZAP scan of the same origin (never raises)."""
    try:
        from attestra.runner import nuclei_urls

        lines, zap_run_id = nuclei_urls.zap_urls_for(s, run, target, asset)
        if not lines:
            return
        urls = nuclei_urls.rank(nuclei_urls.filter_urls(lines, plan.root_url, plan.scope))
        if urls:
            plan.discovered_urls = urls
            plan.url_source = f"zap-scan-{zap_run_id}"
        else:
            plan.notes.append(f"ZAP scan {zap_run_id} found only static files on this host; running a quick crawl instead")
    except Exception:  # noqa: BLE001 - fall back to nuclei's own crawl
        pass


# ------------------------------------------------------------------ summaries

SUMMARY_NAME = "crawl-summary.json"


def summary_for_run(run) -> dict | None:
    """Read the crawl summary a scanner wrote next to its report (scan page)."""
    import json

    from attestra import config

    try:
        path = config.DATA_DIR / "raw" / f"scan-{run.id}" / SUMMARY_NAME
        if not path.is_file():
            return None
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except Exception:  # noqa: BLE001 - display only
        return None


# ------------------------------------------------------------------ target settings (UI)


def validate_settings(identifier: str, kind: str, seed_text, spider, ajax) -> tuple[str, int | None, int | None]:
    """Validate the Crawl Settings form. Returns (seed text to store, spider, ajax)."""
    seed_text = (seed_text or "").strip()
    if seed_text and kind not in ("web_app", "api"):
        raise CrawlSettingsError("Extra Start URLs only apply to web application and API targets")
    seeds = parse_seed_text(seed_text, identifier) if seed_text else []
    return (
        "\n".join(seeds),
        parse_minutes(spider, "Spider Minutes", allow_zero=False),
        parse_minutes(ajax, "AJAX Spider Minutes", allow_zero=True),
    )


def add_asset_with_crawl(
    s,
    engagement_id: int,
    *,
    crawl_seed_urls: str = "",
    crawl_spider_minutes: str = "",
    crawl_ajax_minutes: str = "",
    **kwargs,
):
    """services.add_asset plus the optional Crawl Settings from the Add Target form."""
    from attestra import services

    kind = {"url": "web_app"}.get(kwargs.get("kind", ""), kwargs.get("kind", ""))
    try:
        seeds, spider, ajax = validate_settings(
            (kwargs.get("identifier") or "").strip(), kind, crawl_seed_urls, crawl_spider_minutes, crawl_ajax_minutes
        )
    except CrawlSettingsError as exc:
        raise services.ServiceError(str(exc)) from None
    asset = services.add_asset(s, engagement_id, **kwargs)
    if seeds or spider is not None or ajax is not None:
        asset.crawl_seed_urls = seeds
        asset.crawl_spider_minutes = spider
        asset.crawl_ajax_minutes = ajax
        s.flush()
    return asset


def update_crawl_settings(s, engagement_id: int, asset_id: int, *, seed_text, spider, ajax, actor: str):
    from attestra import audit, services
    from attestra.models import Asset

    asset = s.get(Asset, asset_id)
    if asset is None or asset.engagement_id != engagement_id:
        raise LookupError("target not found")
    try:
        seeds, sp, aj = validate_settings(asset.identifier, asset.kind, seed_text, spider, ajax)
    except CrawlSettingsError as exc:
        raise services.ServiceError(str(exc)) from None
    asset.crawl_seed_urls = seeds
    asset.crawl_spider_minutes = sp
    asset.crawl_ajax_minutes = aj
    audit.record(
        s, actor, "asset.crawl_settings", "asset", asset.id,
        seeds=len(seeds.splitlines()) if seeds else 0, spider_minutes=sp, ajax_minutes=aj,
    )
    return asset


def form_defaults() -> dict:
    return {
        "spider_minutes": default_spider_minutes(),
        "ajax_minutes": default_ajax_minutes(),
        "max_seeds": MAX_SEEDS,
        "max_minutes": MAX_MINUTES,
        "nuclei_max_urls": nuclei_max_urls(),
        "nuclei_max_host_errors": nuclei_max_host_errors(),
    }
