"""Controlled authenticated-site crawler with Playwright preference and httpx fallback.

Starts from approved seeds, normalizes URLs, enforces [[attestra/auth_web/limits.py#CrawlLimits]],
and records discovered/visited/skipped/failed/blocked routes. Logout links are never followed
as ordinary navigation. Passive/baseline by default — no exploit payloads.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from attestra.auth_web.limits import CrawlLimits
from attestra.auth_web.scope import CrawlScope, ScopeError, assert_redirect_in_scope, assert_url_in_scope, is_in_scope

ROUTE_STATUSES = ("discovered", "visited", "skipped", "failed", "blocked")

# Path/query tokens that indicate session teardown — never crawl as ordinary links.
_LOGOUT_RE = re.compile(
    r"(?i)(?:^|[/_.?-])(?:logout|log-out|log_out|signout|sign-out|sign_out|logoff|log-off|signoff)(?:$|[/_.?-])"
)

FetchFn = Callable[[str], "FetchResult"]


@dataclass
class FetchResult:
    """Minimal fetch response used by both Playwright and pure-Python engines."""

    url: str
    status_code: int
    body: str = ""
    redirect_to: str | None = None
    error: str = ""


@dataclass
class CrawlRecord:
    url: str
    status: str
    reason: str = ""
    depth: int = 0
    discovered_from: str = ""
    http_status: int | None = None
    title: str = ""


@dataclass
class CrawlResult:
    records: list[CrawlRecord] = field(default_factory=list)
    engine: str = ""
    diagnostic: str = ""
    blocked: bool = False

    @property
    def visited(self) -> list[CrawlRecord]:
        return [r for r in self.records if r.status == "visited"]

    @property
    def blocked_records(self) -> list[CrawlRecord]:
        return [r for r in self.records if r.status == "blocked"]


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        from playwright.sync_api import sync_playwright  # noqa: F401

        return True
    except Exception:
        return False


def normalize_url(url: str, *, max_query_params: int = 8) -> str:
    """Strip fragments, drop empty noise, and bound query cardinality for dedup."""
    parts = urlsplit((url or "").strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return url.strip()
    port = parts.port
    default = 443 if scheme == "https" else 80
    netloc = host if (port is None or port == default) else f"{host}:{port}"
    path = parts.path or "/"
    # Collapse duplicate slashes in path (not at scheme).
    while "//" in path:
        path = path.replace("//", "/")
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if len(pairs) > max_query_params:
        pairs = pairs[:max_query_params]
    # Stable order for dedup without inventing new semantics.
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    query = urlencode(pairs, doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))  # fragment stripped


def is_logout_url(url: str) -> bool:
    parts = urlsplit(url)
    hay = f"{parts.path}?{parts.query}" if parts.query else parts.path
    return bool(_LOGOUT_RE.search(hay or ""))


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and ad.get("href"):
            self.hrefs.append(ad["href"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def extract_links(html: str, base_url: str) -> tuple[list[str], str]:
    """Return (absolute_urls, page_title) from HTML anchors."""
    parser = _LinkExtractor()
    try:
        parser.feed(html or "")
    except Exception:
        return [], ""
    out: list[str] = []
    seen: set[str] = set()
    for href in parser.hrefs:
        href = (href or "").strip()
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:", "data:")):
            continue
        abs_url = normalize_url(urljoin(base_url, href))
        if abs_url not in seen:
            seen.add(abs_url)
            out.append(abs_url)
    return out, parser.title.strip()


def _httpx_fetch(url: str, *, timeout_s: float) -> FetchResult:
    try:
        import httpx
    except ImportError:
        return _urllib_fetch(url, timeout_s=timeout_s)
    try:
        with httpx.Client(follow_redirects=False, timeout=timeout_s) as client:
            resp = client.get(url, headers={"User-Agent": "attestra-auth-web/0.1 (security testing)"})
            if resp.is_redirect:
                return FetchResult(
                    url=url,
                    status_code=resp.status_code,
                    body="",
                    redirect_to=resp.headers.get("location"),
                )
            return FetchResult(url=str(resp.url), status_code=resp.status_code, body=resp.text)
    except Exception as exc:
        return FetchResult(url=url, status_code=0, error=type(exc).__name__)


def _urllib_fetch(url: str, *, timeout_s: float) -> FetchResult:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "attestra-auth-web/0.1 (security testing)"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - caller scoped URL
            body = resp.read(2_000_000).decode("utf-8", errors="replace")
            return FetchResult(url=resp.geturl(), status_code=getattr(resp, "status", 200), body=body)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            return FetchResult(
                url=url,
                status_code=exc.code,
                redirect_to=exc.headers.get("Location") if exc.headers else None,
            )
        body = exc.read(2_000_000).decode("utf-8", errors="replace") if exc.fp else ""
        return FetchResult(url=url, status_code=exc.code, body=body)
    except Exception as exc:
        return FetchResult(url=url, status_code=0, error=type(exc).__name__)


def _playwright_fetch_factory(timeout_s: float) -> FetchFn:
    from playwright.sync_api import sync_playwright

    # Keep a single browser for the crawl; closed by caller via attribute.
    state: dict = {}

    def _ensure():
        if "pw" not in state:
            state["pw"] = sync_playwright().start()
            state["browser"] = state["pw"].chromium.launch(headless=True)
            state["context"] = state["browser"].new_context(
                user_agent="attestra-auth-web/0.1 (security testing)",
            )

    def fetch(url: str) -> FetchResult:
        _ensure()
        page = state["context"].new_page()
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=int(timeout_s * 1000))
            status = resp.status if resp else 0
            # Detect client-side navigations that left the start URL.
            final = page.url
            body = page.content()
            return FetchResult(url=final, status_code=status, body=body)
        except Exception as exc:
            return FetchResult(url=url, status_code=0, error=type(exc).__name__)
        finally:
            page.close()

    def close() -> None:
        for key in ("context", "browser", "pw"):
            obj = state.pop(key, None)
            if obj is None:
                continue
            try:
                if key == "pw":
                    obj.stop()
                else:
                    obj.close()
            except Exception:
                pass

    fetch.close = close  # type: ignore[attr-defined]
    return fetch


def crawl(
    seeds: list[str] | tuple[str, ...],
    scope: CrawlScope,
    limits: CrawlLimits | None = None,
    *,
    fetch: FetchFn | None = None,
    prefer_playwright: bool = True,
    max_query_params: int = 8,
    check_dns: bool = True,
    resolver=None,
) -> CrawlResult:
    """Crawl approved seeds under scope and limits; return route inventory records.

    When ``fetch`` is omitted, prefers Playwright if importable; otherwise uses a
    pure-Python httpx/urllib link follower suitable for tests against a mock.
    If Playwright is preferred but missing and no fallback fetch can be built for
    live use, returns a blocked diagnostic rather than crashing.
    """
    limits = limits or CrawlLimits()
    result = CrawlResult()
    closer = None
    engine = "inject"

    if fetch is None:
        if prefer_playwright and playwright_available():
            fetch = _playwright_fetch_factory(limits.timeout_s)
            closer = getattr(fetch, "close", None)
            engine = "playwright"
        else:
            # Feature-flag style diagnostic when callers insist on Playwright only.
            if prefer_playwright and not playwright_available():
                # Still provide pure-Python fallback for inventory tests / mocks.
                engine = "httpx"
                result.diagnostic = "Playwright not installed; using pure-Python link follower"
            else:
                engine = "httpx"

            def fetch(url: str, _timeout: float = limits.timeout_s) -> FetchResult:
                return _httpx_fetch(url, timeout_s=_timeout)

    result.engine = engine

    # Pre-check seeds against scope (SSRF / allowlist) before any network IO.
    queue: deque[tuple[str, int, str]] = deque()
    seen: set[str] = set()
    records_by_url: dict[str, CrawlRecord] = {}
    host_last: dict[str, float] = {}
    started = time.monotonic()

    resolve_kw = {}
    if resolver is not None:
        resolve_kw["resolver"] = resolver

    for seed in seeds:
        norm = normalize_url(seed, max_query_params=max_query_params)
        try:
            assert_url_in_scope(norm, scope, check_dns=check_dns, **resolve_kw)
        except ScopeError as exc:
            rec = CrawlRecord(url=norm, status="blocked", reason=str(exc), depth=0)
            records_by_url[norm] = rec
            seen.add(norm)
            continue
        if is_logout_url(norm):
            rec = CrawlRecord(url=norm, status="skipped", reason="logout URL", depth=0)
            records_by_url[norm] = rec
            seen.add(norm)
            continue
        queue.append((norm, 0, ""))
        seen.add(norm)
        records_by_url[norm] = CrawlRecord(url=norm, status="discovered", depth=0)

    try:
        while queue:
            if time.monotonic() - started > limits.max_duration_s:
                for url, depth, parent in queue:
                    rec = records_by_url.get(url) or CrawlRecord(url=url, depth=depth, discovered_from=parent)
                    rec.status = "skipped"
                    rec.reason = "max_duration_s exceeded"
                    records_by_url[url] = rec
                break

            visited_count = sum(1 for r in records_by_url.values() if r.status == "visited")
            if visited_count >= limits.max_routes:
                for url, depth, parent in queue:
                    rec = records_by_url.get(url) or CrawlRecord(url=url, depth=depth, discovered_from=parent)
                    if rec.status == "discovered":
                        rec.status = "skipped"
                        rec.reason = "max_routes exceeded"
                        records_by_url[url] = rec
                break

            url, depth, parent = queue.popleft()
            if depth > limits.max_depth:
                rec = records_by_url[url]
                rec.status = "skipped"
                rec.reason = "max_depth exceeded"
                continue

            host = (urlsplit(url).hostname or "").lower()
            # Simple per-host rate limit.
            min_interval = 1.0 / limits.rate_per_host
            last = host_last.get(host, 0.0)
            wait = min_interval - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
            host_last[host] = time.monotonic()

            try:
                assert_url_in_scope(url, scope, check_dns=check_dns, **resolve_kw)
            except ScopeError as exc:
                rec = records_by_url[url]
                rec.status = "blocked"
                rec.reason = str(exc)
                continue

            fr = fetch(url)
            rec = records_by_url[url]
            rec.discovered_from = parent
            rec.depth = depth

            if fr.error:
                rec.status = "failed"
                rec.reason = fr.error
                continue

            if fr.redirect_to:
                try:
                    nxt = assert_redirect_in_scope(
                        url, fr.redirect_to, scope, check_dns=check_dns, **resolve_kw
                    )
                except ScopeError as exc:
                    rec.status = "blocked"
                    rec.reason = str(exc)
                    rec.http_status = fr.status_code
                    continue
                nxt = normalize_url(nxt, max_query_params=max_query_params)
                rec.status = "visited"
                rec.http_status = fr.status_code
                if nxt not in seen and len(records_by_url) < limits.max_routes * 2:
                    seen.add(nxt)
                    if is_logout_url(nxt):
                        records_by_url[nxt] = CrawlRecord(
                            url=nxt, status="skipped", reason="logout URL", depth=depth + 1, discovered_from=url
                        )
                    elif not is_in_scope(nxt, scope):
                        records_by_url[nxt] = CrawlRecord(
                            url=nxt, status="blocked", reason="out of scope", depth=depth + 1, discovered_from=url
                        )
                    else:
                        records_by_url[nxt] = CrawlRecord(
                            url=nxt, status="discovered", depth=depth + 1, discovered_from=url
                        )
                        if depth + 1 <= limits.max_depth:
                            queue.append((nxt, depth + 1, url))
                continue

            links, title = extract_links(fr.body, fr.url or url)
            rec.status = "visited"
            rec.http_status = fr.status_code
            rec.title = title

            # If Playwright followed a cross-origin navigation, block it.
            final_norm = normalize_url(fr.url or url, max_query_params=max_query_params)
            if final_norm != url:
                try:
                    assert_url_in_scope(final_norm, scope, check_dns=check_dns, **resolve_kw)
                except ScopeError as exc:
                    rec.status = "blocked"
                    rec.reason = f"navigation left scope: {exc}"
                    continue

            for link in links:
                if link in seen:
                    continue
                seen.add(link)
                if is_logout_url(link):
                    records_by_url[link] = CrawlRecord(
                        url=link, status="skipped", reason="logout URL", depth=depth + 1, discovered_from=url
                    )
                    continue
                if not is_in_scope(link, scope):
                    records_by_url[link] = CrawlRecord(
                        url=link, status="blocked", reason="out of scope", depth=depth + 1, discovered_from=url
                    )
                    continue
                # Cap discovery bookkeeping relative to max_routes.
                if sum(1 for r in records_by_url.values() if r.status in ("discovered", "visited")) >= limits.max_routes:
                    records_by_url[link] = CrawlRecord(
                        url=link, status="skipped", reason="max_routes exceeded", depth=depth + 1, discovered_from=url
                    )
                    continue
                records_by_url[link] = CrawlRecord(
                    url=link, status="discovered", depth=depth + 1, discovered_from=url
                )
                if depth + 1 <= limits.max_depth:
                    queue.append((link, depth + 1, url))
    finally:
        if closer:
            closer()

    result.records = list(records_by_url.values())
    return result


def crawl_or_block_without_playwright(
    seeds: list[str] | tuple[str, ...],
    scope: CrawlScope,
    limits: CrawlLimits | None = None,
    *,
    require_playwright: bool = False,
    **kwargs,
) -> CrawlResult:
    """Convenience wrapper: when ``require_playwright`` and Playwright is missing, return blocked status."""
    if require_playwright and not playwright_available():
        return CrawlResult(
            records=[
                CrawlRecord(
                    url=normalize_url(s),
                    status="blocked",
                    reason="Playwright not installed",
                )
                for s in seeds
            ],
            engine="none",
            diagnostic="Playwright is required for this crawl but is not installed",
            blocked=True,
        )
    return crawl(seeds, scope, limits, prefer_playwright=True, **kwargs)
