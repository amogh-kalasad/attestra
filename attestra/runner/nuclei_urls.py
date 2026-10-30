"""Which URLs nuclei scans besides the root.

nuclei does not crawl. Without help it only tests the root URL (plus the target's typed path
and Extra Start URLs). This module finds more pages on the same host, in this order; the
source used is recorded as ``url_source`` in ``crawl-summary.json``:

1. ``zap-scan-<id>``: the ``zap-urls.txt`` of the newest finished ZAP scan of the same target
   (or another target with the same scheme, host and port), at most
   ``ATTESTRA_NUCLEI_ZAP_REUSE_DAYS`` days old (default 14, 0 = never reuse).
2. ``nuclei-crawl``: a quick crawl run just before nuclei. GET only, to the pinned IP, same
   scheme/host/port only, at most ``ATTESTRA_NUCLEI_CRAWL_PAGES`` requests (default 25) in
   ``ATTESTRA_NUCLEI_CRAWL_SECONDS`` (default 60). It reads HTML links, sitemap.xml and the
   Next.js build manifest / app-router chunk names, so client-side routes are found too.
   An authenticated scan's session headers are sent to the target origin only.
   ``ATTESTRA_NUCLEI_CRAWL=0`` turns it off.
3. ``root-only``: nothing found; nuclei scans the root plus the start URLs.

Static files (scripts, styles, images, fonts), Cloudflare ``/cdn-cgi/`` and Next.js ``/_next/``
paths are dropped: templates target pages and endpoints, and every URL multiplies the request
count. The list is capped by ``ATTESTRA_NUCLEI_MAX_URLS``.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

DEFAULT_CRAWL_PAGES = 25
DEFAULT_CRAWL_SECONDS = 60
DEFAULT_ZAP_REUSE_DAYS = 14
REQUEST_TIMEOUT_S = 15
MAX_BODY = 2_000_000
MAX_JS_FETCHES = 6
USER_AGENT = "Mozilla/5.0 (compatible; attestra-nuclei-crawl/0.1)"

STATIC_EXT = {
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "wav", "ogg", "pdf", "zip", "gz",
    "tar", "rar", "7z", "exe", "dmg", "woff2", "txt", "xml", "webmanifest",
}
SKIP_PREFIXES = ("/_next/", "/cdn-cgi/", "/__nextjs", "/_vercel/")
DROP_QUERY_KEYS = {"_rsc"}

_LINK_RE = re.compile(r"""(?:href|src|action|data-href)\s*=\s*["']([^"'<>\s]+)["']""", re.I)
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_BUILD_MANIFEST_RE = re.compile(r"""/_next/static/[^/"'\s<>]+/_buildManifest\.js""")
_NEXT_CHUNK_RE = re.compile(r"""/_next/static/chunks/[^"'\s<>\\)]+\.js""")
_APP_PAGE_RE = re.compile(r"/_next/static/chunks/app/((?:[^\"'\s?#]*/)?)page-[0-9a-zA-Z]+\.js")
_PAGES_RE = re.compile(r"/_next/static/chunks/pages/([^\"'\s?#]+?)-[0-9a-zA-Z]{6,}\.js")
_MANIFEST_KEY_RE = re.compile(r"""["'](/[^"'\s]*)["']\s*:""")
# quoted absolute paths in HTML / JS (client-side router links), e.g. "/projects/settings"
_JS_PATH_RE = re.compile(r"""["'`](/[a-zA-Z][a-zA-Z0-9_\-]{1,40}(?:/[a-zA-Z0-9_\-]{1,40}){0,4}/?)["'`]""")


# ------------------------------------------------------------------ settings


def _env_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    if raw.isdigit():
        return max(low, min(int(raw), high))
    return default


def crawl_pages() -> int:
    return _env_int("ATTESTRA_NUCLEI_CRAWL_PAGES", DEFAULT_CRAWL_PAGES, 1, 200)


def crawl_seconds() -> int:
    return _env_int("ATTESTRA_NUCLEI_CRAWL_SECONDS", DEFAULT_CRAWL_SECONDS, 5, 600)


def zap_reuse_days() -> int:
    return _env_int("ATTESTRA_NUCLEI_ZAP_REUSE_DAYS", DEFAULT_ZAP_REUSE_DAYS, 0, 365)


def crawl_enabled() -> bool:
    raw = os.environ.get("ATTESTRA_NUCLEI_CRAWL", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    # Unit tests never reach the network unless they opt in with ATTESTRA_NUCLEI_CRAWL=1.
    return "PYTEST_CURRENT_TEST" not in os.environ


# ------------------------------------------------------------------ URL filtering


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        port = -1
    return scheme, (p.hostname or "").lower(), port


def next_routes(url: str) -> list[str]:
    """Routes named by Next.js chunk paths (``chunks/app/user/verify/page-x.js`` -> ``/user/verify``).

    Dynamic segments (``[id]``) can't be guessed and are skipped; route groups ``(auth)`` vanish.
    """
    out: list[str] = []
    path = unquote(url)
    for m in _APP_PAGE_RE.finditer(path):
        out.append("/" + m.group(1).strip("/"))
    for m in _PAGES_RE.finditer(path):
        name = m.group(1)
        if name.startswith("_"):
            continue
        out.append("/" if name == "index" else "/" + re.sub(r"/index$", "", name))
    clean: list[str] = []
    for r in out:
        segs = [s for s in r.split("/") if s and not (s.startswith("(") and s.endswith(")"))]
        if any("[" in s or "]" in s or s.startswith("@") for s in segs):
            continue
        route = "/" + "/".join(segs)
        if route not in clean:
            clean.append(route)
    return clean


def _normalize(url: str, root: str) -> str | None:
    """Same-origin, cleaned URL; None when it must not be sent to nuclei."""
    url = unescape(url.strip())
    if not url or url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    absolute = urljoin(root, url)
    if _origin(absolute) != _origin(root):
        return None
    p = urlsplit(absolute)
    path = p.path or "/"
    if re.search(r"[\s<>\"'\\`]", absolute):
        return None
    query = p.query
    if query:
        pairs = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k not in DROP_QUERY_KEYS]
        query = urlencode(pairs)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, query, ""))


def _is_static(url: str) -> bool:
    path = urlsplit(url).path
    if path.startswith(SKIP_PREFIXES) or path.rstrip("/") + "/" in SKIP_PREFIXES:
        return True
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        return last.rsplit(".", 1)[-1].lower() in STATIC_EXT
    return False


def filter_urls(urls, root: str, scope=None) -> list[str]:
    """Same-origin page/endpoint URLs in input order (Next.js chunk paths become their routes)."""
    authorize = None
    if scope is not None:
        from attestra.runner.authorization import AuthorizationError, authorize_target

        def authorize(u: str) -> bool:
            try:
                authorize_target(scope, u, "url")
                return True
            except AuthorizationError:
                return False
            except Exception:  # noqa: BLE001 - a scope check that cannot run refuses the URL
                return False

    root_clean = _normalize(root, root)
    # ZAP's site tree lists folder nodes (/fonts, /images) whose children are all static files:
    # those folders are not pages, so drop them too.
    children: dict[str, list[bool]] = {}
    for raw in urls:
        u = _normalize(str(raw or ""), root)
        if not u:
            continue
        segs = [s for s in urlsplit(u).path.split("/") if s]
        static = _is_static(u)
        for i in range(1, len(segs)):
            children.setdefault("/" + "/".join(segs[:i]), []).append(static)
    asset_dirs = {d for d, flags in children.items() if flags and all(flags)}
    out: list[str] = []
    seen: set[str] = set()
    for raw in urls:
        raw = str(raw or "").strip()
        if not raw:
            continue
        candidates = [raw]
        if "/_next/static/chunks/" in raw:
            candidates = [urljoin(root, r) for r in next_routes(raw)]
        for cand in candidates:
            u = _normalize(cand, root)
            if u is None or _is_static(u) or urlsplit(u).path.rstrip("/") in asset_dirs:
                continue
            key = u.rstrip("/") or u
            if key in seen or u == root_clean:
                continue
            if authorize is not None and not authorize(u):
                continue
            seen.add(key)
            out.append(u)
    return out


def rank(urls: list[str]) -> list[str]:
    """Shallow pages first (more likely real routes), then shorter URLs; stable otherwise."""
    def key(u: str):
        p = urlsplit(u)
        depth = len([s for s in p.path.split("/") if s])
        return (depth, 1 if p.query else 0, len(u))

    return sorted(urls, key=key)


# ------------------------------------------------------------------ 1. reuse a ZAP crawl


def zap_urls_for(s, run, target, asset) -> tuple[list[str], int | None]:
    """Lines of the newest finished ZAP scan's zap-urls.txt for this origin (or ``([], None)``)."""
    days = zap_reuse_days()
    if days <= 0 or s is None:
        return [], None
    from sqlalchemy import select

    from attestra import config
    from attestra.models import ScanRun
    from attestra.runner.crawl import root_url
    from attestra.runner.scanners.zap_crawl import URLS_NAME

    want = _origin(root_url(target))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    this_id = getattr(run, "id", None)
    this_asset = getattr(asset, "id", None)
    q = select(ScanRun).where(ScanRun.tool == "zap", ScanRun.status == "done").order_by(ScanRun.id.desc()).limit(100)
    best: tuple[int, list[str]] | None = None
    for zr in s.scalars(q):
        if zr.id == this_id:
            continue
        ended = zr.ended_at or zr.started_at
        if ended is not None:
            if ended.tzinfo is None:
                ended = ended.replace(tzinfo=timezone.utc)
            if ended < cutoff:
                continue
        same_asset = this_asset is not None and zr.asset_id == this_asset
        if not same_asset:
            ident = getattr(zr.asset, "identifier", "") or ""
            if _origin(ident if "://" in ident else f"{want[0]}://{ident}") != want:
                continue
        path = Path(config.DATA_DIR) / "raw" / f"scan-{zr.id}" / URLS_NAME
        try:
            lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except OSError:
            continue
        if not lines:
            continue
        if same_asset:
            return lines, zr.id
        if best is None:
            best = (zr.id, lines)
    if best is not None:
        return best[1], best[0]
    return [], None


# ------------------------------------------------------------------ 2. quick crawl


def auth_headers_from_secret_file(path: str | None, host: str) -> dict[str, str]:
    """Session headers from the nuclei authx secret file (for the crawl only; never logged)."""
    if not path:
        return {}
    try:
        import yaml

        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        out: dict[str, str] = {}
        for entry in doc.get("static") or []:
            domains = [str(d).lower() for d in (entry.get("domains") or [])]
            if domains and host.lower() not in domains:
                continue
            for kv in entry.get("headers") or []:
                k, v = str(kv.get("key") or ""), str(kv.get("value") or "")
                if k and v and "\n" not in k + v and "\r" not in k + v:
                    out[k] = v
        return out
    except Exception:  # noqa: BLE001 - crawl runs without auth rather than failing the scan
        return {}


def pinned_fetch(pin):
    """fetch(url, headers) -> (status, content_type, text, location) over the pinned IP."""
    from attestra.runner.http_safe import _connect

    def _fetch(url: str, headers: dict[str, str]):
        conn = _connect(pin)
        conn.timeout = REQUEST_TIMEOUT_S
        try:
            p = urlsplit(url)
            path = p.path or "/"
            if p.query:
                path = f"{path}?{p.query}"
            req = {"Host": pin.host_header, "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
            req.update(headers or {})
            conn.request("GET", path, headers=req)
            resp = conn.getresponse()
            body = resp.read(MAX_BODY)
            ctype = (resp.getheader("content-type") or "").lower()
            return resp.status, ctype, body.decode("utf-8", errors="replace"), resp.getheader("location") or ""
        finally:
            conn.close()

    return _fetch


def crawl_site(
    root: str,
    seeds=(),
    *,
    fetch,
    headers: dict[str, str] | None = None,
    scope=None,
    max_pages: int | None = None,
    budget_s: int | None = None,
    cancel=None,
    clock=time.monotonic,
) -> tuple[list[str], list[str]]:
    """Breadth-first same-origin crawl. Returns (candidate URLs in priority order, notes)."""
    max_pages = max_pages or crawl_pages()
    budget_s = budget_s or crawl_seconds()
    headers = dict(headers or {})
    deadline = clock() + budget_s
    queue: list[tuple[str, str]] = [("page", root)] + [("page", u) for u in seeds] + [("sitemap", urljoin(root, "/sitemap.xml"))]
    queued: set[str] = {u for _, u in queue}
    pages: list[str] = []      # fetched and not 404
    links: list[str] = []      # HTML links, sitemap, redirects, Next.js routes
    js_paths: list[str] = []   # quoted paths found in scripts (weaker signal)
    fetched = 0
    js_fetched = 0
    errors = 0
    notes: list[str] = []

    def enqueue(kind: str, u: str) -> None:
        if u in queued or _origin(u) != _origin(root):
            return
        queued.add(u)
        queue.append((kind, u))

    while queue and fetched < max_pages:
        if clock() >= deadline:
            notes.append(f"quick crawl stopped after {budget_s}s")
            break
        if cancel is not None and getattr(cancel, "is_set", lambda: False)():
            break
        kind, url = queue.pop(0)
        if kind == "js" and js_fetched >= MAX_JS_FETCHES:
            continue
        fetched += 1
        if kind == "js":
            js_fetched += 1
        try:
            status, ctype, text, location = fetch(url, headers)
        except Exception:  # noqa: BLE001 - one bad page never stops the crawl
            errors += 1
            continue
        if status in (301, 302, 303, 307, 308) and location:
            nxt = _normalize(location, url)
            if nxt:
                links.append(nxt)
                enqueue("page", nxt)
            continue
        if status >= 400:
            continue
        if kind == "sitemap":
            for loc in _LOC_RE.findall(text)[:500]:
                u = _normalize(loc, root)
                if u:
                    links.append(u)
                    if not _is_static(u):
                        enqueue("page", u)
            continue
        if kind == "manifest":
            for key in _MANIFEST_KEY_RE.findall(text):
                if key.startswith("/_") or "[" in key:
                    continue
                links.append(urljoin(root, key))
            continue
        if kind == "js":
            for m in _NEXT_CHUNK_RE.findall(text):
                links.extend(urljoin(root, r) for r in next_routes(m))
            js_paths.extend(urljoin(root, m) for m in _JS_PATH_RE.findall(text))
            continue
        # HTML page
        pages.append(url)
        if "html" not in ctype and "<html" not in text[:2000].lower():
            continue
        for raw in _LINK_RE.findall(text):
            u = _normalize(raw, url)
            if not u:
                continue
            if "/_next/static/chunks/" in u:
                links.extend(urljoin(root, r) for r in next_routes(u))
                if u.endswith(".js"):
                    enqueue("js", u)
                continue
            if _is_static(u):
                continue
            links.append(u)
            enqueue("page", u)
        for m in _BUILD_MANIFEST_RE.findall(text):
            enqueue("manifest", urljoin(root, m))
        for m in _NEXT_CHUNK_RE.findall(text):  # chunk paths inside inline RSC / JSON payloads
            links.extend(urljoin(root, r) for r in next_routes(m))
        js_paths.extend(urljoin(root, m) for m in _JS_PATH_RE.findall(text))

    if errors:
        notes.append(f"quick crawl: {errors} request(s) failed")
    found = filter_urls([*pages[1:], *links, *rank(filter_urls(js_paths, root, scope))], root, scope)
    notes.append(f"quick crawl: {fetched} request(s), {len(found)} URL(s) found")
    return found, notes