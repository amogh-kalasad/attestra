"""API endpoint discovery from same-origin JavaScript bundles.

Single-page apps (Next.js, React, ...) read their login token from browser storage, so a
crawler that only injects an ``Authorization`` header never sees the app's own API calls.
The bundles still name those calls as string literals, e.g.
``axios.get("/api/projects/get-projects-overview")``. This module:

1. takes the same-origin ``.js`` URLs from the newest finished ZAP scan,
2. fetches them (GET only, no auth sent, same scheme/host/port, scope/SSRF check per URL,
   size cap, per-request timeout, file cap, overall time budget),
3. regex-extracts API path literals and the HTTP method when the call site shows it,
4. returns de-duplicated same-origin endpoints.

Only endpoints seen exclusively with GET, without dynamic segments (``${id}``, trailing
``/`` or ``=`` meant for concatenation) and without state-changing words (logout, delete,
refresh, ...) are marked ``capture_safe``. Automated capture (T01) only ever requests those,
and only with GET.

Results are cached as ``js-api-endpoints.json`` (paths only, never secrets) next to the
ZAP scan's ``zap-urls.txt`` so later executions don't refetch the bundles.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

DEFAULT_MAX_JS_FILES = 40
DEFAULT_BUDGET_S = 120
MAX_JS_BYTES = 3_000_000
FETCH_TIMEOUT_S = 15.0
CACHE_NAME = "js-api-endpoints.json"
CACHE_VERSION = 2
USER_AGENT = "attestra-automated-vapt/0.1 (js api discovery; authorized engagement)"

# Path prefixes that look like API endpoints.
_API_PATH = r"/(?:api|v[0-9]{1,2}|graphql|rest)(?:/[^\"'`\s]*)?"
_ABS_PREFIX = r"(?:https?://[A-Za-z0-9.\-]+(?::[0-9]{1,5})?)?"
_PATH_CHARS_RE = re.compile(r"^/[A-Za-z0-9_\-./~%:@?=&,+${}]*$")

# axios.get("/api/x"), http.post(`/api/y/${id}`), api.request("/api/z")
_CALL_RE = re.compile(
    r"""\.(get|post|put|patch|delete|head|options|request)\s*\(\s*(["'`])(""" + _ABS_PREFIX + _API_PATH + r""")\2""",
    re.I,
)
# fetch("/api/x", { method: "POST" })
_FETCH_RE = re.compile(
    r"""\bfetch\s*\(\s*(["'`])(""" + _ABS_PREFIX + _API_PATH + r""")\1\s*(,\s*\{[^}]{0,400}\})?""",
    re.I,
)
_FETCH_METHOD_RE = re.compile(r"""method\s*:\s*["'`]([A-Za-z]+)["'`]""")
# any quoted literal that looks like an API path
_LITERAL_RE = re.compile(r"""(["'`])(""" + _ABS_PREFIX + _API_PATH + r""")\1""", re.I)

_STATIC_EXT = {
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "pdf", "zip", "txt", "xml",
}
# Words that suggest a call changes state even when sent as GET: never auto-request these.
UNSAFE_WORDS_RE = re.compile(
    r"(?i)(log-?out|sign-?out|delete|remove|destroy|revoke|cron|register|reset|unsubscribe|"
    r"refresh|disconnect|cancel|approve|reject|send|trigger|execute|import|sync|webhook|"
    r"callback|oauth|consent|transfer|close|dismiss|complete|update|create|upload)"
)


# Query/path parameter names that look like an object identifier (IDOR candidates).
ID_PARAM_RE = re.compile(r"(?i)(^id$|_id$|id$|project|client|user|tenant|account|org|member|team|company|workspace)")


@dataclass
class ApiEndpoint:
    path: str
    methods: set[str] = field(default_factory=set)
    dynamic: bool = False
    files: set[str] = field(default_factory=set)
    query_keys: set[str] = field(default_factory=set)  # query param names seen (e.g. clientId)
    path_param: bool = False  # endpoint takes a trailing path id (e.g. /get-timeline/<id>)

    @property
    def capture_safe(self) -> bool:
        return (
            self.methods == {"GET"}
            and not self.dynamic
            and not UNSAFE_WORDS_RE.search(self.path)
        )

    @property
    def gettable(self) -> bool:
        """GET (or method unknown) and not a state-changing action: safe to replay with GET."""
        return self.methods <= {"GET"} and not UNSAFE_WORDS_RE.search(self.path)

    @property
    def id_query_keys(self) -> list[str]:
        return sorted(k for k in self.query_keys if ID_PARAM_RE.search(k))

    @property
    def idor_candidate(self) -> bool:
        """GET endpoint that takes an object id in the path or an id-like query param."""
        return self.gettable and (self.path_param or bool(self.id_query_keys))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "methods": sorted(self.methods),
            "dynamic": self.dynamic,
            "capture_safe": self.capture_safe,
            "gettable": self.gettable,
            "query_keys": sorted(self.query_keys),
            "path_param": self.path_param,
            "idor_candidate": self.idor_candidate,
            "files": sorted(self.files)[:5],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ApiEndpoint":
        return cls(
            path=str(d.get("path") or ""),
            methods={str(m).upper() for m in d.get("methods") or []},
            dynamic=bool(d.get("dynamic")),
            files=set(d.get("files") or []),
            query_keys={str(k) for k in d.get("query_keys") or []},
            path_param=bool(d.get("path_param")),
        )


@dataclass
class DiscoveryResult:
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    files_total: int = 0
    files_fetched: int = 0
    files_failed: int = 0
    notes: list[str] = field(default_factory=list)
    cached: bool = False

    @property
    def safe_get_paths(self) -> list[str]:
        return [e.path for e in self.endpoints if e.capture_safe]

    def summary(self) -> dict[str, Any]:
        return {
            "files_total": self.files_total,
            "files_fetched": self.files_fetched,
            "files_failed": self.files_failed,
            "endpoints": len(self.endpoints),
            "safe_get": len(self.safe_get_paths),
            "cached": self.cached,
            "notes": list(self.notes)[:10],
        }


# ------------------------------------------------------------------ settings


def _env_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    if raw.isdigit():
        return max(low, min(int(raw), high))
    return default


def max_js_files() -> int:
    return _env_int("ATTESTRA_AUTOMATED_VAPT_JS_FILES", DEFAULT_MAX_JS_FILES, 1, 200)


def budget_seconds() -> int:
    return _env_int("ATTESTRA_AUTOMATED_VAPT_JS_SECONDS", DEFAULT_BUDGET_S, 5, 900)


def enabled() -> bool:
    raw = os.environ.get("ATTESTRA_AUTOMATED_VAPT_JS_API", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    # Unit tests never reach the network unless they opt in.
    return "PYTEST_CURRENT_TEST" not in os.environ


# ------------------------------------------------------------------ helpers


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        port = -1
    return scheme, (p.hostname or "").lower(), port


def is_unsafe_path(url_or_path: str) -> bool:
    """True when a URL/path names a state-changing action (never auto-GET it)."""
    path = urlsplit(url_or_path).path if "://" in url_or_path else url_or_path.split("?", 1)[0]
    return bool(UNSAFE_WORDS_RE.search(path or ""))


def js_urls_from(lines: Iterable[str], root: str) -> list[str]:
    """Same-origin .js/.mjs URLs, app/page chunks first (they hold the app's own calls)."""
    want = _origin(root)
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        u = str(raw or "").strip()
        if not u or "://" not in u:
            continue
        p = urlsplit(u)
        last = (p.path or "").rsplit("/", 1)[-1].lower()
        if not (last.endswith(".js") or last.endswith(".mjs")):
            continue
        if _origin(u) != want:
            continue
        key = u.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(key)

    def prio(u: str) -> tuple[int, int]:
        path = urlsplit(u).path
        if "/chunks/app/" in path or "/chunks/pages/" in path:
            return (0, 0)
        if any(x in path for x in ("polyfills", "webpack-", "framework-", "main-app-", "/main-")):
            return (2, 0)
        return (1, 0)

    return sorted(out, key=prio)


def normalize_api_path(raw: str, root: str) -> tuple[str, bool, list[str], bool] | None:
    """Return ``(path, dynamic, query_keys, path_param)`` for a same-origin API literal, or None.

    ``path`` keeps any fully-specified query string; ``query_keys`` are the parameter names
    seen even when their value was dynamic; ``path_param`` is True when the literal ends with a
    placeholder meant to take an id (``/x/${id}`` or ``/x/`` used for concatenation).
    """
    s = (raw or "").strip()
    if not s:
        return None
    if "://" in s:
        if _origin(s) != _origin(root):
            return None
        p = urlsplit(s)
        s = (p.path or "/") + (f"?{p.query}" if p.query else "")
    dynamic = False
    path_param = False
    query_keys: list[str] = []
    for marker in ("${", "{", ":"):
        # template literal / route placeholder: keep the static prefix only
        idx = s.find(marker, 1)
        if idx != -1 and not (marker == ":" and s[idx - 1] != "/"):
            if "?" not in s[:idx] and s[:idx].rstrip().endswith("/"):
                path_param = True
            s = s[:idx]
            dynamic = True
    if "#" in s:
        s = s.split("#", 1)[0]
    raw_path, _, query = s.partition("?")
    if raw_path.endswith("/"):
        # trailing slash in the literal usually means an id is concatenated on.
        path_param = True
    if query:
        pairs = [q for q in query.split("&") if q]
        keep: list[str] = []
        for q in pairs:
            k, eq, v = q.partition("=")
            if k:
                query_keys.append(k)
            if not eq or v == "":
                dynamic = True  # value supplied at runtime
            else:
                keep.append(q)
        query = "&".join(keep)
    elif s.endswith("?"):
        dynamic = True
    path = raw_path
    if path.endswith("/") or path.endswith("="):
        dynamic = True
    path = path.rstrip("/") or "/"
    if not _PATH_CHARS_RE.match(path):
        return None
    segs = [x for x in path.split("/") if x]
    if len(segs) < 2:  # bare "/api" or "/v1" base path
        return None
    if ".." in segs:
        return None
    last = segs[-1]
    if "." in last and last.rsplit(".", 1)[-1].lower() in _STATIC_EXT:
        return None
    if query:
        path = f"{path}?{query}"
    return path, dynamic, query_keys, path_param


def extract_api_endpoints(text: str, root: str, *, source: str = "") -> list[ApiEndpoint]:
    """API endpoints named in one JS/HTML text (same-origin only, de-duplicated)."""
    found: dict[str, ApiEndpoint] = {}

    def add(raw: str, method: str | None) -> None:
        norm = normalize_api_path(raw, root)
        if norm is None:
            return
        path, dynamic, query_keys, path_param = norm
        ep = found.get(path)
        if ep is None:
            ep = found[path] = ApiEndpoint(path=path)
        ep.dynamic = ep.dynamic or dynamic
        ep.path_param = ep.path_param or path_param
        ep.query_keys.update(query_keys)
        if method:
            ep.methods.add(method.upper())
        if source:
            ep.files.add(source)

    typed: set[tuple[int, int]] = set()
    for m in _CALL_RE.finditer(text or ""):
        method = m.group(1).upper()
        add(m.group(3), None if method == "REQUEST" else method)
        typed.add(m.span(3))
    for m in _FETCH_RE.finditer(text or ""):
        opts = m.group(3) or ""
        mm = _FETCH_METHOD_RE.search(opts)
        add(m.group(2), (mm.group(1) if mm else "GET"))
        typed.add(m.span(2))
    for m in _LITERAL_RE.finditer(text or ""):
        if m.span(2) in typed:
            continue
        add(m.group(2), None)
    return list(found.values())


def merge_endpoints(groups: Iterable[Iterable[ApiEndpoint]]) -> list[ApiEndpoint]:
    out: dict[str, ApiEndpoint] = {}
    for group in groups:
        for ep in group:
            cur = out.get(ep.path)
            if cur is None:
                out[ep.path] = ApiEndpoint(
                    path=ep.path,
                    methods=set(ep.methods),
                    dynamic=ep.dynamic,
                    files=set(ep.files),
                    query_keys=set(ep.query_keys),
                    path_param=ep.path_param,
                )
            else:
                cur.methods |= ep.methods
                cur.dynamic = cur.dynamic or ep.dynamic
                cur.files |= ep.files
                cur.query_keys |= ep.query_keys
                cur.path_param = cur.path_param or ep.path_param
    return sorted(out.values(), key=lambda e: e.path)


# ------------------------------------------------------------------ fetching


Fetch = Callable[[str], tuple[int, str]]


def default_fetch(client: Any | None = None, *, timeout_s: float = FETCH_TIMEOUT_S) -> tuple[Fetch, Callable[[], None]]:
    """GET without auth, no redirects, body capped at MAX_JS_BYTES. Returns (fetch, close)."""
    import httpx

    http = client or httpx.Client(timeout=timeout_s, follow_redirects=False, headers={"User-Agent": USER_AGENT})
    owns = client is None

    def _fetch(url: str) -> tuple[int, str]:
        with http.stream("GET", url) as resp:
            if resp.status_code != 200:
                return resp.status_code, ""
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf.extend(chunk)
                if len(buf) >= MAX_JS_BYTES:
                    break
            return resp.status_code, bytes(buf[:MAX_JS_BYTES]).decode("utf-8", "replace")

    def _close() -> None:
        if owns:
            http.close()

    return _fetch, _close


def discover_from_js(
    lines: Iterable[str],
    root: str,
    *,
    scope: Any | None = None,
    check_dns: bool = True,
    fetch: Fetch | None = None,
    max_files: int | None = None,
    budget_s: int | None = None,
    cache_path: Path | str | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> DiscoveryResult:
    """Fetch same-origin JS from ``lines`` (e.g. zap-urls.txt) and extract API endpoints."""
    if cache_path is not None:
        cached = load_cache(cache_path, root)
        if cached is not None:
            return cached

    js = js_urls_from(lines, root)
    res = DiscoveryResult(files_total=len(js))
    cap = max_files or max_js_files()
    if len(js) > cap:
        res.notes.append(f"{len(js)} JS file(s) found; only the first {cap} were read")
        js = js[:cap]
    budget = budget_s or budget_seconds()
    deadline = clock() + budget

    close: Callable[[], None] = lambda: None
    if fetch is None:
        fetch, close = default_fetch()
    groups: list[list[ApiEndpoint]] = []
    try:
        for url in js:
            if clock() >= deadline:
                res.notes.append(f"stopped after {budget}s budget")
                break
            if scope is not None:
                try:
                    from attestra.automated_vapt.core import scope_validator

                    scope_validator.validate_target_url(url, scope, check_dns=check_dns)
                except Exception:  # noqa: BLE001 - out of scope / SSRF guard: skip the file
                    res.files_failed += 1
                    continue
            try:
                status, text = fetch(url)
            except Exception:  # noqa: BLE001 - one bad file never stops discovery
                res.files_failed += 1
                continue
            if status != 200 or not text:
                res.files_failed += 1
                continue
            res.files_fetched += 1
            name = urlsplit(url).path.rsplit("/", 1)[-1]
            groups.append(extract_api_endpoints(text, root, source=name))
    finally:
        close()
    res.endpoints = merge_endpoints(groups)
    if cache_path is not None and res.files_fetched:
        save_cache(cache_path, root, res)
    return res


# ------------------------------------------------------------------ cache


def load_cache(path: Path | str, root: str) -> DiscoveryResult | None:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if doc.get("version") != CACHE_VERSION or _origin(str(doc.get("root") or "")) != _origin(root):
        return None
    res = DiscoveryResult(
        endpoints=[ApiEndpoint.from_dict(d) for d in doc.get("endpoints") or []],
        files_total=int(doc.get("files_total") or 0),
        files_fetched=int(doc.get("files_fetched") or 0),
        files_failed=int(doc.get("files_failed") or 0),
        notes=list(doc.get("notes") or []),
        cached=True,
    )
    return res


def save_cache(path: Path | str, root: str, res: DiscoveryResult) -> None:
    doc = {
        "version": CACHE_VERSION,
        "root": root,
        "files_total": res.files_total,
        "files_fetched": res.files_fetched,
        "files_failed": res.files_failed,
        "notes": res.notes,
        "endpoints": [e.to_dict() for e in res.endpoints],
    }
    try:
        Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        pass
