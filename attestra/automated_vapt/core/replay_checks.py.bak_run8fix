"""GET-only replay checks for automated VAPT: auth bypass (T19), IDOR (T20), input (T21).

Each check:
1. uses the login profile's session (``session_auth``) and the JS-discovered API list,
2. GETs endpoints while authenticated to establish a baseline of real data,
3. replays with a modified request (no auth / bad token / swapped id / bad param),
4. flags a finding when the modified response still looks like the authenticated data
   (or, for input, when the server returns 5xx / stack / SQL / reflected XSS),
5. returns redacted HttpPair evidence for the original and modified exchanges so the
   existing report / two-panel rendering path can attach them.

Never issues POST/PUT/PATCH/DELETE. Caps and a short sleep bound request volume.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from attestra.automated_vapt.core import js_api_discovery as jsd
from attestra.automated_vapt.core import scope_validator
from attestra.automated_vapt.core.session_auth import SessionAuth

DEFAULT_AUTH_CAP = 20
DEFAULT_IDOR_CAP = 40
DEFAULT_INPUT_CAP = 30
DEFAULT_SLEEP_S = 0.15
BODY_COMPARE_BYTES = 8_000
BODY_EVIDENCE_BYTES = 20_000
INVALID_BEARER = "Bearer INVALID_TOKEN_attestra_replay_check_do_not_use"

# Structured skip/block reason codes surfaced in case results and reports so a SKIPPED
# T19/T20/T21/T22 is never read as "tested and clean". Report rendering (Phase 5) and
# checklist_auto turn these into visible limitations.
SKIP_NO_AUTH_SESSION = "no_auth_session"
SKIP_NO_CAPTURE_SAFE_API = "no_capture_safe_api"
SKIP_NO_JSON_GET_BODIES = "no_json_get_bodies"
SKIP_NO_OBJECT_IDS = "no_object_ids"
SKIP_NO_IDOR_ENDPOINTS = "no_idor_endpoints"
SKIP_NO_WRITE_TEMPLATES = "no_write_templates"
SKIP_MUTATION_DISABLED = "mutation_disabled"
SKIP_APP_ENV_BLOCKED = "app_env_blocked"
SKIP_NO_PARAM_ENDPOINTS = "no_param_endpoints"

# Response body signals that a protected JSON API answered with real data (not an SPA shell
# or a blank/error envelope). Used for the auth-bypass and IDOR checks.
_DATA_KEYS_RE = re.compile(
    r'"(?:data|items|results|projects|clients|users|records|rows|list|'
    r'project_id|projectId|client_id|clientId|user_id|userId|id)"\s*:',
    re.I,
)
_HTML_SHELL_RE = re.compile(r"(?i)<!doctype\s+html|<html[\s>]")
_ERROR_STATUS_RE = re.compile(r'(?i)"(?:status|success|ok)"\s*:\s*(?:"?(?:error|fail|false|0)"?|false)')
_EMPTY_LIST_RE = re.compile(r'"(?:data|items|results|projects|clients|users|records|rows|list)"\s*:\s*\[\s*\]')

# Harvest object ids from authenticated JSON bodies.
_ID_KEY_RE = re.compile(
    r'"(?P<k>project_id|projectId|client_id|clientId|user_id|userId|'
    r'tenant_id|tenantId|account_id|accountId|(?<![A-Za-z0-9_])id)"\s*:\s*'
    r'(?:"(?P<s>[A-Za-z0-9_\-]{1,64})"'
    r'|(?P<n>-?\d{1,18}))',
    re.I,
)

# Server-side error / injection signals for the input check.
_STACK_RE = re.compile(
    r"(?i)(traceback \(most recent call last\)|at [\w.$]+\([\w./\\]+:\d+:\d+\)|"
    r"System\.(NullReference|Argument|InvalidOperation)Exception|"
    r"java\.lang\.\w+Exception|org\.springframework|"
    r"SQLSTATE|ORA-\d{5}|syntax error at|pg_query|mysql_fetch|"
    r"Uncaught (?:PDO|mysqli|TypeError|ReferenceError)|"
    r"StackTrace:|ErrorException|Fatal error:|"
    r"/var/www/|/home/\w+/|/usr/src/|C:\\\\Users\\\\|"
    r"Internal Server Error)"
)
_REFLECT_SCRIPT = "<script>alert(1)</script>"

INPUT_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("sqli_quote", "'"),
    ("sqli_dquote", '"'),
    ("xss_script", _REFLECT_SCRIPT),
    ("path_traversal", "../" * 8 + "etc/passwd"),
    ("long_string", "A" * 2000),
    ("wrong_type", "abcXYZ"),
)


@dataclass
class CaptureResult:
    url: str
    status: int | None
    body: str
    pair: Any | None = None  # redacted HttpPair
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and self.error == ""

    @property
    def substantive(self) -> bool:
        """True when the body looks like authenticated API data (not SPA / empty / error)."""
        if not self.ok or self.status != 200:
            return False
        body = self.body or ""
        if _HTML_SHELL_RE.search(body[:2000]):
            return False
        if len(body.strip()) < 20:
            return False
        if _ERROR_STATUS_RE.search(body[:2000]) and not _DATA_KEYS_RE.search(body[:BODY_COMPARE_BYTES]):
            return False
        if _EMPTY_LIST_RE.search(body[:BODY_COMPARE_BYTES]) and not _DATA_KEYS_RE.search(body[200:BODY_COMPARE_BYTES]):
            # empty list alone is not "real data"
            return False
        return bool(_DATA_KEYS_RE.search(body[:BODY_COMPARE_BYTES])) or (
            body.lstrip().startswith(("{", "[")) and len(body) >= 80
        )


@dataclass
class EndpointOutcome:
    url: str
    check: str
    status: str  # PASSED | FINDING | SKIPPED | FAILED
    detail: str
    auth_status: int | None = None
    probe_status: int | None = None
    finding: bool = False
    evidence_pairs: list[Any] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "check": self.check,
            "status": self.status,
            "detail": self.detail,
            "auth_status": self.auth_status,
            "probe_status": self.probe_status,
            "finding": self.finding,
            "meta": self.meta,
        }


# ------------------------------------------------------------------ helpers


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        port = -1
    return scheme, (p.hostname or "").lower(), port


_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|refresh|session|cookie|private)"
)
_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_ID_NAME_RE = re.compile(r"(?i)^(id|.+_id|.+Id)$")


def _canon_id_key(raw: str) -> str:
    return re.sub(r"([a-z])([A-Z])", r"\1_\2", raw or "").lower()


def _is_harvestable_id_value(val: Any) -> bool:
    if isinstance(val, bool) or val is None:
        return False
    if isinstance(val, int):
        return True
    if not isinstance(val, str):
        return False
    s = val.strip()
    if not s or len(s) > 64:
        return False
    if _SECRET_KEY_RE.search(s):
        return False
    if s.isdigit() or _UUID_RE.match(s):
        return True
    # Short opaque object ids (alphanumeric / hyphen / underscore), not emails or URLs.
    if "@" in s or "://" in s or "/" in s:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", s))


def _walk_json_ids(node: Any, out: dict[str, set[str]], *, depth: int = 0) -> None:
    """Collect nested ``id`` / ``*_id`` / ``*Id`` values from parsed JSON (cap depth)."""
    if depth > 6:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            key = str(k)
            if _SECRET_KEY_RE.search(key):
                continue
            if _ID_NAME_RE.match(key) and _is_harvestable_id_value(v):
                canon = _canon_id_key(key)
                out.setdefault(canon, set()).add(str(v).strip() if not isinstance(v, int) else str(v))
            elif isinstance(v, (dict, list)):
                _walk_json_ids(v, out, depth=depth + 1)
    elif isinstance(node, list):
        for item in node[:200]:
            _walk_json_ids(item, out, depth=depth + 1)


def harvest_ids(text: str) -> dict[str, set[str]]:
    """``{canonical_key: {id, ...}}`` from a JSON (or JSON-ish) body. Values are strings.

    Combines a regex pass (fast, works on partial JSON) with a nested walk when the body
    parses, so ``data.items[].id`` / ``projectId`` lists feed T20 even when keys nest.
    Never harvests secret-looking keys or values.
    """
    out: dict[str, set[str]] = {}
    for m in _ID_KEY_RE.finditer(text or ""):
        raw = m.group("k") or ""
        if _SECRET_KEY_RE.search(raw):
            continue
        key = _canon_id_key(raw)
        val = m.group("s") if m.group("s") is not None else m.group("n")
        if not val or not _is_harvestable_id_value(val):
            continue
        out.setdefault(key, set()).add(val)
    try:
        parsed = json.loads(text or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    if parsed is not None:
        _walk_json_ids(parsed, out)
    return out


def merge_harvested_ids(store: dict[str, set[str]], text: str) -> dict[str, set[str]]:
    """Merge [[harvest_ids]] into an existing inventory dict (mutates and returns ``store``)."""
    for k, vals in harvest_ids(text).items():
        store.setdefault(k, set()).update(vals)
    return store


def record_harvest_into_ctx(ctx: Any, text: str, *, url: str = "") -> int:
    """Persist harvested ids on ``ctx.extra['_harvested_ids']`` for later T20/T22.

    Also appends ``url`` to ``_capture_api_urls`` when the body looks like substantive JSON
    API data so T20 has a shared inventory even if JS discovery missed the path.
    Returns the count of newly seen id values.
    """
    extra = getattr(ctx, "extra", None)
    if not isinstance(extra, dict):
        return 0
    before = sum(len(v) for v in (extra.get("_harvested_ids") or {}).values())
    store: dict[str, set[str]] = {
        str(k): set(v) if not isinstance(v, set) else v
        for k, v in (extra.get("_harvested_ids") or {}).items()
    }
    merge_harvested_ids(store, text or "")
    extra["_harvested_ids"] = store
    after = sum(len(v) for v in store.values())
    # Promote substantive JSON responses onto the capture-safe API list for T19/T20.
    body = text or ""
    if url and body and not _HTML_SHELL_RE.search(body[:200]):
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, (dict, list)) and (
            _DATA_KEYS_RE.search(body) or (isinstance(parsed, list) and parsed) or store
        ):
            urls = list(extra.get("_capture_api_urls") or [])
            if url not in urls:
                urls.append(url)
                extra["_capture_api_urls"] = urls
    return max(0, after - before)


def neighbour_ids(known: set[str], *, span: int = 3) -> list[str]:
    """Numeric ids near the harvested set that are not in it (candidates the user shouldn't own)."""
    nums: list[int] = []
    for v in known:
        try:
            nums.append(int(v))
        except ValueError:
            continue
    if not nums:
        return []
    out: list[str] = []
    seen = set(known)
    # Prefer +1..+span then -1..-span so "next" ids are tried first.
    deltas = [d for d in range(1, span + 1)] + [-d for d in range(1, span + 1)]
    for n in sorted(nums):
        for d in deltas:
            cand = str(n + d)
            if cand in seen:
                continue
            seen.add(cand)
            out.append(cand)
    return out


def body_shape(text: str) -> tuple[str, int, int]:
    """``(kind, length, approx_keys)`` — used to compare authenticated vs probe responses."""
    body = (text or "").strip()
    length = len(body)
    if not body:
        return ("empty", 0, 0)
    if body[0] in "{[":
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return ("jsonish", length, body.count('":'))
        if isinstance(data, dict):
            return ("object", length, len(data))
        if isinstance(data, list):
            return ("array", length, len(data))
    if _HTML_SHELL_RE.search(body[:500]):
        return ("html", length, 0)
    return ("text", length, 0)


def responses_similar(auth: CaptureResult, probe: CaptureResult) -> bool:
    """True when the unauth/probe response still looks like the authenticated data."""
    if not auth.substantive or not probe.ok or probe.status != 200:
        return False
    if not probe.substantive:
        return False
    a_kind, a_len, a_keys = body_shape(auth.body)
    p_kind, p_len, p_keys = body_shape(probe.body)
    if a_kind != p_kind:
        return False
    if a_len == 0:
        return False
    # length within 40% and key counts close (or both lists non-empty)
    ratio = p_len / max(a_len, 1)
    if ratio < 0.4 or ratio > 2.5:
        return False
    if a_keys and p_keys and abs(a_keys - p_keys) > max(3, a_keys):
        return False
    return True


def input_finding(status: int | None, body: str, payload: str) -> tuple[bool, str]:
    """Return ``(is_finding, reason)`` for an input-validation probe response."""
    if status is not None and status >= 500:
        return True, f"server returned HTTP {status}"
    text = body or ""
    if _STACK_RE.search(text[:BODY_COMPARE_BYTES]):
        return True, "response body leaks stack / SQL / framework error"
    if payload == _REFLECT_SCRIPT and _REFLECT_SCRIPT in text:
        # reflected unescaped
        return True, "XSS payload reflected unescaped in response"
    return False, ""


# ------------------------------------------------------------------ capture


def _do_get(
    url: str,
    *,
    headers: dict[str, str] | None,
    scope: Any,
    profile: str,
    client: Any | None,
    check_dns: bool,
    auth: SessionAuth | None,
) -> CaptureResult:
    from attestra.automated_vapt.capture.http_capture import capture_request

    try:
        tx = capture_request(
            "GET",
            url,
            scope=scope,
            profile=profile,
            headers=headers or None,
            client=client,
            check_dns=check_dns,
        )
    except Exception as exc:  # noqa: BLE001
        detail = str(exc)
        if auth is not None:
            detail = auth.scrub(detail)
        return CaptureResult(url=url, status=None, body="", error=detail)

    report = tx.report_pair or tx.pair.redacted()
    if auth is not None and auth.redact_values:
        report.response_body = auth.scrub(report.response_body)
        report.request_body = auth.scrub(report.request_body)
        report.request_headers = {k: auth.scrub(v) for k, v in report.request_headers.items()}
        report.response_headers = {k: auth.scrub(v) for k, v in report.response_headers.items()}
        tx.report_pair = report
    # Cap stored body size so evidence stays bounded.
    if len(report.response_body or "") > BODY_EVIDENCE_BYTES:
        report.response_body = (report.response_body or "")[:BODY_EVIDENCE_BYTES] + "\n…[truncated]"
    return CaptureResult(url=url, status=report.status, body=report.response_body or "", pair=report)


def _strip_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    drop = {"authorization", "cookie", "proxy-authorization", "x-auth-token", "x-access-token"}
    return {k: v for k, v in headers.items() if k.lower() not in drop}


def _invalid_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    out = _strip_auth_headers(headers)
    # Prefer replacing Authorization; if the profile used a Cookie, leave Cookie empty
    # and send a fake Bearer so the probe is still "authenticated-looking".
    out["Authorization"] = INVALID_BEARER
    return out


# ------------------------------------------------------------------ endpoints


def _endpoints_from_ctx(ctx: Any) -> list[jsd.ApiEndpoint]:
    raw = (ctx.extra.get("_js_api") or {}).get("endpoints_list") or []
    out: list[jsd.ApiEndpoint] = []
    for d in raw:
        if isinstance(d, dict) and d.get("path"):
            out.append(jsd.ApiEndpoint.from_dict(d))
    return out


def _abs(root: str, path: str) -> str:
    return urljoin(root if root.endswith("/") else root + "/", path.lstrip("/"))


def _api_root(ctx: Any) -> str:
    """Base for relative API paths: resolved API base for the run, else the target."""
    from attestra.automated_vapt.core.api_base import api_root

    return api_root(ctx)


def _build_scope(ctx: Any, urls: list[str]):
    return scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        extra_seeds=[u for u in urls if u],
        allow_private=ctx.allow_private,
    )


# ------------------------------------------------------------------ T19 auth bypass


def run_auth_bypass(
    ctx: Any,
    *,
    cap: int = DEFAULT_AUTH_CAP,
    sleep_s: float = DEFAULT_SLEEP_S,
    clock_sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """T19: replay each authenticated 200 API without auth and with a bad bearer."""
    auth: SessionAuth | None = ctx.extra.get("_session_auth")
    auth_info = auth.public() if auth is not None else {"profile_id": None, "status": "none", "note": "", "injected": []}
    if auth is None or auth.status != "ready":
        return {
            "test_id": "T19",
            "status": "SKIPPED",
            "detail": f"login profile not ready ({auth_info.get('status')}: {auth_info.get('note')})",
            "skip_reason": SKIP_NO_AUTH_SESSION,
            "category": "authentication",
            "auth": auth_info,
            "endpoints": [],
            "validation": {},
        }

    api_urls = list(ctx.extra.get("_capture_api_urls") or [])
    if not api_urls:
        # fall back to capture_safe endpoints from js discovery
        api_urls = [_abs(_api_root(ctx), e.path) for e in _endpoints_from_ctx(ctx) if e.capture_safe]
    api_urls = api_urls[:cap]
    if not api_urls:
        return {
            "test_id": "T19",
            "status": "SKIPPED",
            "detail": "no capture-safe API endpoints discovered (no authenticated JSON GET URLs from T01/T02/JS discovery)",
            "skip_reason": SKIP_NO_CAPTURE_SAFE_API,
            "category": "authentication",
            "auth": auth_info,
            "endpoints": [],
            "validation": {},
        }

    scope = _build_scope(ctx, api_urls)
    client = ctx.extra.get("httpx_client")
    outcomes: list[EndpointOutcome] = []
    evidence: list[Any] = []
    findings = 0

    for url in api_urls:
        base_headers = auth.headers_for(url, ctx.target_base_url)
        auth_cap = _do_get(
            url, headers=base_headers, scope=scope, profile=ctx.profile,
            client=client, check_dns=not ctx.allow_private, auth=auth,
        )
        clock_sleep(sleep_s)
        if not auth_cap.ok or auth_cap.status != 200 or not auth_cap.substantive:
            outcomes.append(EndpointOutcome(
                url=url, check="auth_bypass", status="SKIPPED",
                detail=(
                    f"auth baseline not substantive (HTTP {auth_cap.status}"
                    + (f": {auth_cap.error}" if auth_cap.error else "") + ")"
                ),
                auth_status=auth_cap.status,
            ))
            continue

        # (a) no auth
        none_cap = _do_get(
            url, headers={}, scope=scope, profile=ctx.profile,
            client=client, check_dns=not ctx.allow_private, auth=auth,
        )
        clock_sleep(sleep_s)
        # (b) invalid bearer
        bad_cap = _do_get(
            url, headers=_invalid_auth_headers(base_headers), scope=scope, profile=ctx.profile,
            client=client, check_dns=not ctx.allow_private, auth=auth,
        )
        clock_sleep(sleep_s)

        hit = None
        for label, probe in (("no_auth", none_cap), ("invalid_token", bad_cap)):
            if responses_similar(auth_cap, probe):
                hit = (label, probe)
                break

        pairs = [p for p in (auth_cap.pair, none_cap.pair, bad_cap.pair) if p is not None]
        if hit is not None:
            findings += 1
            label, probe = hit
            for p in pairs:
                evidence.append(p)
            outcomes.append(EndpointOutcome(
                url=url, check="auth_bypass", status="FINDING",
                detail=f"broken authentication: {label} still returned substantive HTTP {probe.status}",
                auth_status=auth_cap.status, probe_status=probe.status, finding=True,
                evidence_pairs=pairs,
                meta={"probe": label, "auth_len": len(auth_cap.body), "probe_len": len(probe.body)},
            ))
        else:
            # still keep one pair of evidence for the run folder
            if auth_cap.pair is not None:
                evidence.append(auth_cap.pair)
            if none_cap.pair is not None:
                evidence.append(none_cap.pair)
            outcomes.append(EndpointOutcome(
                url=url, check="auth_bypass", status="PASSED",
                detail=(
                    f"auth required (no_auth HTTP {none_cap.status}, "
                    f"invalid_token HTTP {bad_cap.status})"
                ),
                auth_status=auth_cap.status,
                probe_status=none_cap.status,
                evidence_pairs=pairs,
                meta={"no_auth": none_cap.status, "invalid_token": bad_cap.status},
            ))

    validation: dict[str, Any] = {}
    if findings:
        validation = {
            "status": "CONFIRMED",
            "confidence": "high",
            "reasons": [f"{findings} endpoint(s) returned substantive data without a valid session"],
            "cwe": 287,
            "title_suffix": "broken authentication",
            "recommendation": "Require a valid session on every protected API and return 401/403 otherwise.",
        }
    status = "FINDING" if findings else "PASSED"
    return {
        "test_id": "T19",
        "status": status,
        "detail": (
            f"auth bypass: {findings} finding(s) across {len(outcomes)} endpoint(s); "
            f"auth: {auth_info['status']} (profile #{auth_info.get('profile_id')})"
        ),
        "category": "authentication",
        "auth": auth_info,
        "endpoints": [o.to_dict() for o in outcomes],
        "finding_count": findings,
        "validation": validation,
        "evidence_pairs": evidence,
        "finding_evidence_pairs": [p for o in outcomes if o.finding for p in o.evidence_pairs],
        "finding_title": "Broken authentication on API endpoints" if findings else "",
        "finding_location": next((o.url for o in outcomes if o.finding), ctx.target_base_url),
        "finding_cwe": 287,
        "finding_recommendation": validation.get("recommendation", ""),
    }


# ------------------------------------------------------------------ T20 IDOR


def _fill_idor_url(root: str, ep: jsd.ApiEndpoint, oid: str) -> str | None:
    """Build a concrete GET URL for an idor-candidate endpoint with the given object id."""
    if not ep.idor_candidate:
        return None
    path = ep.path
    if ep.path_param:
        # append id as a trailing path segment
        base = path.split("?", 1)[0].rstrip("/")
        return _abs(root, f"{base}/{oid}")
    keys = ep.id_query_keys or list(ep.query_keys)
    if not keys:
        return None
    # put the id into the first id-like query key; leave others empty/omitted
    q = [(keys[0], oid)]
    return _abs(root, path.split("?", 1)[0]) + "?" + urlencode(q)


def run_idor(
    ctx: Any,
    *,
    cap: int = DEFAULT_IDOR_CAP,
    sleep_s: float = DEFAULT_SLEEP_S,
    clock_sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """T20: swap harvested object ids into dynamic GET endpoints."""
    auth: SessionAuth | None = ctx.extra.get("_session_auth")
    auth_info = auth.public() if auth is not None else {"profile_id": None, "status": "none", "note": "", "injected": []}
    secondary: SessionAuth | None = ctx.extra.get("_secondary_session_auth")
    secondary_info = (
        secondary.public()
        if secondary is not None
        else {"profile_id": None, "status": "none", "note": "not configured"}
    )
    if auth is None or auth.status != "ready":
        return {
            "test_id": "T20",
            "status": "SKIPPED",
            "detail": f"login profile not ready ({auth_info.get('status')}: {auth_info.get('note')})",
            "skip_reason": SKIP_NO_AUTH_SESSION,
            "category": "authorization",
            "auth": auth_info,
            "endpoints": [],
            "validation": {},
        }

    # 1) authenticated baseline of capture-safe APIs → harvest ids. Reuse ids already
    # harvested by T01 (shared inventory in ctx.extra) so a GET that only appears once
    # still contributes, then confirm with a fresh baseline fetch.
    safe_urls = list(ctx.extra.get("_capture_api_urls") or [])
    if not safe_urls:
        safe_urls = [_abs(_api_root(ctx), e.path) for e in _endpoints_from_ctx(ctx) if e.capture_safe]
    safe_urls = safe_urls[: max(5, min(cap // 2, 15))]
    scope = _build_scope(ctx, safe_urls)
    client = ctx.extra.get("httpx_client")
    harvested: dict[str, set[str]] = {}
    for k, vals in (ctx.extra.get("_harvested_ids") or {}).items():
        harvested.setdefault(k, set()).update(vals)
    seed_pairs: list[Any] = []
    json_get_bodies = 0
    for url in safe_urls:
        headers = auth.headers_for(url, ctx.target_base_url)
        cap_r = _do_get(
            url, headers=headers, scope=scope, profile=ctx.profile,
            client=client, check_dns=not ctx.allow_private, auth=auth,
        )
        clock_sleep(sleep_s)
        if cap_r.pair is not None:
            seed_pairs.append(cap_r.pair)
        if not cap_r.substantive:
            continue
        json_get_bodies += 1
        for k, vals in harvest_ids(cap_r.body).items():
            harvested.setdefault(k, set()).update(vals)

    owned = set()
    for vals in harvested.values():
        owned |= vals
    if not owned:
        if not json_get_bodies and not (ctx.extra.get("_harvested_ids")):
            reason, detail = SKIP_NO_JSON_GET_BODIES, (
                "no authenticated JSON GET responses to harvest object ids from "
                f"({len(safe_urls)} capture-safe URL(s) returned no substantive JSON)"
            )
        else:
            reason, detail = SKIP_NO_OBJECT_IDS, "no object ids harvested from authenticated API responses"
        return {
            "test_id": "T20",
            "status": "SKIPPED",
            "detail": detail,
            "skip_reason": reason,
            "category": "authorization",
            "auth": auth_info,
            "endpoints": [],
            "harvested_keys": sorted(harvested.keys()),
            "validation": {},
            "evidence_pairs": seed_pairs,
        }

    # Prefer project/client ids for the swap; fall back to any harvested set.
    preferred_keys = ("project_id", "client_id", "user_id", "tenant_id", "account_id", "id")
    owned_primary: set[str] = set()
    for k in preferred_keys:
        if harvested.get(k):
            owned_primary = set(harvested[k])
            break
    if not owned_primary:
        owned_primary = set(owned)

    candidates = [e for e in _endpoints_from_ctx(ctx) if e.idor_candidate]
    if not candidates:
        return {
            "test_id": "T20",
            "status": "SKIPPED",
            "detail": f"harvested {len(owned)} id(s) but no dynamic GET endpoints take an id",
            "skip_reason": SKIP_NO_IDOR_ENDPOINTS,
            "category": "authorization",
            "auth": auth_info,
            "endpoints": [],
            "harvested_keys": sorted(harvested.keys()),
            "validation": {},
            "evidence_pairs": seed_pairs,
        }

    foreign = neighbour_ids(owned_primary, span=3)
    if not foreign:
        # non-numeric ids: invent a clearly-foreign token
        foreign = [f"attestra-idor-{i}" for i in range(1, 4)]

    outcomes: list[EndpointOutcome] = []
    evidence: list[Any] = list(seed_pairs)
    findings = 0
    requests_left = cap

    for ep in candidates:
        if requests_left <= 0:
            break
        # baseline with an owned id
        owned_id = next(iter(owned_primary))
        base_url = _fill_idor_url(_api_root(ctx), ep, owned_id)
        if not base_url:
            continue
        # refresh scope to cover the new URLs
        scope = _build_scope(ctx, [base_url])
        headers = auth.headers_for(base_url, ctx.target_base_url)
        base_cap = _do_get(
            base_url, headers=headers, scope=scope, profile=ctx.profile,
            client=client, check_dns=not ctx.allow_private, auth=auth,
        )
        requests_left -= 1
        clock_sleep(sleep_s)
        if not base_cap.substantive:
            outcomes.append(EndpointOutcome(
                url=base_url, check="idor", status="SKIPPED",
                detail=f"owned-id baseline not substantive (HTTP {base_cap.status})",
                auth_status=base_cap.status,
                meta={"owned_id_used": True, "endpoint": ep.path},
            ))
            continue

        hit = None
        probe_cap = None
        probe_url = None
        for fid in foreign[:3]:
            if requests_left <= 0:
                break
            probe_url = _fill_idor_url(_api_root(ctx), ep, fid)
            if not probe_url:
                continue
            scope = _build_scope(ctx, [probe_url])
            probe_auth = (
                secondary
                if secondary is not None and secondary.status == "ready"
                else auth
            )
            probe_headers = probe_auth.headers_for(probe_url, ctx.target_base_url) or headers
            probe_cap = _do_get(
                probe_url, headers=probe_headers, scope=scope, profile=ctx.profile,
                client=client, check_dns=not ctx.allow_private, auth=probe_auth,
            )
            requests_left -= 1
            clock_sleep(sleep_s)
            if responses_similar(base_cap, probe_cap) and probe_cap.substantive:
                # Make sure the body isn't just echoing the owned object (same id set)
                probe_ids = set()
                for vals in harvest_ids(probe_cap.body).values():
                    probe_ids |= vals
                # finding if the probe returned data that includes the foreign id, OR
                # returned a non-empty payload of similar shape (admin may see all —
                # still flag as POTENTIAL)
                hit = (fid, probe_cap, probe_ids)
                break

        pairs = [p for p in (base_cap.pair, getattr(probe_cap, "pair", None)) if p is not None]
        if hit is not None:
            findings += 1
            fid, probe_cap, probe_ids = hit
            for p in pairs:
                evidence.append(p)
            outcomes.append(EndpointOutcome(
                url=probe_url or base_url, check="idor", status="FINDING",
                detail=(
                    f"possible IDOR: foreign id {fid!r} returned substantive HTTP {probe_cap.status} "
                    f"(admin may legitimately see all — confirm manually)"
                ),
                auth_status=base_cap.status, probe_status=probe_cap.status, finding=True,
                evidence_pairs=pairs,
                meta={
                    "endpoint": ep.path,
                    "owned_id": owned_id,
                    "foreign_id": fid,
                    "probe_ids_count": len(probe_ids),
                },
            ))
        else:
            if base_cap.pair is not None:
                evidence.append(base_cap.pair)
            outcomes.append(EndpointOutcome(
                url=base_url, check="idor", status="PASSED",
                detail=(
                    f"foreign ids rejected or empty "
                    f"(owned HTTP {base_cap.status}"
                    + (f", last probe HTTP {probe_cap.status}" if probe_cap is not None else "")
                    + ")"
                ),
                auth_status=base_cap.status,
                probe_status=getattr(probe_cap, "status", None),
                evidence_pairs=pairs,
                meta={"endpoint": ep.path, "owned_id": owned_id, "probes": min(3, len(foreign))},
            ))

    secondary_ready = secondary is not None and secondary.status == "ready"
    validation: dict[str, Any] = {}
    if findings:
        validation = {
            "status": "CONFIRMED" if secondary_ready else "POTENTIAL",
            "confidence": "high" if secondary_ready else "medium",
            "reasons": [
                f"{findings} endpoint(s) returned substantive data for a foreign object id; "
                + (
                    "probed with secondary login profile"
                    if secondary_ready
                    else "confirm the role is not meant to see all objects (no secondary profile)"
                )
            ],
            "cwe": 639,
            "title_suffix": "possible IDOR / BOLA",
            "recommendation": (
                "Enforce object-level authorization: reject requests for objects the caller does not own, "
                "even when the caller is an admin of a different tenant. Retest with a non-admin role."
            ),
        }
    status = "FINDING" if findings else ("PASSED" if outcomes else "SKIPPED")
    detail = (
        f"IDOR: {findings} finding(s) across {len(outcomes)} endpoint(s); "
        f"harvested {len(owned)} id(s) over {sorted(harvested.keys()) or ['—']}; "
        f"auth: {auth_info['status']} (profile #{auth_info.get('profile_id')})"
        + (
            f"; secondary profile #{secondary_info.get('profile_id')} ready"
            if secondary_ready
            else "; no secondary (non-admin) profile — admin-only IDOR, confirm manually"
        )
    )
    return {
        "test_id": "T20",
        "status": status,
        "detail": detail,
        "category": "authorization",
        "auth": auth_info,
        "secondary_auth": secondary_info,
        "endpoints": [o.to_dict() for o in outcomes],
        "finding_count": findings,
        "harvested_keys": sorted(harvested.keys()),
        "harvested_count": len(owned),
        "validation": validation,
        "evidence_pairs": evidence,
        "finding_evidence_pairs": [p for o in outcomes if o.finding for p in o.evidence_pairs],
        "finding_title": "Possible IDOR / BOLA on API endpoints" if findings else "",
        "finding_location": next((o.url for o in outcomes if o.finding), ctx.target_base_url),
        "finding_cwe": 639,
        "finding_recommendation": validation.get("recommendation", ""),
    }


# ------------------------------------------------------------------ T21 input validation


def _param_targets(root: str, ep: jsd.ApiEndpoint, owned_id: str | None) -> list[tuple[str, str]]:
    """Return ``[(url, param_name)]`` for endpoints that take a query or path param."""
    out: list[tuple[str, str]] = []
    if ep.path_param:
        # use a placeholder value we will overwrite with payloads
        seed = owned_id or "1"
        url = _fill_idor_url(root, ep, seed)
        if url:
            out.append((url, "__path__"))
        return out
    keys = list(ep.query_keys) or list(ep.id_query_keys)
    if not keys:
        # static capture_safe endpoints with no params: still probe by appending ?q=
        abs_url = _abs(root, ep.path.split("?", 1)[0])
        out.append((abs_url + "?q=SEED", "q"))
        return out
    for k in keys[:2]:
        seed = owned_id or "1"
        abs_url = _abs(root, ep.path.split("?", 1)[0]) + "?" + urlencode([(k, seed)])
        out.append((abs_url, k))
    return out


def _with_param(url: str, param: str, value: str) -> str:
    p = urlsplit(url)
    if param == "__path__":
        # replace the last path segment
        segs = [s for s in p.path.split("/") if s]
        if not segs:
            return url
        segs[-1] = value
        new_path = "/" + "/".join(segs)
        return urlunsplit((p.scheme, p.netloc, new_path, p.query, ""))
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    pairs.append((param, value))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), ""))


def run_input_validation(
    ctx: Any,
    *,
    cap: int = DEFAULT_INPUT_CAP,
    sleep_s: float = DEFAULT_SLEEP_S,
    clock_sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """T21: replay authenticated GET endpoints with malicious parameter values."""
    auth: SessionAuth | None = ctx.extra.get("_session_auth")
    auth_info = auth.public() if auth is not None else {"profile_id": None, "status": "none", "note": "", "injected": []}
    if auth is None or auth.status != "ready":
        return {
            "test_id": "T21",
            "status": "SKIPPED",
            "detail": f"login profile not ready ({auth_info.get('status')}: {auth_info.get('note')})",
            "skip_reason": SKIP_NO_AUTH_SESSION,
            "category": "validation",
            "auth": auth_info,
            "endpoints": [],
            "validation": {},
        }

    # Prefer endpoints that take params; also allow capture_safe static ones with ?q=
    eps = [e for e in _endpoints_from_ctx(ctx) if e.gettable]
    if not eps:
        return {
            "test_id": "T21",
            "status": "SKIPPED",
            "detail": "no gettable API endpoints discovered",
            "skip_reason": SKIP_NO_PARAM_ENDPOINTS,
            "category": "validation",
            "auth": auth_info,
            "endpoints": [],
            "validation": {},
        }

    # Harvest one owned id so path-param baselines resolve.
    owned_id: str | None = None
    for url in list(ctx.extra.get("_capture_api_urls") or [])[:3]:
        headers = auth.headers_for(url, ctx.target_base_url)
        scope = _build_scope(ctx, [url])
        cap_r = _do_get(
            url, headers=headers, scope=scope, profile=ctx.profile,
            client=client if (client := ctx.extra.get("httpx_client")) else None,
            check_dns=not ctx.allow_private, auth=auth,
        )
        clock_sleep(sleep_s)
        ids = harvest_ids(cap_r.body)
        for k in ("project_id", "client_id", "id"):
            if ids.get(k):
                owned_id = next(iter(ids[k]))
                break
        if owned_id:
            break

    client = ctx.extra.get("httpx_client")
    outcomes: list[EndpointOutcome] = []
    evidence: list[Any] = []
    findings = 0
    requests_left = cap

    # Prefer idor candidates (they take params) then capture_safe
    ordered = sorted(eps, key=lambda e: (0 if e.idor_candidate else 1, e.path))
    for ep in ordered:
        if requests_left <= 0:
            break
        for seed_url, param in _param_targets(_api_root(ctx), ep, owned_id):
            if requests_left <= 0:
                break
            scope = _build_scope(ctx, [seed_url])
            headers = auth.headers_for(seed_url, ctx.target_base_url)
            base_cap = _do_get(
                seed_url, headers=headers, scope=scope, profile=ctx.profile,
                client=client, check_dns=not ctx.allow_private, auth=auth,
            )
            requests_left -= 1
            clock_sleep(sleep_s)
            if not base_cap.ok:
                outcomes.append(EndpointOutcome(
                    url=seed_url, check="input", status="SKIPPED",
                    detail=f"baseline failed (HTTP {base_cap.status}: {base_cap.error})",
                    auth_status=base_cap.status, meta={"endpoint": ep.path, "param": param},
                ))
                continue

            hit = None
            for label, payload in INPUT_PAYLOADS:
                if requests_left <= 0:
                    break
                probe_url = _with_param(seed_url, param, payload)
                # path traversal / long strings can break SSRF/scope; skip if out of origin
                if _origin(probe_url) != _origin(seed_url):
                    continue
                try:
                    scope_validator.validate_target_url(probe_url, scope, check_dns=not ctx.allow_private)
                except Exception:
                    continue
                probe_cap = _do_get(
                    probe_url, headers=headers, scope=scope, profile=ctx.profile,
                    client=client, check_dns=not ctx.allow_private, auth=auth,
                )
                requests_left -= 1
                clock_sleep(sleep_s)
                bad, reason = input_finding(probe_cap.status, probe_cap.body, payload)
                if bad:
                    hit = (label, payload, probe_cap, reason)
                    break

            if hit is not None:
                findings += 1
                label, payload, probe_cap, reason = hit
                pairs = [p for p in (base_cap.pair, probe_cap.pair) if p is not None]
                for p in pairs:
                    evidence.append(p)
                outcomes.append(EndpointOutcome(
                    url=probe_cap.url, check="input", status="FINDING",
                    detail=f"input validation issue ({label}): {reason}",
                    auth_status=base_cap.status, probe_status=probe_cap.status, finding=True,
                    evidence_pairs=pairs,
                    meta={
                        "endpoint": ep.path,
                        "param": param,
                        "payload": label,
                        "payload_len": len(payload),
                    },
                ))
            else:
                if base_cap.pair is not None:
                    evidence.append(base_cap.pair)
                outcomes.append(EndpointOutcome(
                    url=seed_url, check="input", status="PASSED",
                    detail=f"no 5xx / leak / reflection across {len(INPUT_PAYLOADS)} payloads",
                    auth_status=base_cap.status,
                    meta={"endpoint": ep.path, "param": param},
                ))

    validation: dict[str, Any] = {}
    if findings:
        validation = {
            "status": "CONFIRMED",
            "confidence": "high",
            "reasons": [f"{findings} endpoint(s) mishandled crafted input (5xx / leak / reflection)"],
            "cwe": 20,
            "title_suffix": "input validation failure",
            "recommendation": (
                "Validate and sanitize every path/query parameter; return a generic 4xx on bad input "
                "and never echo stack traces, SQL errors or unescaped attacker strings."
            ),
        }
    status = "FINDING" if findings else ("PASSED" if outcomes else "SKIPPED")
    return {
        "test_id": "T21",
        "status": status,
        "detail": (
            f"input validation: {findings} finding(s) across {len(outcomes)} endpoint(s); "
            f"auth: {auth_info['status']} (profile #{auth_info.get('profile_id')})"
        ),
        "category": "validation",
        "auth": auth_info,
        "endpoints": [o.to_dict() for o in outcomes],
        "finding_count": findings,
        "validation": validation,
        "evidence_pairs": evidence,
        "finding_evidence_pairs": [p for o in outcomes if o.finding for p in o.evidence_pairs],
        "finding_title": "Input validation failure on API endpoints" if findings else "",
        "finding_location": next((o.url for o in outcomes if o.finding), ctx.target_base_url),
        "finding_cwe": 20,
        "finding_recommendation": validation.get("recommendation", ""),
    }
