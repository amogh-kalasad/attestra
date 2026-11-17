"""C-05: GraphQL detection, bounded introspection and field authz (catalogue id ``GRAPHQL``).

Read-only (tier T1, at most 10 requests, WSTG-APIT-01). Rules:

- **Queries only.** Every document goes through [[assert_read_only]], which refuses any
  ``mutation`` / ``subscription`` operation; mutations are never sent.
- **Bounded.** One ``{__typename}`` detection request per candidate (max 3 candidates),
  one introspection request with a fixed depth (``ofType`` nesting limited, see
  [[query_depth]]), and response bodies are read through a 512 KB cap.
- **GET first.** Queries go as ``GET ?query=`` (GraphQL over HTTP). A POST with a JSON
  ``query`` is used only when the execution profile allows POST (active / intrusive) and
  the endpoint refused GET.
- **Introspection disabled is not a vulnerability.** Enabled introspection on the target
  is a low-severity, confirmed observation.
- **Field authz** compares up to 3 argument-free root fields as the primary and the
  secondary engagement identity. Without a second identity the comparison is
  ``NOT_TESTED`` (never PASS).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlencode

from attestra.automated_vapt.testing._http import absolute
from attestra.automated_vapt.testing._probe_base import (
    SKIP_DISABLED_BY_FLAG,
    SKIP_NO_SECOND_ROLE,
    ProbeMeta,
    ProbeSession,
    class_name,
    classify,
    engagement_auth,
    finish,
    graphql_probe_enabled,
    not_tested,
    probe_delay_s,
    scope_ok,
    secondary_auth,
)
from attestra.automated_vapt.testing._session import ctx_extra

# @lat: [[web-api-probes#GraphQL probe]]

META = ProbeMeta(
    test_id="GRAPHQL",
    category="api",
    safety_tier="T1",
    request_budget=10,
    auth_required=False,
    wstg_refs=("WSTG-APIT-01",),
    cwe_refs=("CWE-200", "CWE-285"),
)

MAX_RESPONSE_BYTES = 512 * 1024
MAX_DEPTH = 8
MAX_CANDIDATES = 3
MAX_FIELD_CHECKS = 3
DEFAULT_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")

DETECT_QUERY = "query AttestraDetect { __typename }"
# Bounded introspection: names/kinds/args only, ofType nested 3 levels (no fragments).
INTROSPECTION_QUERY = (
    "query AttestraIntrospection { __schema { queryType { name } mutationType { name } "
    "types { name kind fields { name args { name type { kind name ofType { kind name } } } "
    "type { kind name ofType { kind name ofType { kind name } } } } } } }"
)
_OP_RE = re.compile(r"(?i)\b(mutation|subscription)\b")
_PRIVILEGED_RE = re.compile(r"(?i)(admin|users?$|allusers|accounts?|secret|token|internal|audit|billing|payment|role|permission|staff|tenant)")


class UnsafeGraphQLQuery(ValueError):
    pass


def query_depth(query: str) -> int:
    depth = best = 0
    for ch in query or "":
        if ch == "{":
            depth += 1
            best = max(best, depth)
        elif ch == "}":
            depth -= 1
    return best


def assert_read_only(query: str) -> str:
    """Refuse mutation/subscription operations and over-deep documents."""
    q = query or ""
    if _OP_RE.search(q):
        raise UnsafeGraphQLQuery("GraphQL mutations/subscriptions are never sent")
    if query_depth(q) > MAX_DEPTH:
        raise UnsafeGraphQLQuery(f"GraphQL query depth > {MAX_DEPTH}")
    return q


def looks_graphql(body: str) -> bool:
    try:
        data = json.loads(body or "")
    except Exception:  # noqa: BLE001
        return False
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("data"), dict) and "__typename" in data["data"]:
        return True
    errs = data.get("errors")
    if isinstance(errs, list) and errs and isinstance(errs[0], dict) and "message" in errs[0]:
        return True
    return False


def candidate_urls(base_url: str, kwargs: dict[str, Any]) -> list[str]:
    extra = ctx_extra(kwargs)
    api_root = str(extra.get("_api_base_url") or base_url)
    out: list[str] = []

    def add(u: str) -> None:
        if u and u not in out and scope_ok(u, base_url, kwargs):
            out.append(u)

    js = extra.get("_js_api") or {}
    for ep in (js.get("endpoints_list") or []) if isinstance(js, dict) else []:
        path = ep.get("path") if isinstance(ep, dict) else getattr(ep, "path", "")
        if (isinstance(ep, dict) and ep.get("graphql")) or "graphql" in str(path).lower():
            add(absolute(api_root, str(path)))
    for op in extra.get("_api_inventory_ops") or []:
        d = op.to_dict() if hasattr(op, "to_dict") else dict(op or {})
        if "graphql" in str(d.get("path") or "").lower():
            add(absolute(api_root, str(d.get("path"))))
    for u in list(extra.get("_capture_api_urls") or []):
        if "graphql" in str(u).lower():
            add(str(u).split("?", 1)[0])
    for p in DEFAULT_PATHS:
        add(absolute(api_root, p))
    return out[:MAX_CANDIDATES]


def _read_capped(client: Any, method: str, url: str, headers: dict[str, str], json_body: Any = None) -> tuple[int | None, dict[str, str], str, bool]:
    """Request with a hard response-size cap. Returns (status, headers, text, truncated)."""
    kw: dict[str, Any] = {"headers": headers or None, "follow_redirects": False}
    if json_body is not None:
        kw["json"] = json_body
    stream = getattr(client, "stream", None)
    if callable(stream):
        with stream(method, url, **kw) as r:
            chunks: list[bytes] = []
            size = 0
            truncated = False
            for chunk in r.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    truncated = True
                    break
                chunks.append(chunk)
            hdrs = {str(k): str(v) for k, v in r.headers.items()}
            return int(r.status_code), hdrs, b"".join(chunks).decode("utf-8", "replace"), truncated
    r = client.request(method, url, **kw)
    content = getattr(r, "content", b"") or b""
    truncated = len(content) > MAX_RESPONSE_BYTES
    text = content[:MAX_RESPONSE_BYTES].decode("utf-8", "replace")
    return int(r.status_code), {str(k): str(v) for k, v in r.headers.items()}, text, truncated


class _GqlSender:
    """Budgeted GraphQL sender on top of [[ProbeSession]] accounting."""

    def __init__(self, ps: ProbeSession, client: Any, base_url: str, profile: str):
        self.ps = ps
        self.client = client
        self.base_url = base_url
        self.allow_post = (profile or "baseline").lower() in ("active", "intrusive")

    def query(self, url: str, query: str, *, auth: Any = None) -> dict[str, Any]:
        assert_read_only(query)
        if not self.ps.can_send():
            return {"sent": False}
        hdrs: dict[str, str] = {"Accept": "application/json"}
        if auth is not None and hasattr(auth, "headers_for"):
            hdrs.update(auth.headers_for(url, self.base_url) or {})
        get_url = f"{url}?{urlencode({'query': query})}"
        res = self._one("GET", get_url, hdrs, None, authed=auth is not None)
        if res.get("status") in (400, 405) and self.allow_post and self.ps.can_send():
            hdrs["Content-Type"] = "application/json"
            res = self._one("POST", url, hdrs, {"query": query}, authed=auth is not None)
        return res

    def _one(self, method: str, url: str, hdrs: dict[str, str], body: Any, *, authed: bool) -> dict[str, Any]:
        ps = self.ps
        delay = probe_delay_s() if ps.delay_s is None else ps.delay_s
        if delay and ps._last:
            wait = delay - (time.monotonic() - ps._last)
            if wait > 0:
                time.sleep(wait)
        ps.sent += 1
        ps._last = time.monotonic()
        try:
            status, rh, text, truncated = _read_capped(self.client, method, url, hdrs, body)
        except Exception as exc:  # noqa: BLE001
            c = classify(None, {}, "", authed=authed, error=type(exc).__name__)
            ps.samples.append(c)
            ps.requests_log.append({"method": method, "url": url.split("?", 1)[0], "status": None, "class": class_name(c)})
            return {"sent": True, "status": None, "class": class_name(c)}
        c = classify(status, rh, text, authed=authed)
        ps.samples.append(c)
        cls = class_name(c)
        ps.requests_log.append({"method": method, "url": url.split("?", 1)[0], "status": status, "class": cls})
        if cls in ("waf_block", "challenge", "rate_limited"):
            ps.halted_reason = cls
        data = None
        if not truncated:
            try:
                data = json.loads(text)
            except Exception:  # noqa: BLE001
                data = None
        return {
            "sent": True,
            "method": method,
            "url": url,
            "status": status,
            "class": cls,
            "headers": rh,
            "data": data,
            "text": text if not truncated else "",
            "truncated": truncated,
            "bytes": len(text),
        }


def _unwrap(t: dict[str, Any] | None) -> dict[str, Any]:
    cur = t or {}
    for _ in range(4):
        if cur.get("kind") in ("NON_NULL", "LIST") and cur.get("ofType"):
            cur = cur["ofType"]
        else:
            break
    return cur


def root_field_plan(schema: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Argument-free query root fields returning an object, with up to 5 scalar sub-fields."""
    types = {t.get("name"): t for t in (schema.get("types") or []) if isinstance(t, dict)}
    qname = ((schema.get("queryType") or {}).get("name")) or "Query"
    qtype = types.get(qname) or {}
    plan: list[tuple[str, list[str]]] = []
    fields = list(qtype.get("fields") or [])
    fields.sort(key=lambda f: 0 if _PRIVILEGED_RE.search(str(f.get("name") or "")) else 1)
    for f in fields:
        required = [a for a in (f.get("args") or []) if (a.get("type") or {}).get("kind") == "NON_NULL"]
        if required:
            continue
        rt = _unwrap(f.get("type"))
        sub = types.get(rt.get("name")) or {}
        if rt.get("kind") not in ("OBJECT",):
            continue
        scalars = [sf.get("name") for sf in (sub.get("fields") or []) if _unwrap(sf.get("type")).get("kind") in ("SCALAR", "ENUM") and not (sf.get("args") or [])]
        if scalars:
            plan.append((str(f.get("name")), [str(s) for s in scalars[:5]]))
        if len(plan) >= MAX_FIELD_CHECKS:
            break
    return plan


def _field_result(res: dict[str, Any], field: str) -> str:
    data = res.get("data")
    if not isinstance(data, dict):
        return "no_response"
    val = (data.get("data") or {}).get(field) if isinstance(data.get("data"), dict) else None
    if val in (None, [], {}):
        return "denied_or_empty" if data.get("errors") else "empty"
    return "data"


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    if not graphql_probe_enabled():
        return not_tested(META, SKIP_DISABLED_BY_FLAG, "ATTESTRA_GRAPHQL_PROBE is off")
    ctx = kwargs.get("ctx")
    profile = str(getattr(ctx, "profile", "") or kwargs.get("profile") or "baseline")
    auth = engagement_auth(kwargs)
    ps = ProbeSession(client, base_url, META, auth=auth, delay_s=kwargs.get("delay_s"))
    gql = _GqlSender(ps, client, base_url, profile)
    cands = list(kwargs.get("candidates") or candidate_urls(base_url, kwargs))[:MAX_CANDIDATES]

    endpoint = ""
    detections: list[dict[str, Any]] = []
    for u in cands:
        if not ps.can_send():
            break
        res = gql.query(u, DETECT_QUERY, auth=auth)
        ok = looks_graphql(res.get("text") or "")
        detections.append({"url": u.split("?", 1)[0], "status": res.get("status"), "class": res.get("class"), "graphql": ok})
        if ok:
            endpoint = u
            break
    if not endpoint:
        return finish(META, ps, observations={"candidates": detections, "endpoint": None}, finding=False,
                      detail="no GraphQL endpoint detected", status_hint=None if not ps.halted else "BLOCKED")

    intro = gql.query(endpoint, INTROSPECTION_QUERY, auth=auth)
    schema = None
    if isinstance(intro.get("data"), dict):
        schema = ((intro["data"].get("data") or {}) if isinstance(intro["data"].get("data"), dict) else {}).get("__schema")
    introspection_enabled = isinstance(schema, dict) and bool(schema.get("types"))
    obs: dict[str, Any] = {
        "endpoint": endpoint.split("?", 1)[0],
        "candidates": detections,
        "introspection": {
            "enabled": introspection_enabled,
            "status": intro.get("status"),
            "truncated": bool(intro.get("truncated")),
            "bytes": intro.get("bytes"),
            "type_count": len(schema.get("types") or []) if introspection_enabled else 0,
            "has_mutations": bool(introspection_enabled and (schema.get("mutationType") or {}).get("name")),
        },
        "mutations_sent": 0,
    }

    sec = secondary_auth(kwargs)
    field_rows: list[dict[str, Any]] = []
    suspected: list[str] = []
    if not introspection_enabled:
        obs["field_authz"] = {"status": "NOT_TESTED", "reason": "introspection_unavailable"}
    elif auth is None or sec is None:
        obs["field_authz"] = {"status": "NOT_TESTED", "reason": SKIP_NO_SECOND_ROLE}
    else:
        for field, subs in root_field_plan(schema):
            if ps.remaining < 2:
                break
            q = f"query AttestraFieldCheck {{ {field} {{ {' '.join(subs)} }} }}"
            a = gql.query(endpoint, q, auth=auth)
            b = gql.query(endpoint, q, auth=sec)
            ra, rb = _field_result(a, field), _field_result(b, field)
            same = ra == rb == "data" and json.dumps((a.get("data") or {}).get("data"), sort_keys=True) == json.dumps((b.get("data") or {}).get("data"), sort_keys=True)
            row = {"field": field, "primary": ra, "secondary": rb, "identical_data": same, "privileged_name": bool(_PRIVILEGED_RE.search(field))}
            field_rows.append(row)
            if same and row["privileged_name"]:
                suspected.append(field)
        obs["field_authz"] = {"status": "TESTED", "fields": field_rows, "suspected": suspected}

    evidence: list[Any] = []
    if introspection_enabled:
        from attestra.proof.pair import HttpPair

        evidence.append(
            ps.evidence(
                HttpPair(
                    method=str(intro.get("method") or "GET"),
                    url=str(intro.get("url") or endpoint),
                    status=intro.get("status"),
                    response_headers=dict(intro.get("headers") or {}),
                    response_body=str(intro.get("text") or "")[:2_000],
                    source="automated_vapt",
                ),
                body_cap=2_000,
            )
        )
    finding = introspection_enabled or bool(suspected)
    if suspected:
        detail = "privileged GraphQL root fields return identical data to both identities: " + ", ".join(suspected)
        confidence, severity = "suspected", "medium"
    elif introspection_enabled:
        detail = "GraphQL introspection is enabled"
        confidence, severity = "confirmed", "low"
    else:
        detail = "GraphQL endpoint found; introspection disabled (not a vulnerability)"
        confidence, severity = "", ""
    return finish(
        META,
        ps,
        observations=obs,
        finding=finding,
        confidence=confidence,
        severity=severity,
        detail=detail,
        evidence=evidence,
        hints=[f"GET {obs['endpoint']}?query=<read-only query>"],
    )
