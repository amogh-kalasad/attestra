"""B-07: Passive server-side sink indicators for SSRF / XXE / SSTI (catalogue id ``SSIND``).

Tier T0. This module **never** sends an SSRF, XXE or template payload, and never makes
an internal, private-range or cloud-metadata request. It only looks at what the run
already knows, plus at most 4 plain GETs of captured same-origin pages:

- **SSRF sink suspicion**: query parameters whose name (``url``, ``webhook``, ``feed``,
  ``image_url``...) or value (an absolute ``http(s)://`` URL) suggests the server fetches
  a URL; imported API operations with ``format: uri`` parameters.
- **XXE sink suspicion**: responses or API operations that use XML content types.
- **SSTI suspicion**: template-engine error signatures (Jinja2, Twig, Freemarker,
  Velocity, Thymeleaf, Smarty, Mako, ERB, Handlebars) in captured responses.

Everything is labelled ``suspected_sink`` for manual follow-up; ``finding_candidate``
stays False, and the case reports ``INCONCLUSIVE`` (needs manual review) when there is
at least one suspicion.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from attestra.automated_vapt.testing._probe_base import (
    SKIP_DISABLED_BY_FLAG,
    ProbeMeta,
    ProbeSession,
    engagement_auth,
    finish,
    header,
    not_tested,
    probes_web_safe_enabled,
    scope_ok,
)
from attestra.automated_vapt.testing._session import ctx_extra, probe_urls

# @lat: [[web-api-probes#Server-side sink indicators]]

META = ProbeMeta(
    test_id="SSIND",
    category="injection",
    safety_tier="T0",
    request_budget=4,
    wstg_refs=("WSTG-INPV-19", "WSTG-INPV-07", "WSTG-INPV-18"),
    cwe_refs=("CWE-918", "CWE-611", "CWE-1336"),
)

URLISH_PARAM_RE = re.compile(
    r"(?i)^(url|uri|link|href|src|source|dest|target|feed|rss|webhook|callback(_?url)?|"
    r"image(_?url)?|img(_?url)?|avatar(_?url)?|icon(_?url)?|logo(_?url)?|file(_?url)?|"
    r"fetch|proxy|load|remote|endpoint|host|domain|site|path|document(_?url)?|import(_?url)?|pdf(_?url)?)$"
)
_ABS_URL_VALUE_RE = re.compile(r"(?i)^(https?|ftp)://")
XML_CT_RE = re.compile(r"(?i)\b(application|text)/([a-z0-9.+-]*\+)?xml\b|application/soap\+xml")
TEMPLATE_ERROR_RE = re.compile(
    r"(?i)(jinja2\.exceptions|TemplateSyntaxError|UndefinedError: '|Twig[_\\]Error|"
    r"freemarker\.(core|template)\.|FreeMarker template error|org\.apache\.velocity|"
    r"org\.thymeleaf\.exceptions|Smarty error|SmartyCompilerException|mako\.exceptions|"
    r"ActionView::Template::Error|\(erb\):\d+|Handlebars.*Parse error|Liquid error)"
)


def url_param_suspicions(urls: list[str]) -> list[dict[str, Any]]:
    """Pure: URL-ish query parameters in already-known URLs (names only, values not kept)."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for u in urls:
        p = urlsplit(str(u or ""))
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            reason = ""
            if URLISH_PARAM_RE.match(k):
                reason = "url_like_param_name"
            elif _ABS_URL_VALUE_RE.match(v or ""):
                reason = "absolute_url_value"
            if reason and (p.path, k) not in seen:
                seen.add((p.path, k))
                out.append({"kind": "ssrf", "path": p.path or "/", "param": k, "reason": reason, "label": "suspected_sink"})
    return out


def inventory_suspicions(operations: list[Any]) -> list[dict[str, Any]]:
    """Pure: imported API operations that take URLs or XML (from ``api_inventory``)."""
    out: list[dict[str, Any]] = []
    for op in operations or []:
        d = op.to_dict() if hasattr(op, "to_dict") else dict(op or {})
        for prm in d.get("params") or []:
            name = str(prm.get("name") or "")
            if str(prm.get("format") or "").lower() in ("uri", "url") or URLISH_PARAM_RE.match(name):
                out.append({"kind": "ssrf", "path": d.get("path"), "method": d.get("method"), "param": name, "reason": "spec_uri_param", "label": "suspected_sink"})
        for ct in d.get("request_content_types") or []:
            if XML_CT_RE.search(str(ct)):
                out.append({"kind": "xxe", "path": d.get("path"), "method": d.get("method"), "reason": "spec_xml_request_body", "label": "suspected_sink"})
                break
    return out


def response_suspicions(url: str, headers: dict[str, Any] | None, body: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    path = urlsplit(url).path or "/"
    ct = header(headers, "content-type")
    if ct and XML_CT_RE.search(ct):
        out.append({"kind": "xxe", "path": path, "reason": "xml_response_content_type", "label": "suspected_sink"})
    m = TEMPLATE_ERROR_RE.search((body or "")[:100_000])
    if m:
        out.append({"kind": "ssti", "path": path, "reason": "template_error_signature", "signature": m.group(1)[:60], "label": "suspected_sink"})
    return out


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    extra = ctx_extra(kwargs)
    known = list(extra.get("_capture_urls") or []) + list(extra.get("_capture_api_urls") or [])
    suspicions = url_param_suspicions([u for u in known if scope_ok(str(u), base_url, kwargs)])
    inv = extra.get("_api_inventory_ops") or []
    suspicions += inventory_suspicions(list(inv))
    # Responses T01 already captured (no new traffic).
    for pair in list(extra.get("_http_pairs") or [])[:30]:
        suspicions += response_suspicions(getattr(pair, "url", ""), getattr(pair, "response_headers", {}), getattr(pair, "response_body", ""))

    ps: ProbeSession | None = None
    if probes_web_safe_enabled() and not extra.get("_http_pairs"):
        auth = engagement_auth(kwargs)
        ps = ProbeSession(client, base_url, META, auth=auth, delay_s=kwargs.get("delay_s"))
        for u in probe_urls(base_url, kwargs, api=False, limit=META.request_budget):
            if not ps.can_send() or not scope_ok(u, base_url, kwargs):
                continue
            pair = ps.send("GET", u)
            if pair is not None and ps.last_class() in ("app_ok", "origin_error", "unknown"):
                suspicions += response_suspicions(u, pair.response_headers, pair.response_body or "")
    elif not known and not inv and not extra.get("_http_pairs"):
        return not_tested(META, SKIP_DISABLED_BY_FLAG, "no captured traffic and ATTESTRA_PROBES_WEB_SAFE is off")

    # De-duplicate.
    uniq: list[dict[str, Any]] = []
    keys: set[tuple] = set()
    for s in suspicions:
        k = (s.get("kind"), s.get("path"), s.get("param"), s.get("reason"))
        if k not in keys:
            keys.add(k)
            uniq.append(s)
    by_kind = {k: sum(1 for s in uniq if s["kind"] == k) for k in ("ssrf", "xxe", "ssti")}
    detail = (
        "suspected server-side sinks (manual follow-up): " + ", ".join(f"{k}={v}" for k, v in by_kind.items() if v)
        if uniq
        else "no server-side sink indicators in known traffic"
    )
    hint = "INCONCLUSIVE" if uniq else None
    out = finish(
        META,
        ps,
        observations={"suspected_sinks": uniq[:50], "by_kind": by_kind, "passive_sources": {"urls": len(known), "inventory_ops": len(inv), "captured_pairs": len(extra.get("_http_pairs") or [])}},
        finding=False,
        detail=detail,
        hints=["passive review of captured URLs / responses / imported API spec"],
        status_hint=hint,
    )
    if ps is None and hint is None:
        out.pop("status_hint", None)
    return out
