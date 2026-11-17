"""B-01: CORS validation matrix (catalogue id ``CORS``, WSTG-CLNT-07).

Safe-active read-only probe (tier T1, at most 6 requests). It varies only the ``Origin``
request header on GET (actual response) and on one OPTIONS preflight, using
non-routable ``.invalid`` origins, and reads the ``Access-Control-*`` response headers
through [[attestra/automated_vapt/testing/information_disclosure_tests.py#observe_cors]].

Verdicts:

- **finding (confirmed)**: an untrusted origin (or ``null``) is reflected in
  ``Access-Control-Allow-Origin`` with ``Access-Control-Allow-Credentials: true`` on an
  actual GET that returned application content, and the same result reproduces on a
  second identical request. That is a reproducible credentialed cross-origin read.
- **info**: ``Access-Control-Allow-Origin: *`` without credentials, or a permissive
  preflight whose actual response does not allow the origin.
- **BLOCKED**: a WAF / challenge / 429 answered; the probe stops sending at once.
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._probe_base import (
    SKIP_DISABLED_BY_FLAG,
    ProbeMeta,
    ProbeSession,
    engagement_auth,
    finish,
    host_of,
    not_tested,
    probes_web_safe_enabled,
    scope_ok,
)
from attestra.automated_vapt.testing._session import probe_urls
from attestra.automated_vapt.testing.information_disclosure_tests import observe_cors

# @lat: [[web-api-probes#CORS validation]]

META = ProbeMeta(
    test_id="CORS",
    category="configuration",
    safety_tier="T1",
    request_budget=6,
    auth_required=False,
    wstg_refs=("WSTG-CLNT-07",),
    cwe_refs=("CWE-942", "CWE-346"),
)

EVIL_ORIGIN = "https://attestra-cors-probe.invalid"
NULL_ORIGIN = "null"


def suffix_origin(base_url: str) -> str:
    """``https://<target-host>.attestra-cors-probe.invalid``: catches naive suffix/prefix matching."""
    host = host_of(base_url) or "target"
    return f"https://{host}.attestra-cors-probe.invalid"


def evaluate(origin: str, headers: dict[str, Any] | None) -> dict[str, Any]:
    """Pure: how the response treated ``origin`` (no finding decision on its own)."""
    obs = observe_cors(headers)
    acao = (obs.get("access_control_allow_origin") or "").strip()
    creds = (obs.get("access_control_allow_credentials") or "").strip().lower() == "true"
    reflected = bool(acao) and acao != "*" and acao.lower() == origin.lower()
    return {
        "origin": origin,
        "acao": acao or None,
        "credentials": creds,
        "reflected": reflected,
        "wildcard": acao == "*",
        "credentialed_reflection": reflected and creds,
    }


def _pick_url(base_url: str, kwargs: dict[str, Any]) -> str:
    for u in probe_urls(base_url, kwargs, api=True, limit=4):
        if scope_ok(u, base_url, kwargs):
            return u
    return base_url


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    if not probes_web_safe_enabled():
        return not_tested(META, SKIP_DISABLED_BY_FLAG, "ATTESTRA_PROBES_WEB_SAFE is off")
    auth = engagement_auth(kwargs)
    url = str(kwargs.get("url") or _pick_url(base_url, kwargs))
    if not scope_ok(url, base_url, kwargs):
        return not_tested(META, "out_of_scope", "probe URL is not on the target origin")
    ps = ProbeSession(client, base_url, META, auth=auth, delay_s=kwargs.get("delay_s"))

    matrix: list[dict[str, Any]] = []
    evidence: list[Any] = []
    vuln_origin = ""
    for origin in (EVIL_ORIGIN, NULL_ORIGIN, suffix_origin(base_url)):
        if not ps.can_send():
            break
        pair = ps.send("GET", url, headers={"Origin": origin})
        if pair is None:
            break
        row = evaluate(origin, pair.response_headers)
        row.update({"kind": "actual", "status": pair.status, "class": ps.last_class()})
        matrix.append(row)
        if row["credentialed_reflection"] and row["class"] == "app_ok" and not vuln_origin:
            vuln_origin = origin
            evidence.append(ps.evidence(pair))

    preflight: dict[str, Any] = {}
    if ps.can_send():
        pair = ps.send(
            "OPTIONS",
            url,
            headers={"Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "GET"},
        )
        if pair is not None:
            preflight = evaluate(EVIL_ORIGIN, pair.response_headers)
            preflight.update({"kind": "preflight", "status": pair.status, "class": ps.last_class()})
            preflight["allow_methods"] = observe_cors(pair.response_headers).get("access_control_allow_methods")

    reproduced = False
    if vuln_origin and ps.can_send():
        pair = ps.send("GET", url, headers={"Origin": vuln_origin})
        if pair is not None:
            again = evaluate(vuln_origin, pair.response_headers)
            reproduced = again["credentialed_reflection"] and ps.last_class() == "app_ok"
            if reproduced:
                evidence.append(ps.evidence(pair))

    actual_allows_evil = any(r["reflected"] for r in matrix if r["origin"] == EVIL_ORIGIN)
    info: list[str] = []
    if any(r["wildcard"] and not r["credentials"] for r in matrix):
        info.append("wildcard_origin_without_credentials")
    if preflight.get("reflected") and not actual_allows_evil:
        info.append("preflight_permissive_actual_not")
    if any(r["reflected"] and not r["credentials"] for r in matrix):
        info.append("origin_reflected_without_credentials")

    finding = bool(vuln_origin and reproduced)
    if finding:
        detail = f"credentialed cross-origin read: origin {vuln_origin!r} reflected with credentials (reproduced)"
    elif vuln_origin:
        detail = "credentialed reflection seen once but did not reproduce; not reported as a finding"
    elif info:
        detail = "CORS observations only: " + ", ".join(info)
    else:
        detail = "no untrusted origin allowed"
    return finish(
        META,
        ps,
        observations={
            "url": url,
            "authenticated": auth is not None,
            "matrix": matrix,
            "preflight": preflight,
            "reproduced": reproduced,
            "informational": info,
        },
        finding=finding,
        confidence="confirmed",
        severity="medium",
        detail=detail,
        evidence=evidence,
        hints=[f"GET {url} with Origin variations; OPTIONS preflight"],
    )
