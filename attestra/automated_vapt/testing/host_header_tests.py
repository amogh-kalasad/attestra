"""B-02: Host / X-Forwarded-Host handling probe (catalogue id ``HOSTHDR``, WSTG-INPV-17).

Safe-active read-only probe (tier T1, at most 5 GETs). Only header values vary: the
request URL, and so the approved destination and its pinned IP, never changes. The
spoofed host is a non-routable ``.invalid`` marker, so nothing ever calls it back.

1. A baseline GET of the target page (no spoofed headers).
2. One GET per variant: ``X-Forwarded-Host``, ``X-Host``, ``Forwarded: host=``, and an
   overridden ``Host`` header.

A variant is reported when the marker shows up in the ``Location`` header (absolute
redirect built from the spoofed host: **confirmed**) or in absolute links / URLs in the
body that the baseline did not contain (**suspected**, e.g. password-reset link
generation). A plain echo of the header value in body text is ignored.
"""

from __future__ import annotations

import re
from typing import Any

from attestra.automated_vapt.testing._probe_base import (
    SKIP_DISABLED_BY_FLAG,
    ProbeMeta,
    ProbeSession,
    engagement_auth,
    finish,
    header,
    host_of,
    not_tested,
    probes_web_safe_enabled,
    scope_ok,
)

# @lat: [[web-api-probes#Host header probe]]

META = ProbeMeta(
    test_id="HOSTHDR",
    category="configuration",
    safety_tier="T1",
    request_budget=5,
    wstg_refs=("WSTG-INPV-17",),
    cwe_refs=("CWE-644", "CWE-20"),
)

MARKER_HOST = "attestra-host-probe.invalid"

VARIANTS: tuple[tuple[str, dict[str, str]], ...] = (
    ("x-forwarded-host", {"X-Forwarded-Host": MARKER_HOST}),
    ("x-host", {"X-Host": MARKER_HOST}),
    ("forwarded", {"Forwarded": f"host={MARKER_HOST}"}),
    ("host", {"Host": MARKER_HOST}),
)

_LINK_RE = re.compile(
    r"(?i)(?:https?:)?//" + re.escape(MARKER_HOST) + r"(?::\d+)?(?:[/\"'?#\s>]|$)"
)


def marker_in_location(headers: dict[str, Any] | None) -> bool:
    loc = header(headers, "location")
    return bool(loc) and host_of(loc if "://" in loc else ("https:" + loc if loc.startswith("//") else "")) == MARKER_HOST


def marker_links(body: str) -> int:
    """Count absolute / scheme-relative URLs that point at the marker host."""
    return len(_LINK_RE.findall(body or ""))


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    if not probes_web_safe_enabled():
        return not_tested(META, SKIP_DISABLED_BY_FLAG, "ATTESTRA_PROBES_WEB_SAFE is off")
    url = str(kwargs.get("url") or base_url)
    if not scope_ok(url, base_url, kwargs):
        return not_tested(META, "out_of_scope", "probe URL is not on the target origin")
    auth = engagement_auth(kwargs)
    ps = ProbeSession(client, base_url, META, auth=auth, delay_s=kwargs.get("delay_s"))

    base_pair = ps.send("GET", url)
    if base_pair is None:
        return finish(META, ps, observations={"url": url}, finding=False, detail="baseline request not answered by the application")
    baseline_links = marker_links(base_pair.response_body or "")
    rows: list[dict[str, Any]] = []
    evidence: list[Any] = []
    confirmed: list[str] = []
    suspected: list[str] = []
    for name, hdrs in VARIANTS:
        if not ps.can_send():
            break
        pair = ps.send("GET", url, headers=hdrs)
        if pair is None:
            continue
        # The destination never changes: only the header value varied.
        destination_unchanged = pair.url == url and host_of(pair.url) == host_of(base_url)
        loc_hit = marker_in_location(pair.response_headers)
        links = marker_links(pair.response_body or "")
        row = {
            "variant": name,
            "status": pair.status,
            "class": ps.last_class(),
            "destination_unchanged": destination_unchanged,
            "location_uses_marker": loc_hit,
            "marker_links": links,
        }
        rows.append(row)
        if loc_hit:
            confirmed.append(name)
            evidence.append(ps.evidence(pair))
        elif links > baseline_links and ps.last_class() == "app_ok":
            suspected.append(name)
            evidence.append(ps.evidence(pair))

    finding = bool(confirmed or suspected)
    if confirmed:
        detail = "spoofed host used in absolute redirect via " + ", ".join(confirmed)
    elif suspected:
        detail = "spoofed host used to build absolute links via " + ", ".join(suspected)
    else:
        detail = "spoofed Host / X-Forwarded-Host values not used for redirects or links"
    return finish(
        META,
        ps,
        observations={
            "url": url,
            "marker_host": MARKER_HOST,
            "baseline_status": base_pair.status,
            "baseline_marker_links": baseline_links,
            "variants": rows,
            "confirmed_variants": confirmed,
            "suspected_variants": suspected,
            "pinned_destination": host_of(url),
        },
        finding=finding,
        confidence="confirmed" if confirmed else "suspected",
        severity="medium",
        detail=detail,
        evidence=evidence,
        hints=[f"GET {url} with {n}: {MARKER_HOST}" for n, _ in VARIANTS],
    )
