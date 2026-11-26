"""ShieldByte Gap #6: CDN/infra report grouping + security-header grouping.

Pure helpers + consolidate context hygiene; template heading smoke. No classifier rebuild.
"""
# @lat: [[tests#ShieldByte Gap 6 infrastructure report grouping]]

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from attestra.finding_validation.classify import classify_observation
from attestra.finding_validation.statuses import INFORMATIONAL, UNVALIDATED
from attestra.reports import consolidate as consolidate_mod
from attestra.reports import render as render_mod

_APP = "https://shop.example.com/account"
_CHALLENGE = "https://shop.example.com/cdn-cgi/challenge-platform/h/b/scripts/jsd/abc/main.js"
_CDN_CGI = "https://shop.example.com/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"
_TMPL = Path(__file__).resolve().parents[1] / "attestra" / "reports" / "templates"


def _f(
    *,
    id: int,
    title: str,
    location: str,
    tools: list[str] | None = None,
    rule_ids: list[str] | None = None,
    severity: str = "low",
    status: str = "new",
    validation_status: str = "unvalidated",
    param: str = "",
    cwe: int | None = None,
    description: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        title=title,
        location=location,
        tools=tools or ["zap"],
        rule_ids=rule_ids or [],
        severity=severity,
        status=status,
        validation_status=validation_status,
        param=param,
        cwe=cwe,
        description=description,
        occurrences=1,
        risk_score=1.0,
        evidence=[],
        affected_urls=[],
        references=[],
        cves=[],
        kev=False,
        cvss_score=None,
        epss=None,
        asset=None,
        cross_related=[],
        report_members=None,
        member_ids=None,
    )


# --- classify reuse (cf_clearance / cdn-cgi) --------------------------------------


# @lat: [[tests#ShieldByte Gap 6 infrastructure report grouping#cf_clearance and cdn-cgi classified]]
def test_cf_clearance_and_cdn_cgi_classified_informational():
    cookie = classify_observation(
        title="Cookie without SameSite Attribute",
        param="cf_clearance",
        location=_APP,
        severity="low",
    )
    assert cookie["validation_status"] == INFORMATIONAL
    cors = classify_observation(
        title="Cross-Domain Misconfiguration",
        location=_CHALLENGE,
        evidence_texts=["Access-Control-Allow-Origin: *"],
    )
    assert cors["validation_status"] == INFORMATIONAL


# @lat: [[tests#ShieldByte Gap 6 infrastructure report grouping#App CORS still eligible]]
def test_app_cors_still_eligible_not_infrastructure():
    res = classify_observation(
        title="Cross-Domain Misconfiguration",
        location=_APP,
        evidence_texts=["Access-Control-Allow-Origin: *"],
    )
    assert res["validation_status"] == UNVALIDATED
    f = _f(id=1, title="Cross-Domain Misconfiguration", location=_APP, severity="medium")
    assert not render_mod._is_cdn_infrastructure_observation(f)
    assert not render_mod._is_security_header_finding(f)


# --- partition helpers ------------------------------------------------------------


def test_partition_groups_cf_clearance_and_cdn_challenge():
    cookie = _f(
        id=1,
        title="Cookie without SameSite Attribute",
        location=_APP,
        param="cf_clearance",
        validation_status=INFORMATIONAL,
    )
    challenge_cors = _f(
        id=2,
        title="Cross-Domain Misconfiguration",
        location=_CHALLENGE,
        validation_status=INFORMATIONAL,
    )
    hsts = _f(
        id=3,
        title="Strict-Transport-Security Header Not Set",
        location=_APP,
        rule_ids=["10035"],
        severity="low",
    )
    xss = _f(
        id=4,
        title="Reflected XSS in search",
        location=_APP + "/search",
        severity="high",
        cwe=79,
    )
    parts = render_mod._partition_infrastructure_findings([cookie, challenge_cors, hsts, xss])
    assert {f.id for f in parts["cdn_infrastructure_observations"]} == {1, 2}
    assert {f.id for f in parts["security_header_findings"]} == {3}
    # Main list unchanged by partition (caller keeps full reportable).
    assert xss not in parts["cdn_infrastructure_observations"]
    assert xss not in parts["security_header_findings"]


# @lat: [[tests#ShieldByte Gap 6 infrastructure report grouping#Distinct headers remain traceable]]
def test_distinct_security_headers_remain_individually_traceable():
    hsts = _f(id=10, title="Strict-Transport-Security Header Not Set", location=_APP, rule_ids=["10035"])
    csp = _f(id=11, title="Content Security Policy (CSP) Header Not Set", location=_APP, rule_ids=["10038"])
    xcto = _f(id=12, title="X-Content-Type-Options Header Missing", location=_APP, rule_ids=["10021"])
    xfo = _f(id=13, title="Missing Anti-clickjacking Header", location=_APP, rule_ids=["10020"])
    ref = _f(id=14, title="Referrer-Policy header is missing", location=_APP, rule_ids=["http-missing-security-headers:referrer-policy"], tools=["nuclei"])
    pp = _f(id=15, title="Permissions Policy Header Not Set", location=_APP, rule_ids=["10063"])
    parts = render_mod._partition_infrastructure_findings([hsts, csp, xcto, xfo, ref, pp])
    ids = [f.id for f in parts["security_header_findings"]]
    assert ids == [10, 11, 12, 13, 14, 15]
    assert not parts["cdn_infrastructure_observations"]


def test_header_on_cdn_cgi_goes_to_cdn_section_not_headers():
    f = _f(
        id=20,
        title="Strict-Transport-Security Header Not Set",
        location=_CDN_CGI,
        rule_ids=["10035"],
        validation_status=INFORMATIONAL,
    )
    parts = render_mod._partition_infrastructure_findings([f])
    assert parts["cdn_infrastructure_observations"] == [f]
    assert parts["security_header_findings"] == []


# --- consolidate security context -------------------------------------------------


# @lat: [[tests#ShieldByte Gap 6 infrastructure report grouping#Consolidate keeps app and CDN apart]]
def test_consolidate_does_not_merge_app_and_cdn_cgi_same_header():
    app = _f(
        id=1,
        title="Strict-Transport-Security Header Not Set",
        location=_APP,
        rule_ids=["10035"],
        tools=["zap"],
    )
    cdn = _f(
        id=2,
        title="Strict-Transport-Security Header Not Set",
        location=_CDN_CGI,
        rule_ids=["10035"],
        tools=["zap"],
        validation_status=INFORMATIONAL,
    )
    out = consolidate_mod.consolidate(None, [app, cdn], obs_by={1: [], 2: []})
    assert len(out) == 2
    locs = {(getattr(x, "location", None) or "") for x in out}
    assert _APP in locs and _CDN_CGI in locs


def test_consolidate_still_groups_same_header_across_app_urls():
    a = _f(id=1, title="Strict-Transport-Security Header Not Set", location=_APP, rule_ids=["10035"])
    b = _f(
        id=2,
        title="Strict-Transport-Security Header Not Set",
        location="https://shop.example.com/login",
        rule_ids=["10035"],
    )
    out = consolidate_mod.consolidate(None, [a, b], obs_by={1: [], 2: []})
    assert len(out) == 1
    urls = getattr(out[0], "affected_urls", None) or []
    assert len(urls) >= 2


# --- template headings ------------------------------------------------------------


# @lat: [[tests#ShieldByte Gap 6 infrastructure report grouping#Technical HTML section headings]]
def test_technical_and_executive_templates_have_section_headings():
    tech = (_TMPL / "technical.html.j2").read_text(encoding="utf-8")
    execu = (_TMPL / "executive.html.j2").read_text(encoding="utf-8")
    assert 'id="cdn-infrastructure"' in tech
    assert "CDN / Cloudflare Infrastructure Observations" in tech
    assert 'id="security-headers"' in tech
    assert "Security Headers and Browser Security Controls" in tech
    assert 'id="cdn-infrastructure"' in execu
    assert "CDN / Cloudflare Infrastructure Observations" in execu
    assert 'id="security-headers"' in execu
    assert "Security Headers and Browser Security Controls" in execu


def test_technical_html_renders_sections_when_lists_present():
    from jinja2 import Environment

    from attestra.reports import labels as report_labels

    env = Environment(autoescape=True)
    report_labels.register_jinja_filters(env)
    # Mirror the technical template sections (full kind template needs engagement cover context).
    tmpl = env.from_string(
        """
        {% if cdn_infrastructure_observations %}
        <h2 id="cdn-infrastructure">CDN / Cloudflare Infrastructure Observations</h2>
        <p>{{ cdn_infrastructure_observations|length }} observations</p>
        {% for f in cdn_infrastructure_observations %}
        <a href="#finding-{{ f.id }}">{{ flabel(f) }}</a> {{ f.title }} {{ f.location }} {{ f.param }}
        {% endfor %}
        {% endif %}
        {% if security_header_findings %}
        <h2 id="security-headers">Security Headers and Browser Security Controls</h2>
        {% for f in security_header_findings %}
        <a href="#finding-{{ f.id }}">{{ flabel(f) }}</a> {{ f.title }}
        {% endfor %}
        {% endif %}
        """
    )
    cdn = [
        _f(
            id=101,
            title="Cookie without SameSite Attribute",
            location=_CHALLENGE,
            param="cf_clearance",
            validation_status=INFORMATIONAL,
        )
    ]
    headers = [
        _f(id=102, title="Strict-Transport-Security Header Not Set", location=_APP, rule_ids=["10035"]),
        _f(id=103, title="Content Security Policy (CSP) Header Not Set", location=_APP, rule_ids=["10038"]),
    ]

    def flabel(ref):
        rid = ref if isinstance(ref, int) else getattr(ref, "id", ref)
        return {101: "F-1", 102: "F-2", 103: "F-3"}.get(int(rid), f"#{rid}")

    html = tmpl.render(
        cdn_infrastructure_observations=cdn,
        security_header_findings=headers,
        flabel=flabel,
    )
    assert "CDN / Cloudflare Infrastructure Observations" in html
    assert "Security Headers and Browser Security Controls" in html
    assert "cf_clearance" in html and "cdn-cgi" in html
    assert "F-2" in html and "Strict-Transport-Security" in html
    assert "F-3" in html and "Content Security Policy" in html
