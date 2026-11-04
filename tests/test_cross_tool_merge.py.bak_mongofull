"""Cross-tool merge: the same issue from different tools shows as one finding (highest severity)."""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select

SHOP = "https://shop.example.com"


def _asset_id(s, eid, ident=SHOP):
    from attestra.models import Asset

    return s.scalar(select(Asset.id).where(Asset.engagement_id == eid, Asset.identifier == ident))


def _row(s, eid, *, tool, title, severity, location, fp, cves=(), cwe=None, rule_ids=(), asset_id=None, status="new"):
    from attestra.models import Finding

    f = Finding(
        engagement_id=eid, asset_id=asset_id, fingerprint=fp, title=title, tools=[tool],
        rule_ids=list(rule_ids), cwe=cwe, cves=list(cves), location=location, severity=severity, status=status,
    )
    s.add(f)
    s.flush()
    return f


def _all(s, eid):
    from attestra.models import Finding

    return list(s.scalars(select(Finding).where(Finding.engagement_id == eid).order_by(Finding.id)))


# ------------------------------------------------------------------ CVE match
def test_shared_cve_same_host_links_and_takes_highest_severity(engagement):
    from attestra import crossmerge, db, services

    with db.session() as s:
        aid = _asset_id(s, engagement)
        ts = _row(s, engagement, tool="testssl", title="TLS: heartbleed", severity="low",
                  location="shop.example.com:443", fp="a" * 64, cves=["CVE-2014-0160"], asset_id=aid)
        nu = _row(s, engagement, tool="nuclei", title="OpenSSL Heartbleed", severity="high",
                  location="shop.example.com:443", fp="b" * 64, cves=["cve-2014-0160"], asset_id=aid)
        res = crossmerge.recompute(s, engagement, actor="tester")
        assert res["groups"] == 1 and res["related"] == 1
        # Primary is the higher-severity row; the other points at it.
        assert ts.merged_into_id == nu.id and nu.merged_into_id is None
        assert ts.merge_rationale == "cve:CVE-2014-0160"
        # Severities are never rewritten.
        assert (ts.severity, nu.severity) == ("low", "high")
        shown = crossmerge.collapse(s, services.list_findings(s, engagement))
        assert [f.id for f in shown] == [nu.id]
        top = shown[0]
        assert top.effective_severity == "high"
        assert top.severity_label.startswith("High (")
        assert "Nuclei: High" in top.severity_label and "Testssl: Low" in top.severity_label
        assert {src["finding_id"] for src in top.cross_sources} == {ts.id, nu.id}


def test_cve_without_host_needs_exact_location(engagement):
    from attestra import crossmerge, db

    with db.session() as s:
        a = _row(s, engagement, tool="trivy", title="lib CVE", severity="high",
                 location="registry.example.com/shop/api (alpine)", fp="c" * 64, cves=["CVE-2024-9999"])
        b = _row(s, engagement, tool="semgrep", title="lib CVE", severity="low",
                 location="services/payments/requirements.txt", fp="d" * 64, cves=["CVE-2024-9999"])
        crossmerge.recompute(s, engagement, actor="tester")
        assert a.merged_into_id is None and b.merged_into_id is None


# ------------------------------------------------------------------ header mapping
def _zap_report() -> bytes:
    def alert(pid, ref, name, cwe, risk, paths):
        return {
            "pluginid": pid, "alertRef": ref, "alert": name, "riskcode": risk, "confidence": "2",
            "cweid": cwe, "desc": name, "solution": "Fix it.",
            "instances": [{"uri": SHOP + p, "method": "GET", "param": "", "evidence": f"{name} @ {p}"} for p in paths],
        }

    return json.dumps({"site": [{"@name": SHOP, "alerts": [
        alert("10035", "10035-1", "Strict-Transport-Security Header Not Set", "319", "1", ["/", "/login"]),
        alert("10038", "10038-1", "Content Security Policy (CSP) Header Not Set", "693", "2", ["/"]),
    ]}]}).encode()


def _nuclei_headers() -> bytes:
    rows = []
    for matcher in ("strict-transport-security", "x-frame-options"):
        rows.append(json.dumps({
            "template-id": "http-missing-security-headers", "matcher-name": matcher,
            "info": {"name": "HTTP Missing Security Headers", "severity": "info",
                     "classification": {"cwe-id": ["cwe-693"]}},
            "matched-at": SHOP + "/", "host": "shop.example.com",
        }))
    return ("\n".join(rows) + "\n").encode()


def _webcheck_hsts() -> bytes:
    return json.dumps({"findings": [{
        "id": "hsts-present", "title": "HSTS header missing on HTTPS", "severity": "medium", "cwe": 319,
        "description": "No HSTS. Evidence: (missing)", "location": SHOP + "/",
    }]}).encode()


def _import_three(s, eid):
    from attestra import services

    services.import_results(s, eid, tool="zap", filename="zap.json", data=_zap_report(), actor="tester")
    services.import_results(s, eid, tool="nuclei", filename="n.jsonl", data=_nuclei_headers(), actor="tester")
    services.import_results(s, eid, tool="webcheck", filename="w.json", data=_webcheck_hsts(), actor="tester")


def test_nuclei_header_matchers_stay_separate_findings(engagement):
    from attestra import db

    with db.session() as s:
        _import_three(s, engagement)
        nuclei = [f for f in _all(s, engagement) if f.tools == ["nuclei"]]
    assert len(nuclei) == 2  # one per missing header, not collapsed


def test_missing_hsts_merged_across_zap_webcheck_nuclei_after_import(engagement):
    from attestra import crossmerge, db, services

    with db.session() as s:
        _import_three(s, engagement)  # merge runs automatically after each import
        rows = _all(s, engagement)
        shown = crossmerge.collapse(s, services.list_findings(s, engagement))
        hsts = [f for f in shown if len(getattr(f, "cross_sources", [])) > 1]
        assert len(hsts) == 1
        top = hsts[0]
        tools = {src["tool"] for src in top.cross_sources}
        assert tools == {"zap", "webcheck", "nuclei"}
        # Highest of Low (ZAP), Medium (webcheck), Info (nuclei).
        assert top.severity == "medium" and top.effective_severity == "medium"
        assert top.severity_label.startswith("Medium (")
        for part in ("ZAP: Low", "Webcheck: Medium", "Nuclei: Info"):
            assert part in top.severity_label
        # Evidence from each tool is kept on its own source entry.
        zap_src = next(src for src in top.cross_sources if src["tool"] == "zap")
        assert any("Strict-Transport-Security" in e for e in zap_src["evidence"])
        # Nothing deleted: 2 ZAP + 2 nuclei + 1 webcheck rows still stored; 2 folded in.
        assert len(rows) == 5
        assert len(shown) == 3
        # CSP-missing (ZAP) and X-Frame-Options (nuclei) are different issues: not merged.
        titles = sorted(f.title for f in shown if len(getattr(f, "cross_sources", [])) <= 1)
        assert titles == ["Content Security Policy (CSP) Header Not Set", "HTTP Missing Security Headers"]


def test_same_tool_and_different_concepts_never_merge(engagement):
    from attestra import crossmerge, db

    with db.session() as s:
        aid = _asset_id(s, engagement)
        a = _row(s, engagement, tool="zap", title="Content Security Policy (CSP) Header Not Set", severity="medium",
                 location=SHOP + "/", fp="e" * 64, cwe=693, rule_ids=["10038"], asset_id=aid)
        b = _row(s, engagement, tool="webcheck", title="HSTS header missing on HTTPS", severity="medium",
                 location=SHOP + "/", fp="f" * 64, cwe=319, rule_ids=["webcheck/hsts-present"], asset_id=aid)
        c = _row(s, engagement, tool="zap", title="Strict-Transport-Security Header Not Set", severity="low",
                 location=SHOP + "/", fp="1" * 64, cwe=319, rule_ids=["10035"], asset_id=aid)
        crossmerge.recompute(s, engagement, actor="tester")
        assert a.merged_into_id is None  # CSP vs HSTS: different issues
        assert b.merged_into_id is None and c.merged_into_id == b.id  # HSTS pair, webcheck is higher


# ------------------------------------------------------------------ no cross-host
def test_never_merges_across_hosts(engagement):
    from attestra import crossmerge, db

    with db.session() as s:
        a = _row(s, engagement, tool="nuclei", title="SQLi", severity="high", location=SHOP + "/login",
                 fp="2" * 64, cves=["CVE-2023-1234"], cwe=89)
        b = _row(s, engagement, tool="zap", title="SQL Injection", severity="high",
                 location="https://api.shop.example.com/login", fp="3" * 64, cves=["CVE-2023-1234"], cwe=89)
        c = _row(s, engagement, tool="webcheck", title="HSTS header missing on HTTPS", severity="medium",
                 location="https://www.shop.example.com/", fp="4" * 64, rule_ids=["webcheck/hsts-present"])
        d = _row(s, engagement, tool="zap", title="Strict-Transport-Security Header Not Set", severity="low",
                 location=SHOP + "/", fp="5" * 64, rule_ids=["10035"])
        res = crossmerge.recompute(s, engagement, actor="tester")
        assert res["groups"] == 0
        assert all(x.merged_into_id is None for x in (a, b, c, d))


def test_cwe_merge_needs_specific_cwe_and_shared_path(engagement):
    from attestra import crossmerge, db

    with db.session() as s:
        a = _row(s, engagement, tool="nuclei", title="SQLi in login", severity="critical", location=SHOP + "/login",
                 fp="6" * 64, cwe=89)
        b = _row(s, engagement, tool="zap", title="SQL Injection", severity="high", location=SHOP + "/",
                 fp="7" * 64, cwe=89)
        b.affected_urls = [SHOP + "/search?q=1 [param: q]", SHOP + "/login [param: user]"]
        g1 = _row(s, engagement, tool="nuclei", title="Something", severity="low", location=SHOP + "/a",
                  fp="8" * 64, cwe=693)
        g2 = _row(s, engagement, tool="zap", title="Other thing", severity="low", location=SHOP + "/a",
                  fp="9" * 64, cwe=693)
        crossmerge.recompute(s, engagement, actor="tester")
        assert b.merged_into_id == a.id and b.merge_rationale == "cwe:CWE-89+path"
        assert g1.merged_into_id is None and g2.merged_into_id is None  # CWE-693 is too generic


# ------------------------------------------------------------------ triage preserved
def test_triage_history_preserved_and_recompute_idempotent(engagement):
    from attestra import crossmerge, db, services
    from attestra.models import AuditEvent

    with db.session() as s:
        aid = _asset_id(s, engagement)
        low = _row(s, engagement, tool="testssl", title="TLS: SSLv3 protocol offered", severity="medium",
                   location="shop.example.com:443", fp="aa" * 32, cwe=326, rule_ids=["SSLv3"], asset_id=aid,
                   status="triaged")
        low.validated_by = "alice"
        high = _row(s, engagement, tool="nuclei", title="Deprecated TLS Detection", severity="high",
                    location="shop.example.com:443", fp="bb" * 32, rule_ids=["deprecated-tls"], asset_id=aid)
        from attestra.models import FindingObservation

        s.add(FindingObservation(finding_id=high.id, engagement_id=engagement, tool="nuclei",
                                 original_id="deprecated-tls:ssl_3.0", severity="high", title=high.title))
        s.flush()
        first = crossmerge.recompute(s, engagement, actor="tester")
        assert first["linked"] == 1 and low.merged_into_id == high.id
        assert low.merge_rationale == "map:tls:sslv3-offered"
        # Triage state on the related row is untouched.
        assert (low.status, low.validated_by, low.severity) == ("triaged", "alice", "medium")
        again = crossmerge.recompute(s, engagement, actor="tester")
        assert again["linked"] == 0 and again["unlinked"] == 0
        assert len(_all(s, engagement)) == 2
        events = list(s.scalars(select(AuditEvent).where(AuditEvent.action == "finding.cross_merge")))
        assert [e.entity_id for e in events] == [low.id]

        # Primary marked false positive: the open related row is shown instead, with its own severity.
        services.transition(s, high.id, to="false_positive", note="not reachable", actor="tester")
        shown = crossmerge.collapse(s, services.list_findings(s, engagement))
        assert [f.id for f in shown] == [low.id]
        assert shown[0].effective_severity == "medium"
        src = {x["finding_id"]: x for x in shown[0].cross_sources}
        assert src[high.id]["status_label"] == "False Positive"


# ------------------------------------------------------------------ reports
def test_reports_show_severity_by_tool_and_sources(engagement):
    from attestra import db
    from attestra.reports import generate_report
    from attestra.reports.markdown_export import export_engagement_markdown

    with db.session() as s:
        _import_three(s, engagement)
        r = generate_report(s, engagement, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")
        md = export_engagement_markdown(s, engagement, actor="tester")
    assert "<th>Severity by tool</th>" in body
    assert "<b>Sources.</b> (3)" in body
    assert "- Severity by tool: Medium (" in md
    assert "### Sources (3)" in md
    assert "Webcheck: Medium" in md and "ZAP: Low" in md and "Nuclei: Info" in md


def test_concepts_table_examples():
    from attestra.crossmerge import concepts_for

    class F:
        def __init__(self, tools, rule_ids, title):
            self.tools, self.rule_ids, self.title = tools, rule_ids, title

    assert concepts_for(F(["zap"], ["10020"], "Missing Anti-clickjacking Header"), []) == {"header:x-frame-options-missing"}
    assert concepts_for(F(["zap"], ["10020"], "Multiple X-Frame-Options Header Entries"), []) == frozenset()
    assert concepts_for(F(["zap"], ["10055"], "CSP: script-src unsafe-inline"), []) == {"csp:script-src:unsafe-inline"}
    assert concepts_for(F(["webcheck"], ["webcheck/csp:script-src:unsafe-inline"], "CSP: script-src unsafe-inline"), []) == {"csp:script-src:unsafe-inline"}
    assert concepts_for(F(["testssl"], ["TLS1_1"], "TLS: TLS 1.1 protocol offered"), []) == {"tls:tls1.1-offered"}
    assert concepts_for(F(["testssl"], ["cert_notAfter"], "Certificate expires soon (5 days)"), []) == frozenset()
