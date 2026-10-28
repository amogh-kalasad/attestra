"""ZAP grouping: one finding per ZAP rule per host, every URL kept (affected URLs + observations)."""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select


def _inst(uri: str, param: str = "", evidence: str = "") -> dict:
    return {"uri": uri, "method": "GET", "param": param, "attack": "", "evidence": evidence, "otherinfo": ""}


def _alert(pluginid, ref, name, cwe, risk, instances):
    return {
        "pluginid": pluginid,
        "alertRef": ref,
        "alert": name,
        "riskcode": risk,
        "confidence": "2",
        "cweid": cwe,
        "desc": f"<p>{name}</p>",
        "solution": "<p>Fix it.</p>",
        "instances": instances,
    }


SHOP = "https://shop.example.com"


def _report(extra_eval_urls: tuple[str, ...] = ()) -> bytes:
    eval_urls = ["/", "/robots.txt", "/sitemap.xml", *extra_eval_urls]
    doc = {
        "site": [
            {
                "@name": SHOP,
                "alerts": [
                    # Same plugin, two alertRefs: must stay two findings.
                    _alert("10055", "10055-10", "CSP: script-src unsafe-eval", "693", "2",
                           [_inst(SHOP + p, evidence="script-src 'unsafe-eval'") for p in eval_urls]),
                    _alert("10055", "10055-5", "CSP: script-src unsafe-inline", "693", "2",
                           [_inst(SHOP + "/"), _inst(SHOP + "/robots.txt")]),
                    # Different plugin, same CWE 693, no alertRef subtype: must stay separate.
                    _alert("10021", "10021", "X-Content-Type-Options Header Missing", "693", "1",
                           [_inst(SHOP + "/"), _inst(SHOP + "/app.js", param="x-content-type-options")]),
                    # Param-level issue on two URLs: one finding, URL+param listed.
                    _alert("40012", "40012", "Cross Site Scripting (Reflected)", "79", "3",
                           [_inst(SHOP + "/search?q=1", param="q"), _inst(SHOP + "/product", param="name")]),
                ],
            },
            {
                # Same rule on a different host: separate finding.
                "@name": "https://api.shop.example.com",
                "alerts": [
                    _alert("10055", "10055-10", "CSP: script-src unsafe-eval", "693", "2",
                           [_inst("https://api.shop.example.com/"), _inst("https://api.shop.example.com/v1")]),
                ],
            },
        ]
    }
    return json.dumps(doc).encode()


def _zap_findings(s, engagement_id):
    from attestra.models import Finding

    rows = list(s.scalars(select(Finding).where(Finding.engagement_id == engagement_id).order_by(Finding.id)))
    return [f for f in rows if "zap" in (f.tools or [])]


def _by_title_host(rows):
    out = {}
    for f in rows:
        out[(f.title, f.location)] = f
    return out


def test_parser_still_emits_one_record_per_instance_with_evidence():
    from attestra.importers import zap

    nfs = zap.parse(_report())
    assert len(nfs) == 3 + 2 + 2 + 2 + 2
    first = nfs[0]
    assert first.location == SHOP + "/"
    assert any(r.startswith("evidence: ") for r in first.evidence_refs)


def test_zap_instances_grouped_per_rule_and_host(engagement):
    from attestra import db, services
    from attestra.models import FindingObservation

    with db.session() as s:
        run = services.import_results(s, engagement, tool="zap", filename="zap.json", data=_report(), actor="tester")
        rows = _zap_findings(s, engagement)
        # 4 rules on shop + 1 rule on api host (api host matches the shop asset? no: label boundary)
        titles = sorted(f.title for f in rows)
        assert run.new_findings == len(rows)
        assert run.updated_findings == 0
        shop = [f for f in rows if f.location == SHOP + "/"]
        assert sorted(f.title for f in shop) == [
            "CSP: script-src unsafe-eval",
            "CSP: script-src unsafe-inline",
            "Cross Site Scripting (Reflected)",
            "X-Content-Type-Options Header Missing",
        ], titles
        api = [f for f in rows if f.location == "https://api.shop.example.com/"]
        assert [f.title for f in api] == ["CSP: script-src unsafe-eval"]
        assert len(rows) == 5

        by = {f.title: f for f in shop}
        ev = by["CSP: script-src unsafe-eval"]
        assert ev.affected_urls == [SHOP + "/", SHOP + "/robots.txt", SHOP + "/sitemap.xml"]
        assert ev.occurrences == 3
        xss = by["Cross Site Scripting (Reflected)"]
        assert xss.affected_urls == [SHOP + "/search?q=1 [param: q]", SHOP + "/product [param: name]"]
        assert xss.severity == "high"
        xcto = by["X-Content-Type-Options Header Missing"]
        assert len(xcto.affected_urls) == 2

        obs = list(s.scalars(select(FindingObservation).where(FindingObservation.finding_id == ev.id)))
        assert sorted(o.location for o in obs) == sorted(ev.affected_urls)
        assert all(any(r.startswith("evidence: ") for r in o.evidence_refs) for o in obs)


def test_reimport_is_idempotent(engagement):
    from attestra import db, services

    data = _report()
    with db.session() as s:
        run1 = services.import_results(s, engagement, tool="zap", filename="zap.json", data=data, actor="tester")
        before = {f.id: list(f.affected_urls) for f in _zap_findings(s, engagement)}
        run2 = services.import_results(s, engagement, tool="zap", filename="zap.json", data=data, actor="tester")
        after = {f.id: list(f.affected_urls) for f in _zap_findings(s, engagement)}
    assert run2.new_findings == 0
    assert run2.updated_findings == run1.new_findings == 5
    assert before == after  # same findings, URL lists not duplicated


def test_new_url_on_rescan_joins_existing_finding(engagement):
    from attestra import db, services

    with db.session() as s:
        services.import_results(s, engagement, tool="zap", filename="zap.json", data=_report(), actor="tester")
        run2 = services.import_results(
            s, engagement, tool="zap", filename="zap2.json", data=_report(("/login",)), actor="tester"
        )
        rows = _zap_findings(s, engagement)
        ev = next(f for f in rows if f.title == "CSP: script-src unsafe-eval" and f.location == SHOP + "/")
    assert run2.new_findings == 0
    assert len(rows) == 5
    assert ev.affected_urls[-1] == SHOP + "/login"
    assert len(ev.affected_urls) == 4


def test_legacy_per_url_finding_is_adopted(engagement):
    """A finding stored before grouping (per-URL fingerprint, first URL) is adopted as the group row."""
    from attestra import db, services
    from attestra.fingerprint import fingerprint
    from attestra.models import Asset, Finding

    with db.session() as s:
        asset = s.scalar(select(Asset).where(Asset.engagement_id == engagement, Asset.identifier == SHOP))
        legacy_fp = fingerprint(
            location=SHOP + "/", cwe=693, cves=[], title="CSP: script-src unsafe-eval",
            param="", asset_id=asset.id, variant="10055-10",
        )
        legacy = Finding(
            engagement_id=engagement, asset_id=asset.id, fingerprint=legacy_fp,
            title="CSP: script-src unsafe-eval", tools=["zap"], rule_ids=["10055"], cwe=693, cves=[],
            location=SHOP + "/", severity="medium", status="triaged",
        )
        s.add(legacy)
        s.flush()
        legacy_id = legacy.id
        services.import_results(s, engagement, tool="zap", filename="zap.json", data=_report(), actor="tester")
        f = s.get(Finding, legacy_id)
        evals = [x for x in _zap_findings(s, engagement) if x.title == "CSP: script-src unsafe-eval" and x.location == SHOP + "/"]
    assert [x.id for x in evals] == [legacy_id]
    assert f.status == "triaged"  # triage state kept
    assert f.location == SHOP + "/"
    assert set(f.affected_urls) == {SHOP + "/", SHOP + "/robots.txt", SHOP + "/sitemap.xml"}


def test_scan_history_fingerprints_grouped():
    from attestra.history import _fingerprints_and_sev

    fps, by_sev = _fingerprints_and_sev(_report(), "zap", asset_id=1)
    assert len(fps) == 5
    assert sum(by_sev.values()) == 5


def test_other_tools_not_grouped():
    from attestra.fingerprint import canonicalize_for_merge

    kw = dict(location=SHOP + "/a", cwe=693, cves=[], title="t", param="p", variant="")
    assert canonicalize_for_merge(**kw, tool="nuclei", rule_key="x")["location"] == SHOP + "/a"
    zap_kw = canonicalize_for_merge(**kw, tool="zap", rule_key="10021")
    assert zap_kw["location"] == SHOP + "/"
    assert zap_kw["param"] == ""
    assert zap_kw["variant"] == "zap-10021"


def test_technical_report_lists_affected_urls(engagement):
    from attestra import db, services
    from attestra.reports import generate_report
    from attestra.reports.markdown_export import export_engagement_markdown

    with db.session() as s:
        services.import_results(s, engagement, tool="zap", filename="zap.json", data=_report(), actor="tester")
        r = generate_report(s, engagement, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")
        md = export_engagement_markdown(s, engagement, actor="tester")
    assert "### Affected URLs (3)" in md
    assert "Affected URLs.</b> (3)" in body
    assert "<li>https://shop.example.com/sitemap.xml</li>" in body
    assert "(3 affected URLs, listed below)" in body
    assert "(3 observations)" in body
