"""Phase 0: remediation pack matching (attestra/remediation/match.py) never maps own-header titles to CSP."""

from __future__ import annotations

from types import SimpleNamespace

from attestra.remediation.match import (
    format_remediation_markdown,
    pack_for_finding,
    remediation_for_finding,
    resolve_concepts,
)
from attestra.remediation.packs import REMEDIATION_PACKS, pack_for_concept

_CSP_CONCEPTS = {"header:csp-missing", "header:csp-weak", "csp:weak-or-incomplete"}


def _finding(title: str, **kw) -> SimpleNamespace:
    base = {"title": title, "tools": [], "rule_ids": [], "rule_id": None, "description": "", "location": ""}
    base.update(kw)
    return SimpleNamespace(**base)


# @lat: [[tests#test_remediation_match.py#Permissions-Policy never resolves to a CSP pack]]
def test_permissions_policy_title_gets_own_pack_not_csp():
    f = _finding("Permissions Policy Header Not Set")
    concepts = resolve_concepts(f)
    assert concepts[0] == "header:permissions-policy-missing"
    assert not (set(concepts) & _CSP_CONCEPTS)
    out = remediation_for_finding(f)
    assert out["concept"] == "header:permissions-policy-missing"
    assert "content-security-policy" not in out["recommended_fix"].lower()
    assert "permissions-policy" in out["recommended_fix"].lower()


def test_feature_policy_alias_maps_to_permissions_policy_pack():
    assert pack_for_finding(_finding("Feature-Policy header not set"))["concept"] == "header:permissions-policy-missing"


# @lat: [[tests#test_remediation_match.py#Expect-CT resolves to its deprecated-header pack]]
def test_expect_ct_title_gets_deprecated_pack_not_csp():
    f = _finding("Expect-CT header not set")
    out = remediation_for_finding(f)
    assert out["concept"] == "header:expect-ct-deprecated"
    assert out["concept"] not in _CSP_CONCEPTS
    assert out["recommendation_text"]
    assert "expect-ct" in out["recommendation_markdown"].lower()


def test_cross_origin_isolation_headers_get_own_packs():
    assert pack_for_finding(_finding("Cross-Origin-Embedder-Policy header missing"))["concept"] == "header:coep-missing"
    assert pack_for_finding(_finding("Cross-Origin-Opener-Policy header missing"))["concept"] == "header:coop-missing"
    assert pack_for_finding(_finding("Cross-Origin-Resource-Policy header missing"))["concept"] == "header:corp-missing"
    assert (
        pack_for_finding(_finding("X-Permitted-Cross-Domain-Policies header missing"))["concept"]
        == "header:x-permitted-cross-domain-missing"
    )


# @lat: [[tests#test_remediation_match.py#CSP titles still resolve to CSP packs]]
def test_csp_titles_still_get_csp_packs():
    assert pack_for_finding(_finding("Content Security Policy (CSP) Header Not Set"))["concept"] == "header:csp-missing"
    weak = pack_for_finding(_finding("CSP: script-src unsafe-eval"))
    assert weak["concept"] == "csp:weak-or-incomplete"
    # Alias key resolves to the unified CSP pack.
    assert pack_for_concept("header:csp-weak")["concept"] == "csp:weak-or-incomplete"


def test_unknown_title_returns_empty_remediation():
    out = remediation_for_finding(_finding("Something nobody has a pack for"))
    assert out["concept"] is None
    assert out["recommendation_text"] == ""
    assert out["config_examples"] == {}
    assert pack_for_finding(_finding("")) is None


# @lat: [[tests#test_remediation_match.py#Markdown has the seven sections]]
def test_markdown_has_all_sections_and_config_blocks():
    md = format_remediation_markdown(pack_for_concept("header:hsts-missing"))
    for heading in (
        "### Root cause",
        "### Recommended fix",
        "### Configuration examples",
        "### Code example",
        "### Compatibility",
        "### Verification steps",
        "### Retest instructions",
    ):
        assert heading in md
    assert md.startswith("## Remediation (`header:hsts-missing`)")
    assert "```" in md
    assert format_remediation_markdown(None) == ""


def test_every_pack_has_title_match_and_concept():
    for key, pack in REMEDIATION_PACKS.items():
        assert pack.get("concept"), key
        assert pack.get("title_match"), key
        assert pack.get("recommended_fix"), key
