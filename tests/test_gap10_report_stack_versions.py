"""ShieldByte Gap #10: stack layers, AI adapter versions, numbering legend."""
# @lat: [[tests#Gap 10 report stack versions]]

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace


# @lat: [[tests#Gap 10 report stack versions#Express plus Cloudflare prefers node origin]]
def test_detect_server_type_express_plus_cloudflare_prefers_node():
    from attestra.library.fix_snippets import detect_server_type, detect_stack_layers

    blob = "X-Powered-By: Express behind Cloudflare CDN cf-ray"
    assert detect_server_type(blob) == "node"
    layers = detect_stack_layers(blob)
    assert layers["origin"] == "node"
    assert layers["edge"] == "cloudflare"
    assert layers["proxy"] is None


# @lat: [[tests#Gap 10 report stack versions#Layered snippets return node and cloudflare]]
def test_snippets_for_report_layered_node_and_cloudflare():
    from attestra.library.fix_snippets import BY_TITLE, guidance_from_mapping, snippets_for_report

    g = guidance_from_mapping(BY_TITLE["Server version disclosed in headers"])
    layers = {"origin": "node", "edge": "cloudflare", "proxy": None}
    pairs = snippets_for_report(g, "node", layers=layers)
    keys = [k for k, _ in pairs]
    assert keys == ["node", "cloudflare"]
    assert "helmet" in pairs[0][1].lower() or "x-powered-by" in pairs[0][1].lower()
    assert "cloudflare" in pairs[1][1].lower() or "transform" in pairs[1][1].lower()


# @lat: [[tests#Gap 10 report stack versions#Ambiguous nginx apache still None]]
def test_detect_server_type_nginx_plus_apache_still_ambiguous():
    from attestra.library.fix_snippets import detect_server_type, detect_stack_layers

    blob = "Server: nginx and Apache httpd both mentioned"
    assert detect_server_type(blob) is None
    layers = detect_stack_layers(blob)
    assert layers["origin"] is None
    assert layers["edge"] is None


# @lat: [[tests#Gap 10 report stack versions#Helmet node snippets on header titles]]
def test_helmet_snippet_node_on_header_titles():
    from attestra.library.fix_snippets import BY_TITLE

    titles = (
        "X-Content-Type-Options is missing or not nosniff",
        "Referrer-Policy is not a strict value",
        "Missing or weak Content Security Policy",
        "Missing HTTP Strict Transport Security header",
        "Clickjacking: page can be framed",
    )
    for title in titles:
        node = BY_TITLE[title].get("snippet_node") or ""
        assert node.strip(), f"missing snippet_node for {title!r}"
        assert "helmet" in node.lower() or "Permissions-Policy" in node
        # Existing stacks must remain.
        assert (BY_TITLE[title].get("snippet_nginx") or "").strip()
        assert (BY_TITLE[title].get("snippet_cloudflare") or "").strip()


def _pkg_status(name: str, installed: str | None):
    return SimpleNamespace(name=name, installed=installed, ok=bool(installed), expected="", detail="")


# @lat: [[tests#Gap 10 report stack versions#Garak version probe mocked]]
def test_garak_version_probe_mocked(monkeypatch):
    from attestra.runner.scanners.garak import GarakAdapter
    import attestra.runner.scanners.garak as mod

    monkeypatch.setattr(
        "attestra.scanner_runtime.check_python_package",
        lambda name, expected="": _pkg_status(name, "0.17.1"),
    )
    monkeypatch.setattr(mod, "_shared_python", lambda: None)
    assert GarakAdapter().version() == "garak 0.17.1"


# @lat: [[tests#Gap 10 report stack versions#Promptfoo version probe mocked]]
def test_promptfoo_version_probe_mocked(monkeypatch):
    from attestra.runner.scanners.promptfoo import PromptfooAdapter

    monkeypatch.setattr(
        "attestra.scanner_runtime.check_promptfoo",
        lambda: _pkg_status("promptfoo", "0.118.12"),
    )
    assert PromptfooAdapter().version() == "promptfoo 0.118.12"


# @lat: [[tests#Gap 10 report stack versions#Safelabs version probe mocked]]
def test_safelabs_version_probe_mocked(monkeypatch):
    from attestra.runner.scanners.safelabs import SafeLabsAdapter
    import attestra.runner.scanners.safelabs as mod

    monkeypatch.setattr(
        "attestra.scanner_runtime.check_python_package",
        lambda name, expected="": _pkg_status(name, "0.12.0"),
    )
    monkeypatch.setattr(mod, "_shared_python", lambda: None)
    assert SafeLabsAdapter().version() == "safelabs-eval 0.12.0"


# @lat: [[tests#Gap 10 report stack versions#Unknown version never invented]]
def test_adapter_version_unknown_not_invented(monkeypatch):
    from attestra.runner.scanners.garak import GarakAdapter
    from attestra.runner.scanners.promptfoo import PromptfooAdapter
    from attestra.runner.scanners.safelabs import SafeLabsAdapter
    import attestra.runner.scanners.garak as garak_mod
    import attestra.runner.scanners.safelabs as safelabs_mod

    monkeypatch.setattr(
        "attestra.scanner_runtime.check_python_package",
        lambda name, expected="": _pkg_status(name, None),
    )
    monkeypatch.setattr(
        "attestra.scanner_runtime.check_promptfoo",
        lambda: _pkg_status("promptfoo", None),
    )
    monkeypatch.setattr(garak_mod, "_shared_python", lambda: None)
    monkeypatch.setattr(safelabs_mod, "_shared_python", lambda: None)
    assert GarakAdapter().version() == "garak"
    assert PromptfooAdapter().version() == "promptfoo"
    assert SafeLabsAdapter().version() == "safelabs-eval"


# @lat: [[tests#Gap 10 report stack versions#Numbering legend only present types]]
def test_numbering_legend_only_present_types():
    from attestra.reports.render import _numbering_legend

    eng = SimpleNamespace(id=42)
    findings = [SimpleNamespace(id=1, evidence=[SimpleNamespace(id=9)])]
    imports = [SimpleNamespace(id=3)]
    scans = [SimpleNamespace(id=7, auth_profile_id=5)]
    retests = [{"finding_id": 1}]
    figures = [{"id": "F-1-1"}]

    rows = _numbering_legend(eng, findings, imports, scans, retests, figures)
    labels = {r["label"] for r in rows}
    assert labels == {
        "Engagement",
        "Finding",
        "Scan / run",
        "Import",
        "Auth profile",
        "Retest",
        "Evidence",
    }
    # No unused types when empty inputs.
    bare = _numbering_legend(eng, [], [], [], [], [])
    assert [r["label"] for r in bare] == ["Engagement"]
    assert "Auth profile" not in {r["label"] for r in bare}
    assert "Retest" not in {r["label"] for r in bare}


# @lat: [[tests#Gap 10 report stack versions#Legend in technical HTML]]
def test_numbering_legend_in_technical_html(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert 'id="numbering-legend"' in body
    assert "Report Identifier and Numbering Legend" in body
    assert "Engagement #" in body
    assert ">Finding<" in body or "Finding" in body
    # Imports exist on the loaded fixture — Import row must appear; auth profile may not.
    assert "Import" in body
    assert "Unused types are omitted" in body or "never placeholder" in body.lower()
