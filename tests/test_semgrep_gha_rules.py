"""F-03 Semgrep GitHub Actions rules: structure, adapter wiring, and (when semgrep is
installed) true/false positives on fixtures. Rules are never executed against a target."""
# @lat: [[intel-and-reporting#Semgrep GitHub Actions rules]]

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from attestra.runner.scanners import semgrep as sg

FIX = Path(__file__).parent / "fixtures" / "semgrep_gha"
EXPECTED = {
    "attestra.gha.run-script-injection",
    "attestra.gha.pull-request-target-checkout-head",
    "attestra.gha.third-party-action-not-pinned",
    "attestra.gha.permissions-write-all",
}


def test_rule_files_well_formed():
    ids = set()
    for f in sorted(sg.GHA_RULES_DIR.glob("gha-*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        for r in doc["rules"]:
            ids.add(r["id"])
            assert r["languages"] == ["yaml"] and r["severity"] in ("ERROR", "WARNING")
            assert r["metadata"]["cwe"].startswith("CWE-") and r["metadata"]["attestra_rule_version"]
            assert any(".github/workflows" in p for p in r["paths"]["include"])
    assert ids == EXPECTED


def test_rules_not_under_opa_policy_dir():
    # `opa eval -d policy/` loads *.yml as data; rule files there break the scope policy.
    root = Path(__file__).resolve().parents[1]
    assert not list((root / "policy").rglob("*.yml"))


def test_adapter_adds_local_config(tmp_path, monkeypatch):
    out = tmp_path / "out" / "semgrep-out.sarif"
    out.parent.mkdir()
    argv = sg.SemgrepAdapter().build_argv(str(tmp_path), out_file=out)
    assert argv.count("--config") == 2 and str(sg.GHA_RULES_DIR) in argv and "p/default" in argv
    dargs = sg.SemgrepAdapter().docker_args(str(tmp_path), out_file=out)
    assert f"/out/{sg.RULES_SUBDIR}" in dargs
    assert sorted(p.name for p in (out.parent / sg.RULES_SUBDIR).iterdir()) == sorted(
        p.name for p in sg.GHA_RULES_DIR.glob("gha-*.yml"))
    monkeypatch.setenv("ATTESTRA_SEMGREP_GHA_RULES", "0")
    assert sg.SemgrepAdapter().build_argv(str(tmp_path), out_file=out).count("--config") == 1


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_rules_fire_on_vulnerable_only():
    proc = subprocess.run(
        ["semgrep", "scan", "--metrics", "off", "--disable-version-check", "--config", str(sg.GHA_RULES_DIR),
         "--json", str(FIX)],
        capture_output=True, text=True, timeout=300, check=False,
    )
    doc = json.loads(proc.stdout)
    # semgrep prefixes check ids with the config path; keep the rule id itself.
    hits = {("attestra.gha." + r["check_id"].rsplit("attestra.gha.", 1)[-1], Path(r["path"]).parts[-4])
            for r in doc["results"]}
    assert {h for h, where in hits if where == "vulnerable"} == EXPECTED
    assert not [h for h in hits if h[1] == "safe"]
