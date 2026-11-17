"""Scaffold a new scanner adapter, importer and contract test (L-01).

    python scripts/new_adapter.py mytool --import-tool mytool --tier T1 --egress target \
        --kinds web_app,api --licence MIT [--image-key mytool] [--dry-run] [--force]

Creates (never overwrites unless --force):
  attestra/runner/scanners/<name>.py   adapter with meta = AdapterMeta(...)
  attestra/importers/<import_tool>.py  importer stub (parse(raw) -> list[NormalizedFinding])
  tests/runner/test_adapter_<name>.py  contract + argv tests

It prints (does not apply) the two registry lines the integration step adds:
  runner/scanners/registry.py   "<name>": <Class>()
  importers/__init__.py         "<import_tool>": <import_tool>.parse
No orchestration-core file needs to change.
"""
# @lat: [[attack-surface-and-platform#Adapter SDK]]

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIERS = ("T0", "T1", "T2", "T3")
EGRESS = ("none", "target", "third_party", "cloud_api")

ADAPTER = '''"""{name} adapter (scaffolded by scripts/new_adapter.py). Fill in build_argv/docker_args."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile


class {cls}(ScannerAdapter):
    name = "{name}"
    import_tool = "{import_tool}"
    image_key = "{image_key}"
    out_name = "{name}-out.json"
    adapter_version = "0.1"
    meta = AdapterMeta(
        capabilities=("{capability}",),
        asset_kinds={kinds!r},
        safety_tier="{tier}",
        network_egress="{egress}",
        resource_profile=ResourceProfile(cpu=1, mem_mb=512, timeout_s=1800),
        licence="{licence}",
        image_ref_env="{image_env}",
        output_schema="{import_tool}-json",
    )

    def available(self) -> bool:
        return which("{name}") is not None

    def version(self) -> str:
        return "{name}"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("{name} needs a DNS-pinned target")
        # Scan only the pinned address; keep rate and time bounded.
        return ["{name}", "--target", target.ip, "--output", str(out_file)]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        if not isinstance(target, PinnedTarget):
            raise ValueError("{name} needs a DNS-pinned target")
        return ["--target", target.ip, "--output", f"{{CONTAINER_OUT}}/{{out_file.name}}"]

    def validate_report(self, raw: bytes) -> str | None:
        try:
            from attestra.importers import {import_tool} as imp

            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"{name} output could not be read: {{exc}}"[:500]
        return None
'''

IMPORTER = '''"""{import_tool} importer (scaffolded by scripts/new_adapter.py)."""

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw.decode("utf-8-sig") or "[]")  # raises on malformed input
    items = doc if isinstance(doc, list) else [doc]
    out: list[NormalizedFinding] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        out.append(
            NormalizedFinding(
                tool="{import_tool}",
                rule_id=str(item["id"]),
                title=str(item.get("title") or item["id"]),
                severity=str(item.get("severity") or "info").lower(),
                location=str(item.get("location") or ""),
                description=str(item.get("description") or ""),
            )
        )
    return out
'''

TEST = '''"""Contract tests for the scaffolded {name} adapter."""

from pathlib import Path

from attestra.runner.scanners import sdk
from attestra.runner.scanners.{name} import {cls}


def test_{name}_passes_adapter_contract(tmp_path: Path):
    assert sdk.contract_problems({cls}(), tmp_dir=tmp_path) == []


def test_{name}_rejects_unpinned_target(tmp_path: Path):
    import pytest

    with pytest.raises(ValueError):
        {cls}().build_argv("https://example.invalid/", out_file=tmp_path / "o.json")
'''


def camel(name: str) -> str:
    return "".join(p.capitalize() for p in name.split("_")) + "Adapter"


def render(args) -> dict[Path, str]:
    name = args.name
    import_tool = args.import_tool or name
    kinds = tuple(k.strip() for k in args.kinds.split(",") if k.strip())
    image_key = args.image_key if args.image_key is not None else name
    ctx = {
        "name": name,
        "cls": camel(name),
        "import_tool": import_tool,
        "image_key": image_key,
        "image_env": f"ATTESTRA_IMAGE_{image_key.upper()}" if image_key else "",
        "tier": args.tier,
        "egress": args.egress,
        "kinds": kinds,
        "licence": args.licence,
        "capability": args.capability or name,
    }
    return {
        ROOT / "attestra" / "runner" / "scanners" / f"{name}.py": ADAPTER.format(**ctx),
        ROOT / "attestra" / "importers" / f"{import_tool}.py": IMPORTER.format(**ctx),
        ROOT / "tests" / "runner" / f"test_adapter_{name}.py": TEST.format(**ctx),
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("name")
    p.add_argument("--import-tool", default="")
    p.add_argument("--image-key", default=None)
    p.add_argument("--tier", choices=TIERS, default="T1")
    p.add_argument("--egress", choices=EGRESS, default="target")
    p.add_argument("--kinds", default="web_app,api,host")
    p.add_argument("--licence", default="")
    p.add_argument("--capability", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true")
    args = p.parse_args(argv)
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,30}", args.name):
        p.error("name must be lowercase letters, digits and _ (2-31 chars)")
    if args.import_tool and not re.fullmatch(r"[a-z][a-z0-9_]{1,30}", args.import_tool):
        p.error("bad --import-tool")
    if not args.licence:
        p.error("--licence is required (record the tool's licence before adding it)")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    files = render(args)
    for path, text in files.items():
        rel = path.relative_to(ROOT)
        if path.exists() and not args.force:
            print(f"skip (exists): {rel}")
            continue
        if args.dry_run:
            print(f"would write: {rel} ({len(text)} bytes)")
            continue
        path.write_text(text, encoding="utf-8")
        print(f"wrote: {rel}")
    import_tool = args.import_tool or args.name
    print("\nIntegration (INT) adds:")
    print(f'  attestra/runner/scanners/registry.py: "{args.name}": {camel(args.name)}(),')
    print(f'  attestra/importers/__init__.py: "{import_tool}": {import_tool}.parse,')
    return 0


if __name__ == "__main__":
    sys.exit(main())
