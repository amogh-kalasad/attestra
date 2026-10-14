"""Framework evidence packs (PCI binder, ISO register, SOC 2 population)."""
# @lat: [[reports#Framework packs]]

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from attestra import config, services
from attestra.compliance import load_library


def build_framework_pack(s: Session, engagement_id: int, framework: str) -> Path:
    """Write a zip with HTML index, CSV sample, and sha256 manifest."""
    eng = services.get_engagement(s, engagement_id)
    lib = load_library()
    if framework not in lib.frameworks:
        raise services.ServiceError(f"unknown framework '{framework}'")
    results = services.compliance(s, engagement_id, framework)
    findings = services.list_findings(s, engagement_id)

    buf = io.BytesIO()
    manifest: dict[str, str] = {}

    def add(name: str, data: bytes) -> None:
        manifest[name] = hashlib.sha256(data).hexdigest()
        zf.writestr(name, data)

    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        index_lines = [
            f"# {lib.frameworks[framework]['name']} evidence pack",
            f"Engagement: {eng.name}",
            f"Tenant: {eng.tenant.name}",
            "",
            "| Ref | Status | Title |",
            "| --- | --- | --- |",
        ]
        for r in results:
            index_lines.append(f"| {r.ref} | {r.status} | {r.title} |")
        add("INDEX.md", ("\n".join(index_lines) + "\n").encode("utf-8"))

        # CSV sample / period population
        csv_buf = io.StringIO()
        w = csv.writer(csv_buf)
        w.writerow(["ref", "title", "status", "proposed", "finding_ids"])
        for r in results:
            w.writerow([r.ref, r.title, r.status, r.proposed, ";".join(map(str, r.finding_ids))])
        add("controls.csv", csv_buf.getvalue().encode("utf-8"))

        findings_csv = io.StringIO()
        fw = csv.writer(findings_csv)
        fw.writerow(["id", "severity", "status", "title", "cwe", "location"])
        for f in findings:
            fw.writerow([f.id, f.severity, f.status, f.title, f.cwe or "", f.location])
        add("findings.csv", findings_csv.getvalue().encode("utf-8"))

        meta = {
            "framework": framework,
            "engagement_id": eng.id,
            "control_count": len(results),
            "pack": {
                "pci_dss_4": "PCI binder indexed by requirement",
                "iso_27001_2022": "ISO Annex A evidence register",
                "soc2": "SOC 2 period population sample",
            }.get(framework, "framework pack"),
        }
        add("meta.json", json.dumps(meta, indent=2).encode("utf-8"))
        add("MANIFEST.sha256", ("\n".join(f"{h}  {n}" for n, h in sorted(manifest.items())) + "\n").encode())

    config.ensure_dirs()
    out_dir = config.DATA_DIR / "tenants" / str(eng.tenant_id) / "packs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"eng{eng.id}-{framework}-pack.zip"
    out.write_bytes(buf.getvalue())
    out.chmod(0o444)
    return out
