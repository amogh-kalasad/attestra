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

        for name, data in _framework_extras(s, engagement_id, framework).items():
            add(name, data)

        meta = {
            "framework": framework,
            "engagement_id": eng.id,
            "control_count": len(results),
            "pack": {
                "pci_dss_4": "PCI binder indexed by requirement",
                "iso_27001_2022": "ISO Annex A evidence register",
                "soc2": "SOC 2 period population sample",
                "iso_42001_2023": "ISO 42001 AIMS readiness register",
            }.get(framework, lib.frameworks[framework].get("pack", "framework pack")),
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


def _csv_bytes(header: list[str], rows) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8")


def _framework_extras(s: Session, engagement_id: int, framework: str) -> dict[str, bytes]:
    """Extra pack files: PCI calendar/ASV/segmentation (C9), ISO SoA/NC/9.2 samples (C10)."""
    out: dict[str, bytes] = {}
    if framework == "pci_dss_4":
        cal = services.pci_scan_calendar(s, engagement_id)
        out["pci/scan_calendar.csv"] = _csv_bytes(
            ["quarter", "due", "external_scans", "external_passing", "status"],
            [[q["quarter"], q["due"], q["external_scans"], q["external_passing"], q["status"]] for q in cal["quarters"]],
        )
        out["pci/asv_scans.csv"] = _csv_bytes(
            ["id", "vendor", "scan_date", "passing", "source", "components", "failing", "sha256"],
            [[a.id, a.vendor, a.scan_date, a.passing, a.source, a.item_count, a.failing_count, a.sha256]
             for a in services.list_asv_scans(s, engagement_id)],
        )
        out["pci/segmentation_tests.csv"] = _csv_bytes(
            ["id", "boundary", "source_zone", "target_zone", "method", "result", "tested_on", "tester", "notes"],
            [[t.id, t.boundary, t.source_zone, t.target_zone, t.method, t.result, t.tested_on, t.tester, t.notes]
             for t in services.list_segmentation_tests(s, engagement_id)],
        )
    elif framework == "iso_27001_2022":
        out["iso/statement_of_applicability.csv"] = _csv_bytes(
            ["control_ref", "title", "applicable", "implementation", "justification", "updated_by"],
            [[r.control_ref, r.title, r.applicable, r.implementation, r.justification, r.updated_by]
             for r in services.list_soa(s, engagement_id)],
        )
        out["iso/nonconformities.csv"] = _csv_bytes(
            ["id", "control_ref", "grade", "status", "description", "root_cause", "corrective_action",
             "owner", "due", "verified_by", "closed_at"],
            [[n.id, n.control_ref, n.grade, n.status, n.description, n.root_cause, n.corrective_action,
              n.owner, n.due or "", n.verified_by, n.closed_at or ""]
             for n in services.list_nonconformities(s, engagement_id)],
        )
        out["iso/audit_samples_9_2.json"] = json.dumps(
            [{"id": a.id, "clause": a.clause, "population": a.population, "population_size": a.population_size,
              "sample_size": a.sample_size, "seed": a.seed, "items": a.items, "created_by": a.created_by,
              "created_at": a.created_at.isoformat() if a.created_at else ""}
             for a in services.list_audit_samples(s, engagement_id)],
            indent=2,
        ).encode("utf-8")
    elif framework == "iso_42001_2023":
        from attestra.compliance import iso42001

        results = services.compliance(s, engagement_id, framework)
        out["iso42001/check_register.csv"] = _csv_bytes(
            iso42001.CHECK_REGISTER_HEADER, iso42001.check_register_rows(results)
        )
        out["iso42001/statement_of_applicability_draft.csv"] = _csv_bytes(
            iso42001.SOA_DRAFT_HEADER, iso42001.soa_draft_rows(results)
        )
        out["iso42001/owasp_llm_top10_2025.csv"] = _csv_bytes(iso42001.LLM_MAP_HEADER, iso42001.llm_map_rows())
    return out
