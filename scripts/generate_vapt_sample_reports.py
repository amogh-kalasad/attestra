"""Generate synthetic sample HTML reports into docs/vapt/samples/ for review."""

from __future__ import annotations

import shutil
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "vapt" / "samples"


def main() -> None:
    from attestra import config, db, services
    from attestra.compliance.engine import clear_library_cache
    from attestra.reports import generate_report

    OUT.mkdir(parents=True, exist_ok=True)
    clear_library_cache()
    today = date.today()
    fixtures = ROOT / "tests" / "fixtures"

    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Sample Corp (synthetic)",
            name="Sample VA + PT coverage engagement",
            type="vapt",
            frameworks=[
                "pci_dss_4",
                "iso_27001_2022",
                "soc2",
                "cert_in_2022",
                "nist_csf_2",
            ],
            window_start=today - timedelta(days=7),
            window_end=today + timedelta(days=7),
            actor="sample-generator",
        )
        services.add_authorization(
            s,
            e.id,
            filename="authorization.txt",
            data=(fixtures / "authorization.txt").read_bytes(),
            signer="Sample CISO",
            signed_on=today - timedelta(days=5),
            expires_on=today + timedelta(days=30),
            rules_of_engagement="Synthetic fixture only. No real systems tested.",
            environments=["production"],
            actor="sample-generator",
        )
        a = services.add_asset(
            s,
            e.id,
            kind="web_app",
            identifier="https://shop.example.com",
            name="Storefront",
            environment="production",
            criticality=5,
            exposure="internet",
            in_cde=True,
            actor="sample-generator",
        )
        a.test_types = ["web_dast", "manual_pt", "tls"]
        for tool, fname in [
            ("zap", "zap.json"),
            ("nuclei", "nuclei.jsonl"),
            ("trivy", "trivy.json"),
            ("sarif", "semgrep.sarif"),
        ]:
            services.import_results(
                s,
                e.id,
                tool=tool,
                filename=fname,
                data=(fixtures / fname).read_bytes(),
                actor="sample-generator",
            )
        findings = services.list_findings(s, e.id)
        if findings:
            findings[0].cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            findings[0].owasp_top10 = "A03:2021"
            findings[0].asvs_ref = "V5.1.1"
            findings[0].wstg_ref = "WSTG-INPV-05"

        tech = generate_report(s, e.id, kind="technical", actor="sample-generator")
        retest_r = generate_report(s, e.id, kind="retest", actor="sample-generator")
        comp = generate_report(s, e.id, kind="compliance", actor="sample-generator", framework="pci_dss_4")
        paths = {
            "technical.html": tech.path,
            "retest.html": retest_r.path,
            "compliance_pci_dss_4.html": comp.path,
        }
        for name, src in paths.items():
            dest = OUT / name
            shutil.copy2(src, dest)
            print(f"wrote {dest} ({dest.stat().st_size} bytes)")
        print(f"data dir: {config.DATA_DIR}")


if __name__ == "__main__":
    main()
