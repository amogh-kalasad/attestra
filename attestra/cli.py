"""Command-line interface: `attestra --help`."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

from attestra import audit, db, services
from attestra.reports import approve_report, generate_report, verify_report

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_init(args) -> None:
    db.init()
    print("Database ready.")


def cmd_import(args) -> None:
    data = Path(args.file).read_bytes()
    with db.session() as s:
        run = services.import_results(s, args.engagement, tool=args.tool, filename=Path(args.file).name, data=data, actor=args.actor)
        _print({"import_run": run.id, "new": run.new_findings, "merged": run.updated_findings, "sha256": run.sha256})


def cmd_enrich(args) -> None:
    kev = Path(args.kev).read_bytes() if args.kev else None
    epss = Path(args.epss).read_bytes() if args.epss else None
    with db.session() as s:
        _print(services.enrich(s, kev_json=kev, epss_csv=epss, actor=args.actor))


def cmd_findings(args) -> None:
    with db.session() as s:
        for f in services.list_findings(s, args.engagement, args.status):
            print(f"F-{f.id:<4} {f.severity:<8} risk {f.risk_score:5.1f} {'KEV ' if f.kev else '    '}{f.status:<14} {f.title[:60]}  [{f.location[:50]}]")


def cmd_transition(args) -> None:
    with db.session() as s:
        f = services.transition(s, args.finding, to=args.to, note=args.note, actor=args.actor)
        print(f"F-{f.id} -> {f.status}")


def cmd_compliance(args) -> None:
    with db.session() as s:
        for r in services.compliance(s, args.engagement, args.framework):
            mark = "*" if r.confirmed else " "
            print(f"{r.ref:<12} {r.status:<13}{mark} {r.title[:70]}")
        print("\n* = confirmed by an assessor; others are proposed.")


def cmd_report(args) -> None:
    with db.session() as s:
        r = generate_report(s, args.engagement, kind=args.kind, framework=args.framework or "", actor=args.actor)
        _print({"report": r.id, "version": r.version, "path": r.path, "sha256": r.sha256, "status": r.status})


def cmd_approve(args) -> None:
    with db.session() as s:
        r = approve_report(s, args.report, actor=args.actor)
        _print({"report": r.id, "status": r.status, "approved_by": r.approved_by, "signature": r.signature})


def cmd_verify_report(args) -> None:
    with db.session() as s:
        _print(verify_report(s, args.report))


def cmd_verify_audit(args) -> None:
    with db.session() as s:
        ok, bad = audit.verify(s)
    print("Audit chain intact." if ok else f"Audit chain BROKEN at event {bad}.")
    sys.exit(0 if ok else 1)


def cmd_demo(args) -> None:
    """Load a synthetic engagement from tests/fixtures so the dashboard has data."""
    db.init()
    today = date.today()
    lead, tester, qa, assessor = "priya.lead", "arjun.tester", "meera.qa", "rahul.qsa"
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="Example Retail Pvt Ltd", name="FY27 Q3 VAPT: e-commerce platform", type="vapt",
            frameworks=["pci_dss_4", "iso_27001_2022", "soc2"],
            window_start=today - timedelta(days=7), window_end=today + timedelta(days=7), actor=lead,
        )
        services.add_authorization(
            s, e.id, filename="authorization.txt", data=(FIXTURES / "authorization.txt").read_bytes(),
            signer="CISO, Example Retail", signed_on=today - timedelta(days=10), expires_on=today + timedelta(days=30),
            rules_of_engagement="Business hours only; no denial-of-service; production non-intrusive only.",
            environments=["production", "staging"], actor=lead,
        )
        for kind, ident, name, env, crit, exp, cde in [
            ("web_app", "https://shop.example.com", "Storefront", "production", 5, "internet", True),
            ("web_app", "https://legacy.example.com", "Legacy storefront", "staging", 2, "internet", False),
            ("image", "registry.example.com/shop/api", "Shop API image", "production", 4, "internal", True),
            ("repo", "services/payments", "Payments service", "production", 5, "internal", True),
            ("repo", "web/src", "Web frontend", "production", 3, "internal", False),
        ]:
            services.add_asset(
                s, e.id, kind=kind, identifier=ident, name=name, environment=env, criticality=crit,
                exposure=exp, in_cde=cde, intrusive_allowed=(env != "production"), actor=lead,
            )
        for tool, fname in [("zap", "zap.json"), ("nuclei", "nuclei.jsonl"), ("trivy", "trivy.json"), ("sarif", "semgrep.sarif")]:
            services.import_results(s, e.id, tool=tool, filename=fname, data=(FIXTURES / fname).read_bytes(), actor=tester)
        services.enrich(s, kev_json=(FIXTURES / "kev.json").read_bytes(), epss_csv=(FIXTURES / "epss.csv").read_bytes(), actor=lead)

        # A tester triages and validates the top items; one is fixed and passes retest.
        findings = services.list_findings(s, e.id)
        for f in findings[:4]:
            services.transition(s, f.id, to="triaged", actor=tester)
            services.transition(s, f.id, to="validated", actor=tester, note="Confirmed manually per WSTG.")
        services.add_evidence(
            s, findings[0].id, kind="note", filename="validation-notes.txt",
            data=b"Synthetic demo evidence: request/response pair captured during validation.", note="Demo", actor=tester,
        )
        lowest = findings[-1]
        services.transition(s, lowest.id, to="triaged", actor=tester)
        services.transition(s, lowest.id, to="validated", actor=tester)
        services.transition(s, lowest.id, to="fixed", actor=lead, note="Patched in release 1.4.3")
        services.transition(s, lowest.id, to="retest_passed", actor=qa, note="Retest clean")

        services.get_or_create_tenant(
            s, "Example Retail Pvt Ltd", lead, industry="Retail / e-commerce",
            contact_name="Anita Rao, CISO", contact_email="security@example.com",
        )
        services.confirm_control(
            s, e.id, framework="pci_dss_4", ref="11.4.1", status="met", assessor=assessor,
            rationale="Methodology follows OWASP WSTG and covers application and network layers; reviewed.",
        )
        tech = generate_report(s, e.id, kind="technical", actor=tester)
        approve_report(s, tech.id, actor=qa)
        generate_report(s, e.id, kind="executive", actor=tester)
        for fw in ("pci_dss_4", "iso_27001_2022", "soc2"):
            generate_report(s, e.id, kind="compliance", framework=fw, actor=tester)
        print(f"Demo engagement #{e.id} loaded with {len(findings)} findings. Run `attestra serve` and open http://127.0.0.1:8000")


def cmd_serve(args) -> None:
    import uvicorn

    uvicorn.run("attestra.api:app", host=args.host, port=args.port, reload=False)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="attestra", description="Attestra: from findings to signed attestation.")
    p.add_argument("--actor", default="cli", help="who is acting (recorded in the audit log)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database").set_defaults(fn=cmd_init)
    sub.add_parser("demo", help="load a synthetic demo engagement").set_defaults(fn=cmd_demo)

    sp = sub.add_parser("import", help="import a scanner result file")
    sp.add_argument("engagement", type=int)
    sp.add_argument("tool", choices=["zap", "nuclei", "trivy", "sarif"])
    sp.add_argument("file")
    sp.set_defaults(fn=cmd_import)

    sp = sub.add_parser("enrich", help="apply CISA KEV JSON and/or FIRST EPSS CSV feeds")
    sp.add_argument("--kev")
    sp.add_argument("--epss")
    sp.set_defaults(fn=cmd_enrich)

    sp = sub.add_parser("findings", help="list findings by risk")
    sp.add_argument("engagement", type=int)
    sp.add_argument("--status")
    sp.set_defaults(fn=cmd_findings)

    sp = sub.add_parser("transition", help="move a finding through its lifecycle")
    sp.add_argument("finding", type=int)
    sp.add_argument("to")
    sp.add_argument("--note", default="")
    sp.set_defaults(fn=cmd_transition)

    sp = sub.add_parser("compliance", help="show control status for a framework")
    sp.add_argument("engagement", type=int)
    sp.add_argument("framework", choices=["pci_dss_4", "iso_27001_2022", "soc2"])
    sp.set_defaults(fn=cmd_compliance)

    sp = sub.add_parser("report", help="generate a draft report")
    sp.add_argument("engagement", type=int)
    sp.add_argument("kind", choices=["technical", "executive", "compliance"])
    sp.add_argument("--framework")
    sp.set_defaults(fn=cmd_report)

    sp = sub.add_parser("approve", help="approve and sign a report (four-eyes)")
    sp.add_argument("report", type=int)
    sp.set_defaults(fn=cmd_approve)

    sp = sub.add_parser("verify-report", help="check a report's hash and signature")
    sp.add_argument("report", type=int)
    sp.set_defaults(fn=cmd_verify_report)

    sub.add_parser("verify-audit", help="verify the audit log hash chain").set_defaults(fn=cmd_verify_audit)

    sp = sub.add_parser("serve", help="run the API and dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8000)
    sp.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except (services.ServiceError, LookupError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
