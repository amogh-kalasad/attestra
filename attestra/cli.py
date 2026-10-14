"""Command-line interface: `attestra --help`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, timedelta
from pathlib import Path

from attestra import audit, db, services
from attestra.reports import (
    approve_report,
    generate_report,
    qa_approve,
    qa_reject,
    sign_report,
    submit_report,
    verify_report,
)

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _resolve_actor(args) -> tuple[str, int | None]:
    """Return (actor name, user_id) for CLI writes.

    Prefer ``--api-key`` / ``ATTESTRA_API_KEY``. Offline local CLI falls back to
    ``--user`` (username) or the legacy ``--actor`` string with no user id.
    """
    raw_key = getattr(args, "api_key", None) or os.environ.get("ATTESTRA_API_KEY")
    if raw_key:
        from attestra.auth.keys import authenticate_api_key

        with db.session() as s:
            principal = authenticate_api_key(s, raw_key)
        if not principal:
            print("error: invalid or revoked API key", file=sys.stderr)
            sys.exit(2)
        return principal.actor, principal.user_id
    username = getattr(args, "user", None)
    if username:
        from sqlalchemy import select

        from attestra.models import User

        with db.session() as s:
            user = s.scalar(select(User).where(User.username == username.strip().lower()))
            if not user or not user.active:
                print(f"error: unknown user {username!r}", file=sys.stderr)
                sys.exit(2)
            return user.username, user.id
    return getattr(args, "actor", None) or "cli", None


def cmd_init(args) -> None:
    db.init(use_migrations=True)
    print("Database ready.")


def cmd_user_add(args) -> None:
    from attestra.auth.keys import create_user

    db.init(use_migrations=True)
    with db.session() as s:
        user = create_user(
            s,
            username=args.username,
            role=args.role,
            password=args.password,
            display_name=args.display_name or args.username,
            tenant_id=args.tenant_id,
        )
        print(f"user #{user.id} {user.username} role={user.role}")


def cmd_key_create(args) -> None:
    from sqlalchemy import select

    from attestra.auth.keys import create_api_key
    from attestra.models import User

    db.init(use_migrations=True)
    with db.session() as s:
        user = s.scalar(select(User).where(User.username == args.username.strip().lower()))
        if not user:
            print(f"error: unknown user {args.username!r}", file=sys.stderr)
            sys.exit(2)
        row, raw = create_api_key(s, user)
        print(f"api key #{row.id} prefix={row.prefix}")
        print(raw)
        print("Store this key now; it will not be shown again.", file=sys.stderr)


def cmd_migrate_storage(args) -> None:
    """Move legacy DATA_DIR/{evidence,imports,reports} into tenants/<id>/."""
    from sqlalchemy import select

    from attestra import config
    from attestra.models import Engagement, Report

    db.init(use_migrations=True)
    config.ensure_dirs()
    moved = 0
    with db.session() as s:
        for eng in s.scalars(select(Engagement)):
            tid = eng.tenant_id
            dest_root = config.DATA_DIR / "tenants" / str(tid)
            for sub in ("evidence", "imports", "reports"):
                legacy = config.DATA_DIR / sub
                if not legacy.is_dir():
                    continue
                dest = dest_root / sub
                dest.mkdir(parents=True, exist_ok=True)
                for path in legacy.iterdir():
                    if not path.is_file():
                        continue
                    target = dest / path.name
                    if not target.exists():
                        target.write_bytes(path.read_bytes())
                        target.chmod(0o444)
                        moved += 1
            for r in s.scalars(select(Report).where(Report.engagement_id == eng.id)):
                old = Path(r.path)
                if "tenants" in old.parts:
                    continue
                new = dest_root / "reports" / old.name
                if old.exists() and not new.exists():
                    new.parent.mkdir(parents=True, exist_ok=True)
                    new.write_bytes(old.read_bytes())
                    new.chmod(0o444)
                    r.path = str(new)
                    moved += 1
    print(f"migrate-storage: {moved} file(s) placed under tenants/")


def cmd_import(args) -> None:
    actor, _ = _resolve_actor(args)
    data = Path(args.file).read_bytes()
    with db.session() as s:
        run = services.import_results(s, args.engagement, tool=args.tool, filename=Path(args.file).name, data=data, actor=actor)
        _print({"import_run": run.id, "new": run.new_findings, "merged": run.updated_findings, "sha256": run.sha256})


def cmd_enrich(args) -> None:
    actor, _ = _resolve_actor(args)
    kev = Path(args.kev).read_bytes() if args.kev else None
    epss = Path(args.epss).read_bytes() if args.epss else None
    with db.session() as s:
        _print(services.enrich(s, kev_json=kev, epss_csv=epss, actor=actor))


def cmd_findings(args) -> None:
    with db.session() as s:
        for f in services.list_findings(s, args.engagement, args.status):
            print(f"F-{f.id:<4} {f.severity:<8} risk {f.risk_score:5.1f} {'KEV ' if f.kev else '    '}{f.status:<14} {f.title[:60]}  [{f.location[:50]}]")


def cmd_transition(args) -> None:
    actor, _ = _resolve_actor(args)
    with db.session() as s:
        f = services.transition(s, args.finding, to=args.to, note=args.note, actor=actor)
        print(f"F-{f.id} -> {f.status}")


def cmd_compliance(args) -> None:
    with db.session() as s:
        for r in services.compliance(s, args.engagement, args.framework):
            mark = "*" if r.confirmed else " "
            print(f"{r.ref:<12} {r.status:<13}{mark} {r.title[:70]}")
        print("\n* = confirmed by an assessor; others are proposed.")


def cmd_report(args) -> None:
    actor, user_id = _resolve_actor(args)
    with db.session() as s:
        r = generate_report(s, args.engagement, kind=args.kind, framework=args.framework or "", actor=actor, user_id=user_id)
        _print({"report": r.id, "version": r.version, "path": r.path, "sha256": r.sha256, "status": r.status})


def cmd_approve(args) -> None:
    actor, user_id = _resolve_actor(args)
    with db.session() as s:
        r = approve_report(s, args.report, actor=actor, user_id=user_id)
        _print({"report": r.id, "status": r.status, "approved_by": r.approved_by, "signature": r.signature})


def cmd_submit(args) -> None:
    actor, user_id = _resolve_actor(args)
    with db.session() as s:
        r = submit_report(s, args.report, actor=actor, user_id=user_id)
        _print({"report": r.id, "status": r.status})


def cmd_qa_approve(args) -> None:
    actor, user_id = _resolve_actor(args)
    with db.session() as s:
        r = qa_approve(s, args.report, actor=actor, user_id=user_id)
        _print({"report": r.id, "status": r.status, "qa_by": r.qa_by})


def cmd_qa_reject(args) -> None:
    actor, user_id = _resolve_actor(args)
    with db.session() as s:
        r = qa_reject(s, args.report, actor=actor, note=args.note, user_id=user_id)
        _print({"report": r.id, "status": r.status, "rejection_note": r.rejection_note})


def cmd_sign(args) -> None:
    actor, user_id = _resolve_actor(args)
    with db.session() as s:
        r = sign_report(s, args.report, actor=actor, user_id=user_id, role="lead")
        _print({"report": r.id, "status": r.status, "signature": r.signature, "algorithm": r.algorithm})


def cmd_verify_report(args) -> None:
    with db.session() as s:
        _print(verify_report(s, args.report))


def cmd_verify_audit(args) -> None:
    with db.session() as s:
        ok, bad = audit.verify(s)
    print("Audit chain intact." if ok else f"Audit chain BROKEN at event {bad}.")
    sys.exit(0 if ok else 1)


def cmd_expire_risk(args) -> None:
    db.init(use_migrations=True)
    with db.session() as s:
        n = services.expire_risk_acceptances(s)
    print(f"expired {n} risk acceptance(s)")


def cmd_compliance_export(args) -> None:
    text = services.export_compliance_library_csv()
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(text)


def cmd_demo(args) -> None:
    """Load a synthetic engagement from tests/fixtures so the dashboard has data."""
    from attestra.auth.keys import create_api_key, create_user

    db.init(use_migrations=True)
    today = date.today()
    lead, tester, qa, assessor = "priya.lead", "arjun.tester", "meera.qa", "rahul.qsa"
    with db.session() as s:
        for username, role, password in (
            (lead, "lead", "demo-lead-pass"),
            (tester, "tester", "demo-tester-pass"),
            (qa, "reviewer", "demo-qa-pass"),
            (assessor, "auditor", "demo-auditor-pass"),
        ):
            try:
                create_user(s, username=username, role=role, password=password, display_name=username)
            except ValueError:
                pass
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
        from sqlalchemy import select

        from attestra.models import User

        lead_user = s.scalar(select(User).where(User.username == lead))
        qa_user = s.scalar(select(User).where(User.username == qa))
        tech = generate_report(s, e.id, kind="technical", actor=tester, user_id=None)
        approve_report(s, tech.id, actor=qa, user_id=qa_user.id if qa_user else None)
        generate_report(s, e.id, kind="executive", actor=tester)
        for fw in ("pci_dss_4", "iso_27001_2022", "soc2"):
            generate_report(s, e.id, kind="compliance", framework=fw, actor=tester)
        if lead_user:
            _, raw = create_api_key(s, lead_user)
            print(f"Demo lead API key (store now): {raw}")
        print(f"Demo engagement #{e.id} loaded with {len(findings)} findings. Sign in as {lead} / demo-lead-pass")
        print("Run `attestra serve` and open http://127.0.0.1:8000")


def cmd_serve(args) -> None:
    import uvicorn

    uvicorn.run("attestra.api:app", host=args.host, port=args.port, reload=False)


def cmd_worker(args) -> None:
    """Claim and run scan jobs until interrupted."""
    import time

    from attestra.jobs.durable import (
        claim_job,
        new_worker_id,
        recover_interrupted_jobs,
        resume_queued_jobs,
        run_one_job,
    )
    from attestra.jobs.instance_lock import InstanceLock

    db.init(use_migrations=True)
    lock = InstanceLock("worker")
    if not lock.acquire(timeout=10):
        print("another worker holds the instance lock", file=sys.stderr)
        sys.exit(1)
    worker_id = new_worker_id()
    print(f"worker {worker_id} started")
    try:
        while True:
            with db.session() as s:
                recover_interrupted_jobs(s)
                resume_queued_jobs(s)
                services.enqueue_due_schedules(s, actor=f"worker:{worker_id}")
                job = claim_job(s, worker_id)
                if job:
                    run_one_job(s, job)
                    continue
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print("worker stopping")
    finally:
        lock.release()


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="attestra", description="Attestra: from findings to signed attestation.")
    p.add_argument("--actor", default="cli", help="legacy actor name when no --api-key / --user (offline only)")
    p.add_argument("--api-key", default=None, help="API key (or set ATTESTRA_API_KEY)")
    p.add_argument("--user", default=None, help="local username for offline CLI attribution")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database").set_defaults(fn=cmd_init)
    sub.add_parser("demo", help="load a synthetic demo engagement").set_defaults(fn=cmd_demo)

    sp = sub.add_parser("user", help="user management")
    user_sub = sp.add_subparsers(dest="user_cmd", required=True)
    spu = user_sub.add_parser("add", help="create a user")
    spu.add_argument("username")
    spu.add_argument("--role", default="tester", choices=["admin", "lead", "tester", "reviewer", "client_viewer", "auditor"])
    spu.add_argument("--password", required=True)
    spu.add_argument("--display-name", default="")
    spu.add_argument("--tenant-id", type=int, default=None)
    spu.set_defaults(fn=cmd_user_add)

    sp = sub.add_parser("key", help="API key management")
    key_sub = sp.add_subparsers(dest="key_cmd", required=True)
    spk = key_sub.add_parser("create", help="create an API key for a user")
    spk.add_argument("username")
    spk.set_defaults(fn=cmd_key_create)

    sub.add_parser("migrate-storage", help="move legacy files under tenants/<id>/").set_defaults(fn=cmd_migrate_storage)

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
    sp.add_argument(
        "kind",
        choices=["technical", "executive", "compliance", "iso_soa", "ageing", "closure_letter", "attestation_letter"],
    )
    sp.add_argument("--framework")
    sp.set_defaults(fn=cmd_report)

    sub.add_parser("expire-risk", help="reopen findings with expired risk acceptances").set_defaults(fn=cmd_expire_risk)

    sp = sub.add_parser("compliance-export", help="export control library CSV for external review")
    sp.add_argument("-o", "--output", default="")
    sp.set_defaults(fn=cmd_compliance_export)

    sp = sub.add_parser("submit", help="submit a draft report for QA")
    sp.add_argument("report", type=int)
    sp.set_defaults(fn=cmd_submit)

    sp = sub.add_parser("qa-approve", help="QA-approve a submitted report")
    sp.add_argument("report", type=int)
    sp.set_defaults(fn=cmd_qa_approve)

    sp = sub.add_parser("qa-reject", help="reject a submitted report back to draft")
    sp.add_argument("report", type=int)
    sp.add_argument("--note", required=True)
    sp.set_defaults(fn=cmd_qa_reject)

    sp = sub.add_parser("sign", help="sign a QA-approved report (lead)")
    sp.add_argument("report", type=int)
    sp.set_defaults(fn=cmd_sign)

    sp = sub.add_parser("approve", help="legacy: approve and sign a report (four-eyes)")
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

    sp = sub.add_parser("worker", help="run the durable scan job worker")
    sp.add_argument("--poll", type=float, default=2.0, help="seconds between idle polls")
    sp.set_defaults(fn=cmd_worker)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except (services.ServiceError, LookupError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
