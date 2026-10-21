# Attestra Production Deployment Checklist

Use before promoting a build that includes the report/coverage enhancements. This checklist does **not** claim a production deployment was performed.

## Prerequisites

- [ ] Python version matches `pyproject.toml` / README  
- [ ] Dependencies installed (`pip install -e ".[dev]"` and optional `docs` / `observability` extras as needed)  
- [ ] `DATA_DIR` writable; permissions for sealed report files (`0o444`) understood  
- [ ] Signing keys provisioned (`data/keys/` or secret store); public key published for clients  
- [ ] Database migrated (`alembic upgrade head`) — **no new migration in this pass**  
- [ ] Environment secrets via secret store / env (never commit `.env` with production secrets)  
- [ ] TLS termination and HTTPS for API/UI  

## Configuration

- [ ] Confirm nine frameworks load: `python -c "from attestra.compliance.engine import load_library; print(sorted(load_library().frameworks))"`  
- [ ] Confirm template config loads: `python -c "from attestra.reports.template_config import load_template_config; print(load_template_config()['template_id'])"`  
- [ ] `retest` present in report kinds in UI dropdown  
- [ ] Tenant branding (logo/cover) tested on a non-prod tenant  
- [ ] Optional WeasyPrint / docxtpl installed if rich PDF/DOCX required  
- [ ] Ticket sync left **off** unless credentials and allow-lists configured  
- [ ] OIDC/Keycloak enabled only when IdP is ready  

## Security

- [ ] RBAC roles reviewed (tester / lead / admin / client / auditor)  
- [ ] Tenant isolation smoke test (two tenants, cross-read denied)  
- [ ] Evidence download and report download require auth + audit events  
- [ ] Public trust-center / share links remain opt-in  
- [ ] Rate limits and security headers enabled  
- [ ] Framework packs present and valid; malformed pack refuses load (see tests)  

## Functional smoke

- [ ] Create one engagement per assessment type (`va`, `pt`, `vapt`, `retest`, `continuous`)  
- [ ] Import fixture scanner results; findings appear with fingerprints  
- [ ] Generate technical report; cover, TOC, environment, CVSS vector, disclaimer present  
- [ ] Generate retest report after a finalized retest  
- [ ] Generate compliance report for each of the nine frameworks  
- [ ] Submit → QA → sign with three distinct users; verify-report succeeds  
- [ ] Failed scan does not imply “no vulnerabilities” in narrative  

## Quality gates

- [ ] `pytest -q` green (or failures documented)  
- [ ] `ruff check` clean  
- [ ] `lat check` clean after lat.md updates  
- [ ] Sample reports reviewed under `docs/vapt/samples/` (if generated)  

## Rollback

1. Redeploy previous application version (templates + `render.py` + `template_config`).  
2. No DB downgrade required for this feature set.  
3. Previously sealed HTML reports remain valid; new section content appears only on regenerate.  

## Explicit non-claims

- External penetration test of Attestra itself not completed by this checklist.  
- Framework packs are not a substitute for licensed control text or certified audit opinions.  
- Production cluster deploy (Helm/K8s) remains an ops activity beyond this document.
