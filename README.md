# Attestra

**From findings to signed attestation.**

Attestra turns security testing results into audit-ready evidence. It runs passive scans against approved targets, or imports results from the scanners your testers already use. It removes duplicates, ranks findings by risk, records human review, maps every finding to **PCI DSS v4.0.1, ISO/IEC 27001:2022 and SOC 2** controls, and produces reports that are hashed, reviewed by a second person and signed.

Attestra only tests a target when the engagement has a valid signed permission letter and the target owner has proved control of the domain.

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/USER_MANAGEMENT.md](docs/USER_MANAGEMENT.md), [SETUP_GUIDE.md](SETUP_GUIDE.md), [docs/AUTH_WEB_TESTING.md](docs/AUTH_WEB_TESTING.md).

## What Attestra does

| Area | What it does |
| --- | --- |
| Engagements | Tenants, engagements (VA, PT, VA + PT, retest, continuous), test window and target frameworks |
| Permission gate | A signed permission letter is stored hashed and write-once. Scans and imports are blocked without a valid one |
| Domain ownership | The owner proves control with a DNS TXT record (`attestra-verify=<token>`) or the file `/.well-known/attestra-verify.txt` |
| Targets | Assets with criticality 1 to 5, internet or internal exposure, and a PCI CDE flag |
| In-app scans | Passive and baseline scans run by a background worker: ZAP, webcheck (headers, cookies, DNS and email security, redirects, mixed content), testssl, Nuclei, Trivy, Semgrep, Gitleaks, Checkov, naabu and others. Scans can be cancelled. Queue the same path from the CLI with `attestra scan` |
| Auth website testing | Optional authenticated crawl and checklist (off by default). See [docs/AUTH_WEB_TESTING.md](docs/AUTH_WEB_TESTING.md) |
| Imports | ZAP, Nuclei, Trivy, SARIF (Semgrep, CodeQL, Checkov, Gitleaks and others), testssl, SSL Labs, Observatory, Burp, Nessus, Prowler, kube-bench, CycloneDX, Dependency-Track and more |
| Findings | One finding format keyed on CWE, CVE and location, with duplicates removed across tools and runs. Fix snippets, comments and CSV export |
| Risk | Risk is based on CVSS, FIRST EPSS, CISA KEV, asset criticality and exposure. Each site also gets an A to F grade |
| Lifecycle | new, triaged, validated, fixed, retest passed, plus false positive and risk accepted (a reason is required). A fixed finding that comes back reopens on its own. SLA due dates are set per severity |
| Evidence | Files are hashed with SHA-256, stored by content and never changed |
| Compliance | Findings map to control objectives and then to framework requirements (PCI DSS, ISO 27001, SOC 2, ASVS 4.0, SEBI CSCRF, CERT-In and others). An assessor can confirm or change each result with a reason |
| Reports | Technical security testing report, executive summary, compliance evidence pack, OWASP Top 10 view and attestation letter (includes a Safe-to-Host block). Reports go through Submit for QA, QA approve or reject, then Approve and sign |
| Dashboards | Staff metrics at `/dashboard` (open-by-severity, SLA ageing, trend, site grades); per-target grades at `/sites`. Client and auditor roles are sent to the portal |
| Sharing | Read-only share links, a client portal (comment, `client_fix` evidence, retest request) and an auditor view |
| Public verify | Signed reports verify at `/verify/reports/{id}?sig=…` without login; the page embeds a QR of the same URL |
| Library | Per-tenant writeups; seed starters or import JSON/CSV via `POST /api/library/import` |
| SEBI timeline | Staff page `/engagements/{id}/sebi-timeline` maps engagement milestones to SEBI CSCRF security-testing expectations |
| Alerts | Email alerts, certificate expiry warnings and SLA alerts |
| Users | Local users with roles, invites, API keys (with revoke) and optional single sign-on (OIDC) |
| Audit | Append-only, hash-chained audit log with a tamper check |
| Interfaces | Web UI, REST API (OpenAPI at `/docs`) and CLI |

### Control statuses

| Status | Meaning |
| --- | --- |
| `met` | Engagement records show the control (for example, scans were run or a valid permission letter exists), or an assessor confirmed it |
| `no_exceptions` | Testing found nothing against the control. This alone does not prove the control is in place, so an assessor confirms it |
| `partial` | There are open medium findings, or a process is only partly shown |
| `not_met` | There are open critical or high findings, or required evidence is missing |
| `not_assessed` | Outside what this engagement tested |

## Requirements

- Python 3.11 or newer
- Docker, for the in-app scanners that run in containers (ZAP, testssl, Nuclei and others)

## Quick start

Windows (PowerShell), from the repo folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"          # or: pip install -r requirements.txt
python -m attestra.cli init      # create the database
python -m attestra.cli demo      # optional: load sample data
python -m attestra.cli serve --host 127.0.0.1 --port 8000
```

In a second window, start the worker that runs scans:

```powershell
.\.venv\Scripts\Activate.ps1
python -m attestra.cli worker
```

Linux or macOS:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m attestra.cli init
python -m attestra.cli serve        # http://127.0.0.1:8000  (API docs at /docs)
python -m attestra.cli worker       # in a second terminal
```

Then open http://127.0.0.1:8000 and sign in. Staff home routes include `/dashboard` (severity/SLA/trend metrics) and `/sites` (per-target grades). Client and auditor roles use `/portal`.

`python -m attestra.cli` always runs the code in this folder. If the plain `attestra` command says a subcommand does not exist, run `pip install -e .` again or use `python -m attestra.cli`.

## Users and passwords

```bash
python -m attestra.cli user add <username> --role lead --password <password>
python -m attestra.cli user set-password <username>         # asks for the new password
python -m attestra.cli user disable <username>
python -m attestra.cli key list                             # also: key create, key revoke <id>
```

Roles are `admin`, `lead`, `tester`, `reviewer`, `client_viewer` and `auditor`. Passwords must be at least 12 characters long and use at least 4 different characters.

The CLI uses the database in `ATTESTRA_DATA_DIR` (default `./data` in the folder you run it from). Run it from the same folder as the app, or set `ATTESTRA_DATA_DIR`, or the change goes to a different database.

## Common CLI commands

```bash
python -m attestra.cli findings 1                         # findings ranked by risk
python -m attestra.cli --user alice scan 1 2 --tool zap --profile baseline
# scan: engagement id, asset id, --tool (from list_adapters), optional --profile baseline|active|intrusive
# same gate and audit path as the UI; refused scans print status=refused and a reason
python -m attestra.cli --user alice import 1 zap zap-report.json
python -m attestra.cli enrich --kev known_exploited_vulnerabilities.json --epss epss_scores-current.csv
python -m attestra.cli --user alice transition 4 validated
python -m attestra.cli compliance 1 pci_dss_4              # also: asvs_4_0, soc2, …
python -m attestra.cli --user alice report 1 compliance --framework soc2
python -m attestra.cli --user alice report 1 owasp_top10   # OWASP Top 10 2021 view
python -m attestra.cli --user bob submit 7                 # send the draft to QA
python -m attestra.cli --user carol qa-approve 7           # a different person
python -m attestra.cli --user lead sign 7                  # lead signs
python -m attestra.cli verify-report 7
python -m attestra.cli verify-audit
python -m attestra.cli backup --help
```

Run `python -m attestra.cli --help` for the full list.

The KEV JSON comes from CISA (`known_exploited_vulnerabilities.json`). The EPSS CSV comes from FIRST (`epss_scores-current.csv.gz`, unzipped).

## Settings

Settings are read from environment variables. The most used ones are:

| Variable | Purpose |
| --- | --- |
| `ATTESTRA_DATA_DIR` | Folder for the database, evidence, reports and signing key (default `./data`) |
| `ATTESTRA_DATABASE_URL` | Use another database, for example PostgreSQL (`pip install -e ".[postgres]"`). On Postgres, run Alembic to head (migration `0022_auth_web` adds auth-web tables) |
| `ATTESTRA_PUBLIC_URL` | The address users open, used in links, emails and public verify QR URLs |
| `ATTESTRA_SESSION_SECRET` | Secret for sign-in sessions (also used for public report verify HMAC). Set a long random value outside development |
| `ATTESTRA_IMAGE_<TOOL>` | Docker image for a scanner, pinned by digest (for example `ATTESTRA_IMAGE_TESTSSL`, `ATTESTRA_IMAGE_ZAP`). Built-in values are placeholders and must be set before that scanner can run |
| `ATTESTRA_HSTS_PRELOAD_LOOKUP` | Set to `1` to check whether a site is on the HSTS preload list |
| `ATTESTRA_DNS_RESOLVERS` | DNS servers used for the ownership check |
| `ATTESTRA_AUTH_WEB_ENABLED` | Set to `1` / `true` / `yes` to enable authenticated website testing (off by default) |
| `ATTESTRA_CREDENTIAL_FERNET_KEY` | URL-safe base64 32-byte Fernet key for engagement test-account secrets (required when auth-web stores credentials) |
| `ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL` | Dev/tests only: allow a process-local Fernet key when the Fernet key is unset |
| `ATTESTRA_SMTP_*` | Mail server for invites and alerts |
| `ATTESTRA_OIDC_*` | Single sign-on settings |
| `ATTESTRA_AI_*` | Optional AI drafts for report text. Keep the API key in an environment variable, never in a file in the repo |
| `ATTESTRA_STORAGE`, `ATTESTRA_S3_*` | Store evidence in S3 (`pip install -e ".[s3]"`) |
| `ATTESTRA_METRICS_TOKEN` | Token for the `/metrics` endpoint |

Authenticated website testing caps and setup notes: [docs/AUTH_WEB_TESTING.md](docs/AUTH_WEB_TESTING.md).

## Tests

```bash
python -m pytest -q
ruff check .
```

## Project layout

```
attestra/
  importers/          result file parsers (zap, nuclei, trivy, sarif, testssl, burp, nessus and more)
  runner/             permission and ownership checks, and the in-app scanners
  auth_web/           optional authenticated website testing (profiles, crawl, checklist)
  credentials/        Fernet-backed engagement secret store for auth-web
  jobs/               durable scan queue used by the worker
  compliance/         control mapping engine and data (PCI DSS, ISO 27001, SOC 2, ASVS, …)
  library/            findings library + JSON/CSV import
  reports/            report templates, generation, QA and signing
  verify/             public signed-report verification + QR
  users/, auth/       users, roles, sessions, API keys and single sign-on
  share/, alerts/     share links, email alerts and expiry checks
  services.py         business rules shared by the API and CLI (every write is audited)
  models.py           data model
  audit.py            hash-chained audit log
  api.py, web/        REST API and UI (/dashboard, /sites, /portal, …)
  cli.py              command line (includes scan)
migrations/           database upgrades (alembic; 0022_auth_web for auth-web tables)
docs/                 design, security and guides
lat.md/               short notes on how each part works
tests/                tests and sample data
```

## Before production

- **Control library review.** Control references and titles in `attestra/compliance/data/` are paraphrased. Check them against the licensed PCI SSC, ISO and AICPA texts, ideally with a QSA and an ISO lead auditor.
- **Signing.** Reports are signed with a key kept by this install. That proves the report wasn't changed here, but outside parties can't check it. Use certificate-based or Sigstore signatures for that. Public verify URLs use HMAC over `ATTESTRA_SESSION_SECRET`.
- **Storage.** Use S3 Object Lock (compliance mode) for evidence, and a separate encryption key per tenant.
- **Secrets.** Set `ATTESTRA_SESSION_SECRET` and `ATTESTRA_API_KEY_PEPPER`, and keep all keys out of the repo. If auth-web is enabled, set `ATTESTRA_CREDENTIAL_FERNET_KEY` (do not use ephemeral keys outside local/dev).
- **Licensing.** Scanners run from their own Docker images and are not bundled. Review AGPL, GPL and NPSL terms before bundling or embedding any tool.
