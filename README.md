# Attestra

**From findings to signed attestation.**

Attestra turns VAPT results into audit-ready evidence. It imports results from the open-source scanners your testers already run, de-duplicates and risk-ranks them, records human validation, maps every finding to **PCI DSS v4.0.1, ISO/IEC 27001:2022 and SOC 2** controls, and produces reports that are hashed, four-eyes approved and signed.

Attestra does not run scanners or attack anything. Testers run tools under the client's signed authorization and import the result files. Attestra refuses imports for an engagement with no currently valid signed authorization.

Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What v0.1 does

| Area | Capability |
| --- | --- |
| Engagements | Tenants, engagements (VA / PT / VAPT / retest / continuous), test window, target frameworks |
| Authorization gate | Signed authorization (hashed, stored write-once). Imports are blocked without a valid one (ISO A.8.34) |
| Scope | Assets with criticality 1–5, internet/internal exposure, PCI CDE flag |
| Import | OWASP ZAP JSON, Nuclei JSONL, Trivy JSON (vulnerabilities and misconfigurations), any SARIF 2.1 (Semgrep, CodeQL, Checkov, Gitleaks and others) |
| Normalize | One finding schema keyed on CWE / CVE / location. Cross-tool and cross-run de-duplication by fingerprint |
| Prioritize | Risk = CVSS × (1 + EPSS) × KEV × asset criticality × exposure. CISA KEV and FIRST EPSS feeds applied offline |
| Lifecycle | new → triaged → validated → fixed → retest_passed, plus false_positive and risk_accepted (reason required). A fixed finding seen again reopens automatically. SLA due dates (critical 30 days, per PCI 6.3.3) |
| Evidence | Files hashed (SHA-256), content-addressed, write-once |
| Compliance | CWE → control objective → framework requirement crosswalk (hub and spoke). Process controls (scanning, pentest, retest, authorization) derived from engagement records. PCI evaluation is scoped to CDE assets. Assessor confirmation with rationale overrides the proposal |
| Reports | Technical VAPT report, executive summary, per-framework compliance evidence pack. Versioned, SHA-256 hashed, four-eyes approval, signed |
| Audit | Append-only, hash-chained audit log with tamper verification |
| Interfaces | REST API (OpenAPI at `/docs`), web dashboard, CLI |

### Control statuses

| Status | Meaning |
| --- | --- |
| `met` | A process control is evidenced by engagement records (for example, scans imported or a valid authorization), or an assessor confirmed it |
| `no_exceptions` | Testing found nothing against the control. This does not by itself prove the control is in place, so the assessor confirms it |
| `partial` | Open medium findings, or a process is only partly evidenced |
| `not_met` | Open critical or high findings, or required evidence is missing |
| `not_assessed` | Outside what this engagement tested |

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/attestra demo        # loads a synthetic engagement from tests/fixtures
.venv/bin/attestra serve       # http://127.0.0.1:8000  (API docs at /docs)
```

### CLI

```bash
attestra findings 1                         # findings ranked by risk
attestra --actor arjun import 1 zap zap-report.json
attestra enrich --kev known_exploited_vulnerabilities.json --epss epss_scores-current.csv
attestra --actor arjun transition 4 validated
attestra compliance 1 pci_dss_4
attestra --actor arjun report 1 compliance --framework soc2
attestra --actor meera approve 7            # must be a different person (four-eyes)
attestra verify-report 7
attestra verify-audit
```

KEV JSON comes from CISA (`known_exploited_vulnerabilities.json`); the EPSS CSV comes from FIRST (`epss_scores-current.csv.gz`, unzipped).

### API

Write calls need an `X-Attestra-Actor` header. This is a placeholder until SSO is added; see the roadmap below.

```bash
curl -X POST localhost:8000/api/engagements -H 'X-Attestra-Actor: priya' -H 'Content-Type: application/json' \
  -d '{"tenant":"Acme","name":"Q4 VAPT","type":"vapt","frameworks":["pci_dss_4","soc2"]}'
curl -X POST localhost:8000/api/engagements/1/authorizations -H 'X-Attestra-Actor: priya' \
  -F document=@signed-roe.pdf -F signer="CISO, Acme" -F signed_on=2026-10-01 -F expires_on=2026-12-31
curl -X POST localhost:8000/api/engagements/1/imports -H 'X-Attestra-Actor: arjun' -F tool=zap -F file=@zap.json
curl 'localhost:8000/api/engagements/1/compliance?framework=pci_dss_4'
```

## Project layout

```
attestra/
  importers/          zap, nuclei, trivy, sarif -> NormalizedFinding
  compliance/         engine + data/controls.yaml (objectives -> PCI/ISO/SOC2) + data/cwe_map.yaml
  reports/            Jinja templates, generation, four-eyes approval, signing
  services.py         business rules shared by API and CLI (every write is audited)
  models.py           data model (engagement, authorization, asset, finding, evidence, control, report, audit)
  audit.py            hash-chained audit log
  scoring.py          risk score and SLA
  fingerprint.py      de-duplication keys
  api.py, web/        REST API and dashboard
  cli.py              command line
tests/                25 tests + synthetic fixtures
```

Data (SQLite database, evidence, imports, reports, signing key) lives in `./data` by default. Set `ATTESTRA_DATA_DIR` and `ATTESTRA_DATABASE_URL` (for example `postgresql+psycopg://...`, after `pip install -e ".[postgres]"`) to change this.

## Before production

- **Mapping library review.** Control references and titles in `attestra/compliance/data/controls.yaml` are paraphrased and must be verified against the licensed PCI SSC, ISO and AICPA texts. Have a QSA and an ISO lead auditor review the library.
- **Identity.** Replace the `X-Attestra-Actor` header with Keycloak OIDC and role-based access (tester, reviewer, assessor, client viewer, auditor read-only).
- **Signing.** v0.1 uses HMAC-SHA256 with a per-install key. That proves integrity within this instance, but third parties can't verify it. Move to Sigstore cosign or X.509 document signatures.
- **Storage.** Use S3 Object Lock (compliance mode) for evidence, and per-tenant KMS keys.
- **Licensing.** Attestra only reads scanner output files, so no scanner code is bundled. Review AGPL, GPL and NPSL obligations before bundling or embedding any tool.

## Roadmap

- **v0.2:** DefectDojo sync (push and pull findings), Jira and GitHub tickets, OSCAL Assessment Results and POA&M export, DOCX/PDF output
- **v0.3:** CISO Assistant integration for the full framework libraries, SOC 2 period population export, a tester workbench UI with WSTG and ASVS checklists
- **v0.4:** CERT-In, RBI, SEBI CSCRF, HIPAA and NIST CSF 2.0 mapping packs; VPAT (WCAG 2.2) module using axe-core results
