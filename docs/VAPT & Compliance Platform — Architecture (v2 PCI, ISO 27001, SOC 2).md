# VAPT & Compliance Platform — Architecture (v2: PCI, ISO 27001, SOC 2)

Oct 13, 2026 · @Ravi Linganuri

## Executive summary

We should build the layer that sits around existing open-source scanners: orchestration, evidence and compliance reporting. We should not build our own scanners. Mature open-source tools already find vulnerabilities well. What is missing is a single platform that does the following:

- Limits every test to assets the client has authorized.
- Turns raw output from many scanners into one set of deduplicated, risk-ranked findings.
- Gives human testers a place to validate those findings with evidence.
- Maps confirmed findings to PCI DSS 4.0.1, ISO/IEC 27001:2022 and SOC 2.
- Produces signed reports that an auditor or QSA will accept.

**Product thesis:** cut the time from engagement kick-off to a signed, audit-ready report from weeks to days. Every claim in a report should be traceable back to raw evidence.

| Term | What it is | Who or what does it | Platform role |
| --- | --- | --- | --- |
| VA: Vulnerability Assessment | Breadth-first automated scan for known CVEs, missing patches and misconfigurations | Scanners | Orchestrate, normalize, deduplicate, score |
| PT: Penetration Testing | Depth-first, human-led validation of whether a weakness is really exploitable | Certified testers | Workbench, checklists, evidence capture. The platform never exploits anything autonomously |
| VAPT | VA for coverage, then PT to validate impact | Both | One engagement: scope, scan, triage, validate, report, retest |
| OWASP | Open standards: Top 10, ASVS, WSTG, MASVS | Reference | Test methodology and finding taxonomy |
| VPAT (accessibility) | Accessibility conformance report against WCAG 2.2, Section 508 and EN 301 549 | Accessibility auditors | A later module that reuses the same scan, validate, map and report pipeline |

**Scope of this document:** architecture for v1 (core VAPT) and the v2 compliance module (PCI DSS, ISO 27001 and SOC 2). It also covers the open-source components each layer builds on. Licenses below are from memory and must be verified before any commercial use.

## Open-source landscape

Use DefectDojo as the findings core and CISO Assistant as the compliance and GRC core. Plug best-in-class scanners in behind adapters. Each pick below is the strongest open-source option for its layer as of 2026. Rows marked **License watch** use AGPL, GPL or a custom license. Run those as separate services, or get a commercial license, so the SaaS code stays clean.

### Core platforms (fork or embed)

| Layer | Pick | License | How we use it |
| --- | --- | --- | --- |
| Findings hub | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | BSD-3 | System of record for findings. Parsers for 150+ tools, deduplication, SLAs, REST API. Fork it or run it as an upstream service |
| GRC and compliance | [CISO Assistant](https://github.com/intuitem/ciso-assistant-community) | AGPL-3.0 (license watch) | Ships 80+ frameworks (PCI DSS 4, ISO 27001:2022, SOC 2, NIST CSF, DORA and more), cross-framework mappings, control assessments and evidence. Becomes the v2 compliance engine |
| Pentest reporting | [SysReptor](https://github.com/Syslifters/sysreptor) | Custom community license (license watch) | Markdown-to-PDF pentest reports and finding templates. Alternatives: [PwnDoc](https://github.com/pwndoc/pwndoc) (MIT) and [Dradis CE](https://github.com/dradis/dradis-ce) (GPL-2.0) |
| Collaborative pentest workspace | [Faraday](https://github.com/infobyte/faraday) | GPL-3.0 (license watch) | Reference for the multi-user tester workbench. Borrow its ideas rather than embed it |
| SBOM and dependency risk | [OWASP Dependency-Track](https://github.com/DependencyTrack/dependency-track) | Apache-2.0 | Ingests CycloneDX SBOMs and tracks component risk continuously |
| Control catalogs | [NIST OSCAL](https://github.com/usnistgov/OSCAL), [Secure Controls Framework](https://securecontrolsframework.com) | Public domain / CC | Machine-readable control catalogs and a crosswalk hub between frameworks |

### Scanners (behind adapters, run in isolated runners)

| Coverage | Pick | License | Notes |
| --- | --- | --- | --- |
| Web app DAST (OWASP Top 10) | [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Apache-2.0 | Automation Framework YAML plans, authenticated scans, API scans (OpenAPI, GraphQL) |
| Template-based checks | [Nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Large community template library. Pin and review the templates we enable |
| Network and host VA | [Greenbone / OpenVAS](https://github.com/greenbone) | AGPL / GPL (license watch) | Authenticated host checks and CVE coverage. Run as a separate service |
| Discovery | [Nmap](https://nmap.org) | NPSL (license watch) | Embedding Nmap in a commercial product needs the Nmap OEM license. Alternative: [naabu](https://github.com/projectdiscovery/naabu) (MIT) |
| SAST | [Semgrep CE](https://github.com/semgrep/semgrep) | LGPL-2.1 | Community rules plus our own rule packs |
| SCA, containers, IaC | [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype) + [Syft](https://github.com/anchore/syft) | Apache-2.0 | Image, filesystem and SBOM scanning |
| IaC policy | [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Terraform, CloudFormation, Kubernetes manifests |
| Cloud posture | [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | AWS, Azure, GCP and Kubernetes checks, with built-in compliance mappings for PCI, ISO and SOC 2 |
| Kubernetes benchmarks | [kube-bench](https://github.com/aquasecurity/kube-bench) | Apache-2.0 | CIS Kubernetes Benchmark |
| OS hardening | [OpenSCAP](https://github.com/OpenSCAP/openscap), [Lynis](https://github.com/CISOfy/lynis) | LGPL / GPL-3.0 | CIS and STIG configuration baselines |
| TLS | [testssl.sh](https://github.com/drwetter/testssl.sh) | GPL-2.0 | Cipher and protocol checks for PCI DSS 4.2.1 |
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Hardcoded credentials in repositories |
| Mobile (OWASP MASVS) | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | GPL-3.0 (license watch) | Static analysis of Android and iOS apps |
| Accessibility (VPAT, later) | [axe-core](https://github.com/dequelabs/axe-core), [Pa11y](https://github.com/pa11y/pa11y) | MPL-2.0 / LGPL-3.0 | WCAG 2.2 automated checks |

### Prioritization data (free feeds)

- [NVD](https://nvd.nist.gov) / [CVE](https://www.cve.org): vulnerability records and CVSS scores.
- [FIRST EPSS](https://www.first.org/epss/): the probability that a vulnerability is exploited in the next 30 days.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): vulnerabilities known to be exploited in the wild.
- [MITRE CWE](https://cwe.mitre.org): the weakness taxonomy. This is the join key to OWASP Top 10, ASVS and compliance controls.
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) and [WSTG](https://owasp.org/www-project-web-security-testing-guide/): verification requirements and the manual test checklist.

## Target architecture

The platform has three parts. A control plane holds state and decisions. A runner plane executes scans in isolated, egress-locked containers. An evidence layer is write-once. Scanners never talk to the control plane directly: an adapter converts their output into the common finding schema.

&#91;embedded content: target architecture · 6 control-plane services, 8 scanner adapters\]

The numbered boxes follow one engagement: scope (1) gates the orchestrator (2), runners scan, findings (3) go to human validation (4), then compliance mapping (5) and signed reports (6). The highlighted box is the scope gate, which no job can bypass. Each scanner is a plugin, so adding one means writing a parser and a run profile, not changing the core.

## End-to-end VAPT engagement flow

One engagement runs as a single resumable Temporal workflow, from signed authorization to closure letter. Automation covers breadth (VA). People decide exploitability, control status and sign-off.

&#91;embedded content: VAPT engagement flow · 8 steps, 1 retest loop\]

If a tester marks a finding not exploitable at step 4, it closes as a false positive with a reason. If QA rejects a draft at step 6, it goes back to the tester. Continuous mode reruns steps 2 and 3 on a schedule, for PCI quarterly scans and SOC 2 Type II periods, and through CI/CD gates.

## Common finding schema and data model

One normalized finding schema, keyed on CWE and asset, is what makes the platform work. Every scanner adapter writes to it. Every report and compliance view reads from it. Base the schema on SARIF 2.1 and DefectDojo's Finding model. Extend it with the fields below.

### Core entities

| Entity | Key fields | Notes |
| --- | --- | --- |
| Tenant | id, name, data\_region, plan | Hard isolation boundary for data, runners and encryption keys |
| Engagement | id, tenant\_id, type (VA / PT / VAPT / retest / continuous), frameworks\[\], window\_start, window\_end, status | One audit cycle or test |
| Authorization | engagement\_id, signed\_doc\_uri, sha256, signer, rules\_of\_engagement, expires\_at | No valid authorization means no scan. The scope gate enforces this |
| Asset | id, type (url / ip / cidr / repo / image / cloud\_account / mobile\_app), identifier, criticality (1–5), in\_cde (bool), owner, tags | `in_cde` marks the PCI cardholder data environment and drives PCI scope |
| ScopeRule | engagement\_id, asset\_id or pattern, allow / deny, rate\_limit | Allow-list, evaluated by OPA before any job is dispatched |
| ScanRun | id, engagement\_id, tool, tool\_version, profile, started\_at, ended\_at, raw\_artifact\_uri, raw\_sha256 | Raw output is stored immutably for the evidence chain |
| Finding | see below | Deduplicated across runs and tools |
| Evidence | id, finding\_id or control\_id, kind (screenshot / http\_pair / log / file / attestation), uri, sha256, captured\_by, captured\_at | Hashed and timestamped |
| Control | id, framework, ref (for example `PCI 11.3.1`, `ISO A.8.8`, `SOC2 CC7.1`), text, test\_procedure | Loaded from CISO Assistant libraries or OSCAL catalogs |
| Mapping | source (cwe / tool\_rule / scf\_id), target\_control\_id, strength (full / partial), rationale | The crosswalk graph |
| ControlAssessment | engagement\_id, control\_id, status (met / partial / not met / not applicable), evidence\_ids\[\], assessor, reviewed\_by | Generated from findings, confirmed by a person |
| Report | id, engagement\_id, type, version, template\_id, sha256, signature, approved\_by, published\_at | Immutable once signed |

### Finding fields

- **Identity:** `fingerprint` is a hash of asset, CWE, location, parameter and normalized title. It drives deduplication across tools and runs.
- **Classification:** `cwe`, `cve[]`, `owasp_top10` (2021 / 2025), `asvs_ref[]`, `wstg_ref[]`, `tool_rule_id`.
- **Severity:** `cvss_v4_vector` and `cvss_score`, `epss`, `kev` (bool), `asset_criticality`, `exposure` (internet / internal / CDE).
- **Risk:** `risk_score` is a computed priority (formula below). It ranks findings. It does not replace CVSS in reports.
- **Lifecycle:** `status` moves through new, triaged, validated, risk\_accepted / false\_positive, fixed, then retest\_passed. Every transition keeps actor, timestamp and reason.
- **Validation:** `validated_by` (tester), `validation_method` (manual / automated-confirmed), `evidence_ids[]`.
- **Remediation:** `recommendation`, `sla_due` (from policy, for example critical in 30 days per PCI 6.3.3), `ticket_ref`.
- **Compliance:** `control_ids[]`, derived through Mapping and never typed by hand.

### Risk score (prioritization only)

```latex
\text{risk} = \text{CVSS}_{v4} \times (1 + \text{EPSS}) \times w_{\text{KEV}} \times w_{\text{asset}} \times w_{\text{exposure}}
```

Starting weights: w\_KEV = 1.5 if the CVE is on the KEV list, otherwise 1.0. w\_asset = 0.6 to 1.4 by criticality. w\_exposure = 1.3 for internet-facing or CDE assets. Tune these per tenant.

### Interchange formats

- **In:** native tool output, SARIF, CycloneDX, and DefectDojo parser formats.
- **Out:** OSCAL Assessment Results and POA&M, SARIF, CSV, the Jira and GitHub APIs, and DOCX/PDF reports.

## v2 compliance module: PCI DSS, ISO 27001, SOC 2

v2 adds a mapping layer between findings and controls. Each confirmed finding links to every control it affects, in every framework, through one crosswalk. A single VAPT engagement can then produce a PCI report, an ISO 27001 evidence pack and a SOC 2 evidence pack without retesting.

### How the mapping works

1. **Findings to weaknesses:** each finding carries a CWE, assigned by the scanner adapter or by the tester.
2. **Weaknesses to a hub:** the CWE maps to a hub control. Use Secure Controls Framework (SCF) IDs or CISO Assistant's reference controls. This avoids building N×N mappings between frameworks.
3. **Hub to frameworks:** the hub control maps to PCI DSS, ISO 27001 and SOC 2 requirements. CISO Assistant already ships many of these mapping libraries.
4. **Process controls:** controls about the testing process itself (for example "pentest performed annually" or "internal scans run quarterly") are met by the engagement record and its evidence. They are not met by findings.
5. **Status roll-up:** the system proposes a control status. Critical or high open findings on a mapped control make it **not met**; medium findings make it **partial**. The process evidence then decides whether the control can be **met**. A named assessor confirms every status. The platform proposes; a person decides.

### Crosswalk: where VAPT evidence satisfies each framework

| Control objective | PCI DSS 4.0.1 | ISO/IEC 27001:2022 Annex A | SOC 2 (TSC 2017, rev. 2022) | Platform evidence produced |
| --- | --- | --- | --- | --- |
| Find and rank vulnerabilities | 6.3.1 | A.8.8 Management of technical vulnerabilities | CC7.1 | Ranked findings register with CVSS, EPSS and KEV |
| Patch on time | 6.3.3 (critical within 1 month) | A.8.8 | CC7.1, CC8.1 | SLA tracking, ageing report, retest-passed records |
| Internal vulnerability scans | 11.3.1 (quarterly), 11.3.1.1 (other vulnerabilities per targeted risk analysis), 11.3.1.2 (authenticated) | A.8.8 | CC7.1 | Scheduled scan runs with raw hashed artifacts, auth-success proof, rescan to clean |
| External vulnerability scans | 11.3.2 (quarterly, by a PCI SSC Approved Scanning Vendor) | A.8.8 | CC7.1 | Pre-ASV readiness only, plus import of the ASV report. We cannot issue ASV results unless we become an ASV |
| Penetration testing | 11.4.1 (methodology), 11.4.2 (internal), 11.4.3 (external), annually and after significant change | A.8.29 Security testing in development and acceptance; A.8.8 | CC4.1 (separate evaluations), CC7.1 | Methodology document, WSTG checklist, validated findings, tester qualifications |
| Fix and retest pentest findings | 11.4.4 | A.8.8; clause 10.2 corrective action | CC4.2, CC7.4 | Retest report and closure letter |
| Segmentation testing | 11.4.5 (every 12 months), 11.4.6 (service providers, every 6 months) | A.8.22 Segregation of networks | CC6.6 | Segmentation test results per CDE boundary |
| Secure coding and web attacks | 6.2.4, 6.4.1, 6.4.2 (automated web attack protection) | A.8.28 Secure coding; A.8.26 Application security requirements | CC8.1 | SAST and DAST findings mapped to OWASP Top 10 and ASVS |
| Secure configuration | 2.2.x | A.8.9 Configuration management | CC6.8, CC7.1 | CIS benchmark results (Prowler, kube-bench, OpenSCAP) |
| Strong cryptography in transit | 4.2.1 | A.8.24 Use of cryptography | CC6.7 | TLS scan results |
| Third-party component risk | 6.3.2 (software inventory) | A.8.28, A.5.21 ICT supply chain | CC9.2 | SBOM and Dependency-Track risk |
| Protect systems during testing | Rules of engagement (supports 11.4.1) | A.8.34 Protection of information systems during audit testing | CC6.1 | Signed authorization, scope gate logs, test windows |
| Risk-based decisions | 12.3.1 (targeted risk analysis) | Clause 6.1.2 risk assessment, 8.2 | CC3.2 | Risk acceptances with owner, expiry and rationale |

Control references above are from the published standards as I recall them. Verify the exact wording against the PCI SSC, ISO and AICPA source texts before shipping the mapping library.

### Framework-specific product features

**PCI DSS 4.0.1**

- A CDE scope flag on every asset. Segmentation tests are tied to each CDE boundary.
- A quarterly scan calendar per requirement 11.3, with automatic "rescan until clean" tracking.
- A pentest methodology template that satisfies 11.4.1, covering industry-accepted approaches, application and network layers, and segmentation.
- ASV boundary: the platform runs external pre-scans and imports the ASV attestation. It does not replace the ASV.
- Output: an evidence binder indexed by requirement for the QSA, which supports the Report on Compliance (ROC) or Self-Assessment Questionnaire (SAQ).

**ISO/IEC 27001:2022**

- A Statement of Applicability (SoA) view showing which Annex A controls VAPT evidence supports.
- Nonconformities and corrective actions (clause 10.2) linked to findings and retests.
- Internal audit support (clause 9.2): an evidence pack per control, with sampling.
- Output: an Annex A evidence register and a vulnerability management records pack for the certification body.

**SOC 2 (Type I and Type II)**

- Type II needs evidence of operating effectiveness over a period. Continuous scanning over the period provides it, not a single test.
- A population and sample export for auditors: every scan run, finding and remediation in the period, with timestamps.
- Output: a CC-series evidence pack plus a pentest letter of attestation for customer trust pages.

### Phase v2.1 framework packs (same engine)

CERT-In VAPT guidelines, the RBI cyber security framework, SEBI CSCRF, HIPAA Security Rule, NIST CSF 2.0, DORA, and EU CRA. Each is a new mapping library, with no new code.

## Reporting and evidence

Reports are generated from the finding and control data, reviewed by a person, then signed and frozen. Any sentence in a report must trace back to a hashed raw artifact in two clicks.

### Report catalog

| Report | Audience | Contents | Trigger |
| --- | --- | --- | --- |
| Executive summary | Board, CISO | Risk posture, top 5 risks, trend against the last cycle, framework readiness percentage | Every engagement |
| Technical VAPT report | Engineering | Scope, methodology, each finding with CVSS v4, evidence, reproduction notes and remediation | Every engagement |
| Retest / closure letter | Auditor, customer | Status of every original finding after retest, signed | After retest |
| Letter of attestation | Customers, trust page | Test dates, scope summary, no open critical or high findings. No vulnerability detail | On request |
| PCI DSS evidence binder | QSA | Index by requirement (6.3, 11.3, 11.4) with scan runs, the pentest report, segmentation results and the ASV import | Quarterly and annually |
| ISO 27001 evidence register | Certification body | Annex A controls with evidence, nonconformities and corrective actions | Audit cycle |
| SOC 2 period pack | CPA firm | Population of scans, findings and remediations in the period, plus samples | Type II period end |
| OSCAL export | GRC tools, regulators | Assessment Results and POA&M as JSON | On demand |
| CERT-In format report | Indian regulated entities | Report in the CERT-In empanelled auditor format | v2.1 |

### Generation pipeline

1. Report templates are DOCX files with Jinja placeholders, rendered with [docxtpl](https://github.com/elapouya/python-docx-template). Branded PDFs come from [Gotenberg](https://github.com/gotenberg/gotenberg), or from SysReptor if we adopt it.
2. An LLM drafts the executive narrative and finding write-ups from structured data. The draft is marked AI-generated until a reviewer edits or approves it.
3. A four-eyes workflow: the tester submits, the QA reviewer approves, and the engagement lead signs.
4. On signing, the platform freezes the version, records a SHA-256 hash, and signs it with [Sigstore cosign](https://github.com/sigstore/cosign) or an X.509 document signature. The report is then published to the client portal.

### Evidence chain

- Raw scanner output, screenshots and HTTP request/response pairs go to write-once object storage (S3 Object Lock in compliance mode), with a hash computed at capture.
- An append-only audit log records who did what and when, for every scan, status change, approval and download. It is exportable for auditors.
- Retention is set per framework and tenant. The common default is at least 1 year of history for PCI DSS 10.5.1, and longer where contracts require it.
- Sensitive data captured during testing (card numbers, credentials, PII) is masked at capture. Raw evidence is encrypted with keys per tenant (KMS or Vault).

## Security, safety and legal guardrails

A testing platform that can touch systems outside its authorization is a legal liability. Scope enforcement is therefore a core feature. These guardrails are also part of what we sell: auditors check for them under ISO A.8.34 and PCI 11.4.1.

- **No authorization, no scan.** Every job dispatch is checked by an [OPA](https://github.com/open-policy-agent/opa) policy. The check confirms a valid signed authorization, that the target is on the allow-list, that the time is inside the test window, and that rate limits are set. Ownership of a target is verified first, using a DNS TXT record, an HTTP file or cloud account linking.
- **Kill switch.** The client and the engagement lead can each halt all runners for an engagement instantly. The halt is logged.
- **Safe-by-default profiles.** Intrusive or state-changing checks are off unless the rules of engagement explicitly allow them. Production targets get conservative rate limits.
- **Humans validate exploitability.** The platform runs vulnerability scans and records human validation. It does not run autonomous exploitation chains. AI features are limited to triage, write-up drafting and mapping suggestions.
- **Egress-controlled runners.** Each scan runs in an ephemeral, isolated container or pod. Network policy restricts it to scoped targets, and each runner has its own egress IP that clients can allow-list.
- **Tenant isolation.** Each tenant gets separate storage prefixes, encryption keys and runner pools. Large clients can get dedicated runners or on-premises agents.
- **Platform security.** SSO and MFA (via [Keycloak](https://github.com/keycloak/keycloak)), role-based access (tester, reviewer, client viewer, auditor read-only), secrets in [Vault](https://github.com/hashicorp/vault) or [OpenBao](https://github.com/openbao/openbao), and annual third-party pentests of the platform itself. Target our own SOC 2 Type II and ISO 27001 by year 2.
- **Legal pack.** A master services agreement with a testing authorization clause, a rules-of-engagement template, a data processing agreement, tester NDAs, and professional indemnity insurance. India: align with the IT Act 2000 and the DPDP Act 2023 for data handling. Pursue CERT-In empanelment if we deliver regulated audits ourselves.

## Tech stack, deployment and roadmap

Use Python for the control plane, because DefectDojo, CISO Assistant and most scanner parsers are Python and Django. Use Go only for the runner agent. Deploy on Kubernetes so the same build ships as multi-tenant SaaS or as a single-tenant on-premises install. Banks and regulated clients will ask for on-premises.

| Concern | Choice | Why |
| --- | --- | --- |
| API and services | Python 3.12, FastAPI, with Django for the DefectDojo and CISO Assistant cores | Reuses both open-source codebases directly |
| Workflow orchestration | [Temporal](https://github.com/temporalio/temporal) (MIT) | Long-running, resumable engagement workflows with retries and human-approval steps |
| Job queue and runners | Kubernetes Jobs, plus a Go runner agent for on-premises networks (outbound-only mTLS) | Isolation, autoscaling, reaches internal networks without opening inbound ports |
| Policy | OPA / Rego | Scope gate and access rules as code, testable |
| Database | PostgreSQL 16, with row-level security per tenant | Relational findings and control graph |
| Search and analytics | OpenSearch (Apache-2.0) | Full-text search over findings and evidence, trend dashboards |
| Object storage | S3 with Object Lock (cloud), or [SeaweedFS](https://github.com/seaweedfs/seaweedfs) (Apache-2.0) on-premises | WORM evidence. Avoids AGPL MinIO in the shipped product |
| Identity | Keycloak (SSO, SAML, OIDC, MFA) | Enterprise SSO is required by audit customers |
| Secrets and keys | Vault / OpenBao, cloud KMS | Per-tenant encryption |
| Frontend | React + TypeScript, shadcn/ui | Tester workbench, client portal, auditor view |
| Reports | docxtpl, Gotenberg, cosign | Editable DOCX plus signed PDF |
| AI assist | Claude (Opus 5.5 for drafting, Haiku 5.5 for bulk triage) via the API, with no client data used for training | Write-ups, deduplication hints, control-mapping suggestions |
| Observability | OpenTelemetry, Prometheus, Grafana, Loki | Platform SLOs and runner health |
| CI/CD integration | GitHub Actions, GitLab CI, Jenkins plugins | Shift-left gates on SAST, SCA and DAST |

### Roadmap

&#91;embedded content: roadmap · 4 phases, 3 gates\]

These are proposed durations for a team of 4 to 6 engineers plus one compliance lead. v2 is the commercial wedge: it turns one VAPT engagement into evidence for PCI, ISO and SOC 2 at once.

## Risks, open questions and next steps

The largest risks are licensing, mapping accuracy and positioning, not technology. All three need decisions before the build starts.

| Risk | Impact | Mitigation |
| --- | --- | --- |
| AGPL or GPL components (CISO Assistant, OpenVAS, Faraday, MobSF) in a SaaS | Obligation to release source code, or a licensing dispute | Run them as unmodified, separate services. Or buy commercial licenses: CISO Assistant and Greenbone both sell them. Have counsel review before v2 |
| Nmap NPSL | Embedding Nmap in a commercial product needs an OEM license | Use naabu (MIT) for discovery, or buy the Nmap OEM license |
| Wrong control mappings | An auditor rejects the evidence, and customers lose trust | Every mapping carries a rationale and strength. Have a QSA or ISO lead auditor review the mapping library. Assessors confirm all control statuses |
| Scanner false positives | Noise erodes trust in reports | Human validation step. Per-tenant suppression rules. Track the false-positive rate per tool and rule |
| Scope breach (testing an unauthorized asset) | Legal liability | OPA scope gate, ownership verification, kill switch, insurance |
| Positioning against commercial tools (Tenable, Qualys, Rapid7, Vanta, Drata) | Hard to differentiate | Position as the VAPT-to-audit bridge: services firms and regulated mid-market companies in India and APAC first, where CERT-In and RBI formats matter |

### Open questions

- Business model: a platform sold to VAPT services firms, a managed VAPT service we deliver ourselves, or both?
- Fork DefectDojo, or run it upstream behind our API? Forking gives control; running upstream keeps merges cheap.
- Adopt SysReptor for reporting, or build reports on docxtpl from the start?
- Do we pursue CERT-In empanelment or PCI ASV status ourselves, or partner?
- Where is data hosted? India-only for regulated BFSI clients?

### Next steps

- [ ] Legal review of AGPL, GPL and NPSL usage in the proposed SaaS topology
- [ ] Proof of concept: ZAP + Nuclei + Trivy into DefectDojo, with the OPA scope gate (2 weeks)
- [ ] Stand up CISO Assistant and load the PCI DSS 4.0.1, ISO 27001:2022 and SOC 2 libraries. Test mapping a sample findings set
- [ ] Draft the finding schema (JSON Schema) and the CWE-to-control mapping seed
- [ ] Interview 5 VAPT firms and 5 compliance leads to validate turnaround and report-format pain points
- [ ] Write the rules-of-engagement and authorization templates
