# Scanner Integration Audit

Evidence-based inventory of Attestra scanner adapters, importers, Docker image pins, and worker invoke paths. **No application code was changed; no scanners were installed.** Inspected 2026-11-10 against `C:\Github\attestra`.

**Policy reminder:** Automated VAPT must remain **disabled by default** (`ATTESTRA_AUTOMATED_VAPT_ENABLED` unset/false in `attestra/config.py`). Operator `.env` overrides are local choices, not product defaults.

## Sources inspected

| Area | Path / command |
| --- | --- |
| Adapters | `attestra/runner/scanners/**` (`registry.py`, `base.py`, per-tool modules, `http_service.py`) |
| Importers | `attestra/importers/**` (`PARSERS` in `__init__.py`) |
| Image env | `attestra/config.py` (`_PLACEHOLDER_IMAGES` / `SCANNER_IMAGES`), `.env.example`, `SETUP_GUIDE.md`, `README.md` |
| Worker invoke | `attestra/jobs/durable.py#run_one_job`, `attestra/runner/gate.py` |
| Deploy | `Dockerfile`, `deploy/README.md`, `deploy/helm/attestra/values.yaml`, `deploy/k8s/scanner-job.yaml` |
| Licences | `docs/LICENSES.md` |
| Knowledge graph | `lat search "scanner adapters docker images"` → `lat.md/runner.md`, `lat.md/import-pipeline.md` |
| Integrations | `attestra/integrations/` (tickets/GRC only; **no** scanner connectors) |

## How runs work (shared)

1. Queue via CLI/UI → durable job → `get_adapter(run.tool)` → `adapter.scan(...)`.
2. Prefer Docker when `ATTESTRA_IMAGE_<TOOL>` is a **non-placeholder** `@sha256:` digest **and** `docker` is on PATH; else local binary via `shutil.which`.
3. Report must exist and parse via `importers.parse(import_tool, raw)` (`ScannerAdapter.validate_report`). Non-zero exit with a valid report is success (ZAP WARN/FAIL, Semgrep findings).
4. Timeouts: `ATTESTRA_SCANNER_TIMEOUT_<TOOL>` else `max(default_timeout_s, ATTESTRA_SCANNER_TIMEOUT_S)` (default 600s). ZAP/Nuclei default 1800s.
5. On timeout/cancel: process tree killed; Docker container `docker rm -f` if named `attestra-*`.
6. App image (`Dockerfile`) does **not** bundle scanners. Helm has an **example** scanner Job; worker → Kubernetes Job creation is **not implemented** (`deploy/README.md`).

**Image keys in config today:** `zap`, `trivy`, `nuclei`, `semgrep`, `testssl`, `naabu`, `gitleaks`, `checkov`. Defaults are all-zero digest placeholders (`image_is_placeholder` → Docker path refused until operator pins a real digest).

**`.env.example` gap:** does not document `ATTESTRA_IMAGE_*` (only worker concurrency mentions Nuclei). Setup/README do.

---

## Per-tool status

Legend: **Y** = yes / implemented · **N** = no · **Partial** = stub or incomplete · **Import-only** = parser, no runner · **N/A** = not applicable.

### OWASP ZAP

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `attestra/importers/zap.py` → key `zap` |
| Runner adapter? | Y | `ZapAdapter` in `runner/scanners/zap.py`; registry `zap` |
| Executable available? | N (by design) | `available()` = Docker + configured image only |
| Docker image required? | Y | `image_key=zap`; `ATTESTRA_IMAGE_ZAP` |
| Configured? | Placeholder by default | Real pin required; SETUP_GUIDE documents it |
| Worker can invoke? | Y | `durable.py` + scope quarantine; auth via `auth_web` when enabled |
| Expected output? | `zap-report.json` | Traditional-json (`-J`); mount `/zap/wrk` |
| Import path? | Auto after scan + manual upload | `import_tool=zap` |
| Normalized findings? | Y | Alerts → `NormalizedFinding`; confidence-0 skipped |
| Errors / timeouts? | Y | 1800s default; quarantine out-of-scope sites; tool log `zap-output.log` |
| Licence? | Apache-2.0 | `docs/LICENSES.md` |
| Scope restriction? | Y | Pinned host `--add-host`; `quarantine_if_out_of_scope`; URL tools only |

### Nuclei

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/nuclei.py` |
| Runner adapter? | Y | `NucleiAdapter`; registry `nuclei` |
| Executable available? | Local **or** Docker | `which("nuclei")` or image |
| Docker image required? | Preferred | `ATTESTRA_IMAGE_NUCLEI`; template cache under `SCANNER_CACHE_DIR` |
| Configured? | Placeholder by default | |
| Worker can invoke? | Y | Crawl URL list; auth `-sf` mount; intrusive gated |
| Expected output? | `nuclei-out.jsonl` | `-jsonl -o`; empty OK (`empty_report_ok`) |
| Import path? | Auto + upload | |
| Normalized findings? | Y | CVE/CVSS/evidence refs |
| Errors / timeouts? | Y | 1800s; stderr log; fatal-empty checks |
| Licence? | MIT | |
| Scope restriction? | Y | Pinned IP add-host; same-host URL list; no Interactsh (`-ni`); baseline excludes intrusive tags |

### Trivy

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/trivy.py` |
| Runner adapter? | Y | `TrivyAdapter` |
| Executable available? | Local **or** Docker | `which("trivy")` |
| Docker image required? | Optional | `ATTESTRA_IMAGE_TRIVY` |
| Configured? | Placeholder by default | |
| Worker can invoke? | Y | Asset kinds `repo`, `image` |
| Expected output? | `<name>-out.json` | `--format json` |
| Import path? | Auto + upload | |
| Normalized findings? | Y | Vulns + misconfigs (e.g. DS002 → CWE-16) |
| Errors / timeouts? | Y | Shared timeout / report validation |
| Licence? | Apache-2.0 | DB terms operator-side |
| Scope restriction? | Partial | Exact image match in authorization; fs path must exist on worker |

### Semgrep

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Via SARIF | Adapter `import_tool=sarif` → `importers/sarif.py` |
| Runner adapter? | Y | `SemgrepAdapter` |
| Executable available? | Local **or** Docker | `which("semgrep")` |
| Docker image required? | Optional | `ATTESTRA_IMAGE_SEMGREP` |
| Configured? | Placeholder by default | |
| Worker can invoke? | Y | Asset kind `repo` |
| Expected output? | `semgrep-out.sarif` | `--sarif`; rules `p/default` |
| Import path? | Auto as `sarif` + generic SARIF upload | |
| Normalized findings? | Y | SARIF 2.1 |
| Errors / timeouts? | Y | Non-zero on findings still valid |
| Licence? | LGPL-2.1 engine; Rules License for registry | SaaS caution in LICENSES.md |
| Scope restriction? | Path/repo only | |

### Prowler

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/prowler.py` (OCSF + legacy) |
| Runner adapter? | Y | `ProwlerAdapter` |
| Executable available? | Local only | `which("prowler")`; **no** `image_key` |
| Docker image required? | N | Not in `SCANNER_IMAGES` |
| Configured? | Binary on worker PATH | |
| Worker can invoke? | Partial | Adapter runs if binary present; **not** in `TOOL_ASSET_KINDS` (gate does not map cloud provider → asset kind) |
| Expected output? | `*.ocsf.json` via `resolve_output` | `json-ocsf` |
| Import path? | Auto + upload | |
| Normalized findings? | Y | |
| Errors / timeouts? | Shared base | |
| Licence? | Apache-2.0 | |
| Scope restriction? | Weak | Target is provider name (`aws`/`azure`/`gcp`/`kubernetes`), not engagement URL/image pin |

### kube-bench

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/kube_bench.py` |
| Runner adapter? | Y | `KubeBenchAdapter` |
| Executable available? | Local only | `which("kube-bench")`; no Docker pin |
| Docker image required? | N | |
| Configured? | Binary on node | Intended to run on cluster node |
| Worker can invoke? | Partial | Same asset-kind gap as Prowler |
| Expected output? | JSON `--outputfile` | Targets: master/node/controlplane/etcd/policies |
| Import path? | Auto + upload | |
| Normalized findings? | Y | |
| Errors / timeouts? | Shared | |
| Licence? | Apache-2.0 | CIS text cited by id only |
| Scope restriction? | Operational | Must run where kubelet/config is visible |

### testssl.sh

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/testssl.py` (+ notes/summarize) |
| Runner adapter? | Y | `TlsTestsslAdapter` |
| Executable available? | Local **or** Docker | `which("testssl.sh")` |
| Docker image required? | Preferred | `ATTESTRA_IMAGE_TESTSSL` |
| Configured? | Placeholder by default | Commonly pinned in operator `.env` |
| Worker can invoke? | Y | URL tools; **refused for `http://`** (no TLS) |
| Expected output? | JSON `--jsonfile` | Baseline: `-p -S -P -f -H` (no `-U`) |
| Import path? | Auto + upload | |
| Normalized findings? | Y | Engine noise → notes, not findings |
| Errors / timeouts? | Y | |
| Licence? | GPL-2.0 | Process/container; image distribution → source-offer |
| Scope restriction? | Y | `--ip` pinned address only |

### Gitleaks

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/gitleaks.py` (never keeps secret value) |
| Runner adapter? | Y | `GitleaksAdapter`; always `--redact` |
| Executable available? | Local **or** Docker | |
| Docker image required? | Optional | `ATTESTRA_IMAGE_GITLEAKS` |
| Configured? | Placeholder by default | |
| Worker can invoke? | Y | Asset kind `repo` |
| Expected output? | JSON report path | Docker adds `--no-git` |
| Import path? | Auto + upload | |
| Normalized findings? | Y | Severity high; CWE-798 |
| Errors / timeouts? | Y | `--exit-code 0` |
| Licence? | MIT | |
| Scope restriction? | Path/repo | |

### Checkov

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/checkov.py` |
| Runner adapter? | Y | `CheckovAdapter`; `report_on_stdout=True` |
| Executable available? | Local **or** Docker | |
| Docker image required? | Optional | `ATTESTRA_IMAGE_CHECKOV` |
| Configured? | Placeholder by default | |
| Worker can invoke? | Y | Asset kind `repo` |
| Expected output? | JSON on stdout → saved file | `--soft-fail`; empty OK |
| Import path? | Auto + upload | |
| Normalized findings? | Y | |
| Errors / timeouts? | Y | |
| Licence? | Apache-2.0 | |
| Scope restriction? | Path/repo | |

### Naabu

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/naabu.py` |
| Runner adapter? | Y | `NaabuAdapter` |
| Executable available? | Local **or** Docker | |
| Docker image required? | Optional | `ATTESTRA_IMAGE_NAABU` |
| Configured? | Placeholder by default | |
| Worker can invoke? | Y | URL/host tools |
| Expected output? | `naabu-out.jsonl` | Empty OK (no open ports) |
| Import path? | Auto + upload | |
| Normalized findings? | Y | |
| Errors / timeouts? | Y | |
| Licence? | MIT | Nmap **not** used (NPSL) |
| Scope restriction? | Y | `-host` = pinned IP only; Docker connect-scan `-scan-type c` |

### WebCheck (Attestra built-in)

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/webcheck.py` |
| Runner adapter? | Y | `WebcheckAdapter` (pure Python; `image_key=""`) |
| Executable available? | Always | No external binary |
| Docker image required? | N | |
| Configured? | Built-in | Optional GSB / HSTS preload flags |
| Worker can invoke? | Y | Requires `AuthorizedScope`; `safe_get` only |
| Expected output? | `webcheck.json` | Headers, DNS, CSP, cookies, SRI, mixed content, HTTP→HTTPS |
| Import path? | Auto + upload | |
| Normalized findings? | Y | Merges with ZAP/testssl/Observatory variants |
| Errors / timeouts? | Per-request via safe HTTP | Notes on failures |
| Licence? | Attestra code | GSB API optional, off by default |
| Scope restriction? | Y | Strongest: every request through scope + pin |

### Mozilla HTTP Observatory

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/observatory.py` |
| Runner adapter? | N | Upload only; no live API |
| Executable / Docker? | N/A | |
| Configured? | N/A | |
| Worker can invoke? | N | |
| Expected output? | Saved Observatory JSON | `tests` / `scan`+`tests` shapes |
| Import path? | Manual upload (`observatory`) | |
| Normalized findings? | Y | Variants align with webcheck |
| Errors / timeouts? | Parse-time only | |
| Licence? | N/A (file import) | Site grade helpers in `grade.py` are separate Observatory-*style* scoring |
| Scope restriction? | Import gate + asset match | |

### Qualys SSL Labs

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/ssllabs.py` |
| Runner adapter? | N | Upload only; no live API |
| Executable / Docker? | N/A | |
| Worker can invoke? | N | |
| Expected output? | Host/analyze JSON | Weak protocols/certs → findings |
| Import path? | Manual (`ssllabs`) | |
| Normalized findings? | Y | Variants align with testssl |
| Licence? | N/A (file import) | |
| Scope restriction? | Import gate | |

### Burp Suite

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/burp.py` (Issues XML; XXE-safe) |
| Runner adapter? | N | Manual/export only |
| Executable / Docker? | N/A | Commercial tool outside Attestra |
| Worker can invoke? | N | |
| Expected output? | Burp Issues XML | |
| Import path? | Upload / Elite façade | Proof capture for HTTP pairs |
| Normalized findings? | Y | Out-of-scope hosts → `unmatched_findings` |
| Licence? | Burp proprietary | Attestra does not redistribute |
| Scope restriction? | Host must match engagement asset | |

### Nessus

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/nessus.py` (`.nessus` v2; XXE-safe) |
| Runner adapter? | N | |
| Executable / Docker? | N/A | |
| Worker can invoke? | N | |
| Expected output? | Nessus XML | Plugin 19506 → notes |
| Import path? | Upload | |
| Normalized findings? | Y | Severity 0–4 mapped |
| Licence? | Tenable proprietary | |
| Scope restriction? | Host match / unmatched count | |

### SARIF (generic)

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/sarif.py` |
| Runner adapter? | Indirect | Semgrep writes SARIF; any SARIF upload uses key `sarif` |
| Docker? | N/A for generic upload | |
| Worker can invoke? | Via Semgrep adapter | |
| Expected output? | SARIF 2.1 | |
| Normalized findings? | Y | |
| Licence? | Format OASIS; tool-dependent | |

### CycloneDX

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/cyclonedx.py` |
| Runner adapter? | N | SBOM upload only |
| Worker can invoke? | N | |
| Expected output? | CycloneDX JSON with `vulnerabilities` | Components alone ≠ findings; VEX skip states |
| Import path? | Upload `cyclonedx` | |
| Normalized findings? | Y | |
| Licence? | Format OWASP; content vendor-specific | |

### Dependency-Track

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y | `importers/dependency_track.py` |
| Runner adapter? | N | No live DT API client in runner |
| Worker can invoke? | N | |
| Expected output? | Finding export / FPF JSON | Suppressed skipped |
| Import path? | Upload `dependency_track` | |
| Normalized findings? | Y | |
| Licence? | Apache-2.0 (DT project); import-only here | |

### OpenVAS / Greenbone (extra)

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | N | No `openvas` parser in `PARSERS` |
| Runner adapter? | Stub config only | `http_service.py` `ATTESTRA_OPENVAS_ENABLED` + `_URL` |
| Worker can invoke? | N | No HTTP client / job wiring |
| Licence? | AGPL/GPL — separate service only | |

### MobSF (extra)

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | N | |
| Runner adapter? | Stub config only | `ATTESTRA_MOBSF_ENABLED` + `_URL` |
| Worker can invoke? | N | |
| Licence? | GPL-3.0 — separate service only | |

### ASV (PCI) (extra)

| Question | Status | Evidence |
| --- | --- | --- |
| Importer? | Y (separate) | `importers/asv.py` + `services.import_asv_results` — **not** in `PARSERS` |
| Runner adapter? | N | Vendor scan file conversion |
| Worker can invoke? | N | API/UI ASV import endpoints |

### Automated VAPT orchestrator (extra)

| Question | Status | Evidence |
| --- | --- | --- |
| Nature | In-process test cases (T01–T22), not third-party scanner | `attestra/automated_vapt/` |
| Default | **OFF** | `ATTESTRA_AUTOMATED_VAPT_ENABLED` |
| Mutation / SSRF / upload | Extra flags, also off by default | Must stay disabled by default |

---

## Matrix (compact)

| Tool | Importer | Adapter | Docker env | Local binary | Worker invoke | Default usable |
| --- | --- | --- | --- | --- | --- | --- |
| ZAP | Y | Y | `ATTESTRA_IMAGE_ZAP` | N | Y | After real digest pin |
| Nuclei | Y | Y | `ATTESTRA_IMAGE_NUCLEI` | Y | Y | After pin or local install |
| Trivy | Y | Y | `ATTESTRA_IMAGE_TRIVY` | Y | Y | Same |
| Semgrep | SARIF | Y | `ATTESTRA_IMAGE_SEMGREP` | Y | Y | Same |
| Prowler | Y | Y | — | Y | Partial | Binary + credentials |
| kube-bench | Y | Y | — | Y | Partial | On cluster node |
| testssl | Y | Y | `ATTESTRA_IMAGE_TESTSSL` | Y | Y | After pin or local |
| Gitleaks | Y | Y | `ATTESTRA_IMAGE_GITLEAKS` | Y | Y | Same |
| Checkov | Y | Y | `ATTESTRA_IMAGE_CHECKOV` | Y | Y | Same |
| Naabu | Y | Y | `ATTESTRA_IMAGE_NAABU` | Y | Y | Same |
| WebCheck | Y | Y | — | Built-in | Y | Always (scoped) |
| Observatory | Y | N | — | — | N | Upload |
| SSL Labs | Y | N | — | — | N | Upload |
| Burp | Y | N | — | — | N | Upload |
| Nessus | Y | N | — | — | N | Upload |
| SARIF | Y | via Semgrep | — | — | Partial | Upload / Semgrep |
| CycloneDX | Y | N | — | — | N | Upload |
| Dependency-Track | Y | N | — | — | N | Upload |
| OpenVAS | N | Config stub | — | — | N | Missing |
| MobSF | N | Config stub | — | — | N | Missing |
| ASV | Separate | N | — | — | N | PCI import path |

---

## Gaps (SCANNER-G…)

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| **SCANNER-G01** | `.env.example` omits `ATTESTRA_IMAGE_*` and scanner timeout knobs | Med | Operators only see placeholders via README/SETUP; example env is incomplete |
| **SCANNER-G02** | Default image digests are placeholders → Docker scanners refuse until pinned | Med (by design) | Correct safety; document which tools need pins for a “full” worker |
| **SCANNER-G03** | Prowler / kube-bench have **no** `ATTESTRA_IMAGE_*` and no Docker path | Med | Cloud/K8s posture needs either dedicated images or documented host agents |
| **SCANNER-G04** | Prowler / kube-bench **absent** from `TOOL_ASSET_KINDS` | Med | Gate cannot refuse wrong asset kinds; target semantics differ from web/repo/image |
| **SCANNER-G05** | OpenVAS / MobSF: enable+URL config only; **no** client, job, or importer | High (if marketed) | LICENSES claim HTTP service path; runtime is stub |
| **SCANNER-G06** | Observatory / SSL Labs: import-only (no runner) | Low | Intentional; avoid calling third-party APIs from Attestra |
| **SCANNER-G07** | Burp / Nessus: import-only | Low | Expected for commercial desktop/server tools |
| **SCANNER-G08** | CycloneDX / Dependency-Track: import-only; no SBOM generator or DT API sync | Low–Med | No Trivy→CycloneDX bridge in-runner |
| **SCANNER-G09** | K8s scanner Jobs are templates only; worker still `docker run` on worker host | High (for prod isolation) | `deploy/README.md`: Job API creation not done |
| **SCANNER-G10** | App `Dockerfile` explicitly excludes scanners; no dedicated scanner image published by Attestra | Med | Each tool uses upstream vendor image; no single “attestra-scanners” image |
| **SCANNER-G11** | `lat.md/import-pipeline.md` “No scanner execution” conflicts with runner plane | Low (docs) | Imports module is read-only; runners *do* execute under gate |
| **SCANNER-G12** | ASV importer not registered in `PARSERS` | Low | Separate PCI API; fine if intentional, easy to miss in tool lists |
| **SCANNER-G13** | Semgrep CE Rules License SaaS restriction | Compliance | Documented; review before hosted offering |
| **SCANNER-G14** | Automated VAPT can be enabled in local `.env`; product default must stay off | Policy | Code default is off; enforce in deploy templates / reviews |

---

## Proposal only: dedicated scanner image vs worker image

**Do not implement here.** Recommendation for a later design decision:

### Current state

- **Worker/API image:** Python Attestra only; invokes `docker run` for digest-pinned upstream scanner images when configured.
- **Scanner images:** Vendor upstream (ZAP, Nuclei, Trivy, …), one env var each.
- **K8s:** Example Job + NetworkPolicy (egress to pinned /32); worker does not yet spawn Jobs.

### Option A — Keep multi-image (recommended near-term)

- Worker stays thin; each tool keeps its own pinned image.
- Pros: smaller blast radius, licence isolation (GPL testssl, LGPL Semgrep), independent upgrades, matches today’s adapters.
- Cons: many digests to maintain; worker needs Docker socket or equivalent.

### Option B — Dedicated “scanner sidecar / Job image” set

- Publish (or pin) a **small set** of Attestra-maintained meta-images only where argv/mount conventions need glue — still prefer **one upstream tool per image**, not a mega-image of all GPL/AGPL tools.
- Worker creates **Kubernetes Jobs** (finish SCANNER-G09) with NetworkPolicy egress = gate pin only.
- Pros: matches `Dockerfile` comment and helm chart intent; better multi-tenant isolation than Docker-from-worker.
- Cons: Job API, RBAC, artifact hand-off, digest CI.

### Option C — Mega “all scanners” image (not recommended)

- Bundle ZAP+Nuclei+Trivy+… into one image on the worker.
- Reject: licence entanglement (GPL/LGPL/AGPL), huge attack surface, slow updates, contradicts LICENSES.md rules 1–2.

### Suggested direction

1. **Short term:** Option A + document every `ATTESTRA_IMAGE_*` in `.env.example` (closes G01); pin digests in deploy secrets.
2. **Medium term:** Option B Job launcher for network tools (ZAP, Nuclei, testssl, naabu); keep path tools (Semgrep, Gitleaks, Checkov, Trivy fs) as Job with repo PVC or continue worker-local Docker.
3. **Prowler / kube-bench:** treat as **host/agent** adapters or add explicit images + asset kinds (closes G03/G04); do not hide inside the API image.
4. **OpenVAS / MobSF:** either implement real HTTP import adapters behind the existing enable flags, or remove/hide the stubs until ready (G05).
5. **Automated VAPT:** remain off by default in all shipped compose/helm values (G14).

---

## Summary: implemented vs stub vs missing

### Implemented (runner + importer, worker-ready when binary/image present)

- **ZAP** (Docker-only), **Nuclei**, **Trivy**, **Semgrep** (→ SARIF), **testssl**, **Gitleaks**, **Checkov**, **Naabu**, **WebCheck** (pure Python).

### Implemented importer only (no Attestra runner)

- **Observatory**, **SSL Labs**, **Burp**, **Nessus**, **SARIF** (generic upload), **CycloneDX**, **Dependency-Track**.
- **ASV** via dedicated PCI import (not in `PARSERS`).

### Adapter present but incomplete for production Docker/fleet

- **Prowler**, **kube-bench** — local binary adapters; no image pin; weak asset-kind gating.

### Stub / missing execution path

- **OpenVAS**, **MobSF** — env enable stubs only (`http_service.py`); no importer keys, no HTTP invoke.
- **K8s Job orchestration** from worker — templates only.
- **Dedicated Attestra scanner image** — not built; upstream images only.

### Intentionally non-scanner

- **`attestra/integrations/`** — Jira/GitHub/Azure DevOps/ServiceNow/GRC tickets, not scanners.
- **Automated VAPT** — first-party orchestrator; **must stay disabled by default**.

---

*End of audit. Evidence paths cited above; no scanners installed and no application code modified for this deliverable.*
