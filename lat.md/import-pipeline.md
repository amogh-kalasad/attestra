# Import pipeline

Attestra turns scanner **result files** into [[attestra/importers/base.py#NormalizedFinding]] records, then into persisted [[attestra/models.py#Finding]] rows.

## Supported formats

Tool keys registered in [[attestra/importers/__init__.py#PARSERS]] and their parsers.

| Tool key | Parser | Typical input |
| --- | --- | --- |
| `zap` | [[attestra/importers/zap.py#parse]] | OWASP ZAP traditional-json |
| `nuclei` | [[attestra/importers/nuclei.py#parse]] | Nuclei `-jsonl` |
| `trivy` | [[attestra/importers/trivy.py#parse]] | Trivy JSON (vulns + misconfigs) |
| `sarif` | [[attestra/importers/sarif.py#parse]] | SARIF 2.1 (Semgrep, CodeQL, Checkov, Gitleaks, …) |
| `testssl` | [[attestra/importers/testssl.py#parse]] | testssl.sh `--jsonfile` / pretty JSON |
| `webcheck` | [[attestra/importers/webcheck.py#parse]] | Attestra webcheck JSON (`findings` list) |
| `observatory` | [[attestra/importers/observatory.py#parse]] | Saved Mozilla HTTP Observatory JSON (upload only) |
| `ssllabs` | [[attestra/importers/ssllabs.py#parse]] | Saved Qualys SSL Labs Host JSON (upload only) |
| `burp` | [[attestra/importers/burp.py#parse]] | Burp Suite Issues XML export |
| `nessus` | [[attestra/importers/nessus.py#parse]] | Nessus `.nessus` v2 XML |
| `garak` | [[attestra/importers/garak.py#parse]] | Garak JSONL / hitlog (detector hits only) |
| `promptfoo` | [[attestra/importers/promptfoo.py#parse]] | Promptfoo `eval` / redteam `results.json` |
| `safelabs` | [[attestra/importers/safelabs.py#parse]] | safelabs-eval JSON / EvalResult |
| `pyrit` | [[attestra/importers/pyrit.py#parse]] | PyRIT attack-result JSON/JSONL |

Entry point: [[attestra/importers/__init__.py#parse]].

[[attestra/importers/zap.py#parse]] appends truncated `requestHeader` / `responseHeader` / `statusCode` snippets to `evidence_refs` when alert instances include them (e.g. traditional-json-plus); packaged `-J` traditional-json often omits messages. [[attestra/proof/capture.py#_zap]] accepts kebab-case, camelCase, and lowercase header keys for HttpPair auto-capture.

Observatory and SSL Labs never call those sites from Attestra. Failed Observatory tests and weak SSL Labs protocols/certs become findings; variants match webcheck header ids and testssl TLS ids so re-imports merge instead of doubling.

### Burp and Nessus XML

Offline XML uploads via the same registry, UI drop-down and CLI `import` path.

[[attestra/importers/_xmlutil.py#parse_xml]] uses defusedxml with a size cap and refuses entity expansion (XXE). Burp maps issue type, severity, host/path, background/detail/remediation and request/response evidence; [[attestra/proof/capture.py#capture_from_import]] auto-attaches Burp HTTP pairs and, when a screenshot `capture_fn` is registered via [[attestra/proof/screenshots.py#register_screenshot_capture]], redacted screenshots for matching http(s) findings. Nessus maps `ReportItem` plugin id/name, severity 0–4 (0 → info), port/protocol, CVE/CVSS, description/solution/output. Plugin 19506 (Nessus Scan Information) and similar scan-info rows go to [[attestra/importers/nessus.py#extract_notes]] / `ImportRun.notes_json`, not findings. [[attestra/services.py#import_results]] skips Burp/Nessus findings whose host matches no engagement asset and counts them in `unmatched_findings`. webcheck `dns-caa` and testssl `DNS_CAArecord` also merge via [[attestra/fingerprint.py#canonicalize_for_merge]] (shared [[attestra/fingerprint.py#CAA_VARIANT]]).

### testssl keepers (R17 / R18)

Default skip of OK/INFO still applies, with keepers for weak signatures and OCSP.

[[attestra/importers/testssl.py#parse]] keeps weak certificate signature hashes (`cert_signatureAlgorithm` + SHA224/SHA1/MD5 → Low, CWE-327, variant `cert_signatureAlgorithm`) and weak handshake / key-exchange signature hashes (`FS_TLS12_sig_algs` / `FS_TLS13_sig_algs` + SHA224/SHA1/MD5 → Low, CWE-327, variant `handshake`) so both can show. OCSP stapling not offered (`OCSP_stapling`) is kept only when `cert_ocspURL` is non-empty (Info, CWE-299). Certificate expiry uses `cert_notAfter` via [[attestra/cert_expiry.py#finding_for_end_date]] (30/14/7 bands); chain of trust failures and weak protocols (SSLv2/3, TLS 1.0/1.1) keep clear titles.

### testssl tool notes

Scanner diagnostics stay on the import/scan record; they are not findings.

[[attestra/importers/testssl.py#extract_notes]] collects `engine_problem`, service/scanTime noise, GOST/engine support text, and pretty-JSON `clientProblem*` lines. [[attestra/importers/testssl.py#parse]] skips those rows. [[attestra/services.py#import_results]] stores them on [[attestra/models.py#ImportRun]] `notes_json` (`{"notes":[...]}`); durable scan completion copies the same JSON onto [[attestra/models.py#ScanRun]] `notes_json`.

### TLS summary

Report box for protocols, ciphers, certificate and OCSP from the latest testssl result.

[[attestra/importers/testssl.py#summarize]] fills those fields from raw JSON. [[attestra/services.py#tls_summaries]] reads the latest testssl scan or import per engagement, adds `days_left` from the cert end date, and returns `scanned=False` ("not scanned") when none exists. The technical report template renders the "TLS summary" section.

## Garak importer

AASI Phase 1 parser for native Garak JSONL reports and hitlogs.

[[attestra/importers/garak.py#parse]] emits [[attestra/importers/base.py#NormalizedFinding]] only for detector hits (attempt `status==2` with score ≥ 0.5, or hitlog rows). Probe execution alone is not a finding. `tool="garak"`; probe/detector ids and tool version are preserved; CWE stays unset. Malformed `detector_results` raises `ValueError`. Registered in [[attestra/importers/__init__.py#PARSERS]]. Note: `docs/ai_security/AASI_PHASE1_GARAK_IMPORTER.md`.

## Promptfoo importer

AASI Phase 1 parser for `promptfoo eval -o results.json` / `redteam run -o results.json` (EvaluateSummary v2/v3).

[[attestra/importers/promptfoo.py#parse]] accepts the wrapped export (`results.results[]` plus `metadata.promptfooVersion`) or a bare summary. Failed assertions (`success: false`, `failureReason` ASSERT) become [[attestra/importers/base.py#NormalizedFinding]] with `tool="promptfoo"`; plugin id → `rule_id`, strategy id → `variant` / `original_id`, provider → `location`, `testIdx` → `param`. Passed rows and provider ERROR rows (`failureReason` 2) emit nothing. CWE stays unset unless the source supplies one. Malformed structures raise `ValueError`. Registered in [[attestra/importers/__init__.py#PARSERS]]. Note: `docs/ai_security/AASI_PHASE1_PROMPTFOO_IMPORTER.md`.

## SafeLabs importer

AASI Phase 1 parser for safelabs-eval CLI `--output json` and EvalResult dumps.

[[attestra/importers/safelabs.py#parse]] maps `vulnerable` / `fail` rows to [[attestra/importers/base.py#NormalizedFinding]] with `tool="safelabs"`. Prompt id, detector (`eval_type`), indicators, heuristic confidence, taxonomy source, and tool version are preserved. Titles use **SafeLabs ASI-source** labels (not official OWASP Agentic Top 10 2026). `pass` / `uncertain` / missing / error rows emit nothing. Heuristic uncertainty lives in `confidence` (`validation=potential`); NormalizedFinding has no validation field — persist must stay `potential`. Malformed JSON raises `ValueError`. Registered in [[attestra/importers/__init__.py#PARSERS]]. Note: `docs/ai_security/AASI_PHASE1_SAFELABS_PYRIT_IMPORTERS.md`.

## PyRIT importer

AASI Phase 1 fixture-driven parser for structured PyRIT attack-result JSON/JSONL (worker execution is Phase 5).

[[attestra/importers/pyrit.py#parse]] accepts `attack_results` / `results` wrappers, lists, JSONL, or a single object. Successful outcomes / `success: true` / true scores become findings with `tool="pyrit"`; conversation and scenario ids, score, and success flags are preserved. Failures, errors, undetermined rows, and empty exports yield no findings. Malformed input raises `ValueError`. Registered in [[attestra/importers/__init__.py#PARSERS]]. Note: `docs/ai_security/AASI_PHASE1_SAFELABS_PYRIT_IMPORTERS.md`.

## Normalization helpers

Shared dataclasses and severity/CWE helpers used by every importer.

- [[attestra/importers/base.py#NormalizedFinding]] — common shape
- [[attestra/importers/base.py#parse_cwe]] — accept `79`, `CWE-79`, etc.
- [[attestra/importers/base.py#norm_severity]] — map tool severities to critical/high/medium/low/info

## Import run

Steps performed by [[attestra/services.py#import_results]] for one uploaded result file.

1. Require valid authorization (see [[authorization#Import gate]]).
2. Parse raw bytes with the selected tool parser.
3. Match each finding location to an engagement asset; enforce authorized environments. For `burp` / `nessus`, hosts with no matching asset are skipped and counted as unmatched.
4. Store raw file write-once under `data/imports/` ([[attestra/services.py#_store]]).
5. Create [[attestra/models.py#ImportRun]] with SHA-256; attach tool notes when present (testssl / nessus).
6. Upsert findings by fingerprint (see [[findings#Deduplication]]).
7. Rescore; reopen `fixed` findings that reappear.
8. Audit `import.create`.

## No scanner execution

Clarifies the import-only boundary for this module.

There is no subprocess, Docker job, or Temporal workflow that launches ZAP/Nuclei/Trivy. Testers produce files; Attestra only reads them.
