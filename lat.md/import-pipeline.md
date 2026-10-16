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

Entry point: [[attestra/importers/__init__.py#parse]].

Observatory and SSL Labs never call those sites from Attestra. Failed Observatory tests and weak SSL Labs protocols/certs become findings; variants match webcheck header ids and testssl TLS ids so re-imports merge instead of doubling.

### Burp and Nessus XML

Offline XML uploads via the same registry, UI drop-down and CLI `import` path.

[[attestra/importers/_xmlutil.py#parse_xml]] uses defusedxml with a size cap and refuses entity expansion (XXE). Burp maps issue type, severity, host/path, background/detail/remediation and request/response evidence; [[attestra/proof/capture.py]] auto-attaches Burp HTTP pairs. Nessus maps `ReportItem` plugin id/name, severity 0–4 (0 → info), port/protocol, CVE/CVSS, description/solution/output. Plugin 19506 (Nessus Scan Information) and similar scan-info rows go to [[attestra/importers/nessus.py#extract_notes]] / `ImportRun.notes_json`, not findings. [[attestra/services.py#import_results]] skips Burp/Nessus findings whose host matches no engagement asset and counts them in `unmatched_findings`. webcheck `dns-caa` and testssl `DNS_CAArecord` also merge via [[attestra/fingerprint.py#canonicalize_for_merge]] (shared [[attestra/fingerprint.py#CAA_VARIANT]]).

### testssl keepers (R17 / R18)

Default skip of OK/INFO still applies, with keepers for weak signatures and OCSP.

[[attestra/importers/testssl.py#parse]] keeps weak certificate signature hashes (`cert_signatureAlgorithm` + SHA224/SHA1/MD5 → Low, CWE-327, variant `cert_signatureAlgorithm`) and weak handshake / key-exchange signature hashes (`FS_TLS12_sig_algs` / `FS_TLS13_sig_algs` + SHA224/SHA1/MD5 → Low, CWE-327, variant `handshake`) so both can show. OCSP stapling not offered (`OCSP_stapling`) is kept only when `cert_ocspURL` is non-empty (Info, CWE-299). Certificate expiry uses `cert_notAfter` via [[attestra/cert_expiry.py#finding_for_end_date]] (30/14/7 bands); chain of trust failures and weak protocols (SSLv2/3, TLS 1.0/1.1) keep clear titles.

### testssl tool notes

Scanner diagnostics stay on the import/scan record; they are not findings.

[[attestra/importers/testssl.py#extract_notes]] collects `engine_problem`, service/scanTime noise, GOST/engine support text, and pretty-JSON `clientProblem*` lines. [[attestra/importers/testssl.py#parse]] skips those rows. [[attestra/services.py#import_results]] stores them on [[attestra/models.py#ImportRun]] `notes_json` (`{"notes":[...]}`); durable scan completion copies the same JSON onto [[attestra/models.py#ScanRun]] `notes_json`.

### TLS summary

Report box for protocols, ciphers, certificate and OCSP from the latest testssl result.

[[attestra/importers/testssl.py#summarize]] fills those fields from raw JSON. [[attestra/services.py#tls_summaries]] reads the latest testssl scan or import per engagement, adds `days_left` from the cert end date, and returns `scanned=False` ("not scanned") when none exists. The technical report template renders the "TLS summary" section.

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
