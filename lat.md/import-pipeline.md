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

Entry point: [[attestra/importers/__init__.py#parse]].

### testssl keepers (R17 / R18)

Default skip of OK/INFO still applies, with two keepers.

[[attestra/importers/testssl.py#parse]] keeps weak signature hashes (`cert_signatureAlgorithm` + SHA224/SHA1/MD5 → Low, CWE-327) and OCSP stapling not offered (`OCSP_stapling`) only when `cert_ocspURL` is non-empty (Info, CWE-299). `variant` is the testssl `id`.

## Normalization helpers

Shared dataclasses and severity/CWE helpers used by every importer.

- [[attestra/importers/base.py#NormalizedFinding]] — common shape
- [[attestra/importers/base.py#parse_cwe]] — accept `79`, `CWE-79`, etc.
- [[attestra/importers/base.py#norm_severity]] — map tool severities to critical/high/medium/low/info

## Import run

Steps performed by [[attestra/services.py#import_results]] for one uploaded result file.

1. Require valid authorization (see [[authorization#Import gate]]).
2. Parse raw bytes with the selected tool parser.
3. Match each finding location to an engagement asset; enforce authorized environments.
4. Store raw file write-once under `data/imports/` ([[attestra/services.py#_store]]).
5. Create [[attestra/models.py#ImportRun]] with SHA-256.
6. Upsert findings by fingerprint (see [[findings#Deduplication]]).
7. Rescore; reopen `fixed` findings that reappear.
8. Audit `import.create`.

## No scanner execution

Clarifies the import-only boundary for this module.

There is no subprocess, Docker job, or Temporal workflow that launches ZAP/Nuclei/Trivy. Testers produce files; Attestra only reads them.
