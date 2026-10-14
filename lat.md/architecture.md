# Architecture

Attestra v0.1 is an **import-and-report** VAPT evidence platform. Testers run scanners elsewhere; Attestra imports result files, normalizes findings, maps them to compliance controls, and produces hashed, four-eyes-approved, signed reports.

It does **not** execute scanners, spawn runners, or attack targets. That boundary is intentional (license isolation and legal scope).

## Product thesis

Cut the path from engagement kick-off to a signed, audit-ready report. Every claim in a report should be traceable to raw imported evidence.

See also [[docs/ARCHITECTURE.md]] and [[docs/VAPT & Compliance Platform — Architecture (v2 PCI, ISO 27001, SOC 2).md]].

## System layers

How the Python package is split: interfaces call shared services; importers, compliance, and reports sit underneath.

| Layer | Role | Code |
| --- | --- | --- |
| Interfaces | REST API, CLI, server-rendered dashboard | [[attestra/api.py]], [[attestra/cli.py]], [[attestra/web/ui.py]] |
| Business rules | Shared write path; every mutation audited | [[attestra/services.py]] |
| Importers | Parse ZAP / Nuclei / Trivy / SARIF into one schema | [[attestra/importers]] |
| Findings | Fingerprint dedup, risk score, lifecycle | [[attestra/fingerprint.py]], [[attestra/scoring.py]] |
| Compliance | CWE → objective → PCI / ISO / SOC 2 | [[attestra/compliance/engine.py]] |
| Reports | Jinja HTML, four-eyes, HMAC signature | [[attestra/reports/render.py]], [[attestra/reports/signing.py]] |
| Evidence and audit | Content-addressed files; hash-chained log | [[attestra/services.py#_store]], [[attestra/audit.py]] |
| Data | SQLAlchemy models; SQLite or PostgreSQL | [[attestra/models.py]], [[attestra/db.py]], [[attestra/config.py]] |

## Design decisions

Core product rules that shape the v0.1 implementation. Prefer changing these deliberately over silent drift. Details are in the sections below.

## Import do not execute

Attestra never launches scanners; it only parses result files testers already produced.

[[attestra/importers/__init__.py]] documents that Attestra never runs scanners. Supported formats are registered in [[attestra/importers/__init__.py#PARSERS]].

## Hub and spoke compliance mapping

Findings map once to a control objective through CWE; objectives then fan out to frameworks via YAML.

Findings map once to a control **objective** through CWE. Objectives map to each framework. Adding a framework is YAML, not code. Engine: [[attestra/compliance/engine.py]]. Libraries: [[attestra/compliance/data/controls.yaml]], [[attestra/compliance/data/cwe_map.yaml]].

## Propose then confirm

The engine proposes control status; a named assessor must confirm before it is treated as decided.

[[attestra/compliance/engine.py#evaluate]] proposes control statuses. A named assessor confirms via [[attestra/services.py#confirm_control]]. `no_exceptions` is distinct from `met` so absence of findings is never treated as proof a control is in place.

## PCI CDE scope

PCI evaluation only counts findings on CDE assets (plus unmatched locations, conservatively).

[[attestra/compliance/engine.py#in_framework_scope]] counts PCI findings only on CDE assets (or findings with no matched asset — conservative).

## Evidence integrity

Raw artifacts are hashed write-once; the audit log is hash-chained; reports are HMAC-signed.

Raw imports, evidence, and reports are SHA-256 hashed and stored write-once ([[attestra/services.py#_store]]). The audit log is hash-chained ([[attestra/audit.py]]). Reports carry an HMAC signature ([[attestra/reports/signing.py]]).

## Engagement flow

End-to-end path for one engagement from create to signed report.

1. Create tenant + engagement ([[attestra/services.py#create_engagement]]).
2. Record signed authorization ([[attestra/services.py#add_authorization]]); imports are blocked without a currently valid one.
3. Add in-scope assets ([[attestra/services.py#add_asset]]).
4. Import scanner results ([[attestra/services.py#import_results]]).
5. Enrich with KEV / EPSS ([[attestra/services.py#enrich]]); triage via [[attestra/services.py#transition]].
6. Evaluate compliance ([[attestra/services.py#compliance]]); assessor confirms controls.
7. Generate, four-eyes approve, and verify reports ([[attestra/reports/render.py#generate_report]]).

## Out of scope in v0.1

Capabilities intentionally deferred; do not invent runners or SSO in this tree without an explicit product decision.

- Running scanners in isolated runners
- Temporal workflows, OPA policy engine
- Keycloak SSO / RBAC (uses `X-Attestra-Actor` header today)
- DefectDojo / CISO Assistant integration
- DOCX/PDF, cosign / X.509, S3 Object Lock
