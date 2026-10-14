# Attestra architecture

The full architecture write-up, with diagrams, the open-source landscape, the v2 PCI / ISO / SOC 2 crosswalk, guardrails and the roadmap, is in the shared doc:

**https://claude.ai/code/artifact/58f312bf-5dc1-4bfb-9471-54730403702d**

## How v0.1 maps to the target architecture

| Target component | v0.1 implementation | Next step |
| --- | --- | --- |
| Portal and API | FastAPI REST API, server-rendered dashboard (`attestra/api.py`, `attestra/web/`) | React portal, Keycloak SSO and RBAC |
| Engagement and scope | `Engagement`, `Asset`, `Authorization`. Imports blocked without a valid signed authorization | Ownership verification (DNS / HTTP), OPA policy |
| Orchestrator and runners | Not in scope for v0.1. Testers run tools themselves and import the results | Temporal workflows for engagement lifecycle and reminders |
| Findings engine | `importers/`, `fingerprint.py`, `scoring.py`, `services.import_results` | DefectDojo sync |
| Manual PT workbench | Lifecycle transitions with validator identity, evidence upload | WSTG / ASVS checklist UI |
| Compliance engine | `compliance/engine.py` + YAML library (CWE → objective → framework control) | CISO Assistant libraries, OSCAL export |
| Reporting | Jinja HTML, version, SHA-256, four-eyes approval, HMAC signature | DOCX/PDF, cosign / X.509 |
| Data and evidence | SQLite or PostgreSQL, content-addressed write-once files, hash-chained audit log | S3 Object Lock, per-tenant KMS |

## Key design decisions

1. **Import, don't execute.** Attestra never runs testing tools. This keeps it out of the business of operating attack infrastructure and keeps scanner licenses (AGPL, GPL, NPSL) out of the product.
2. **Hub-and-spoke mapping.** Findings map once to a control objective through CWE. Objectives map to each framework. Adding a framework means adding YAML, with no code change.
3. **Propose, then confirm.** The engine only proposes control statuses. A named assessor confirms each one with a rationale. `no_exceptions` is kept separate from `met`, so the absence of findings is never presented as proof that a control is in place.
4. **PCI scope.** PCI DSS evaluation counts only findings on CDE assets, plus findings with no matched asset, to stay conservative.
5. **Evidence integrity.** Raw imports, evidence and reports are hashed and stored write-once. The audit log is hash-chained, and signed reports detect any later edit.
