This directory defines the high-level concepts, business logic, and architecture of **Attestra** using markdown. It is managed by [lat.md](https://www.npmjs.com/package/lat.md). Install with `npm i -g lat.md` and run `lat --help`.

# Attestra knowledge graph

Attestra turns imported VAPT scanner results into de-duplicated, risk-ranked findings, maps them to PCI DSS / ISO 27001 / SOC 2 controls, and produces hashed, four-eyes-approved, signed reports. It does not run scanners.

## Index

Map of topic files in this vault. Use `lat section` or `lat search` to open one.

- [[architecture]] — system layers, design decisions, engagement flow, v0.1 boundaries
- [[authorization]] — signed authorization record, import gate, assets, actor header
- [[import-pipeline]] — parsers, NormalizedFinding, import_results run
- [[findings]] — fingerprint dedup, risk score, SLA, lifecycle, evidence
- [[compliance]] — hub-and-spoke mapping, status proposal, assessor confirm
- [[reports]] — HTML generation, four-eyes approval, HMAC signing
- [[audit]] — hash-chained audit log and verification
- [[interfaces]] — REST API, CLI, web dashboard, config

## Quick orientation

Entry points for common questions about what Attestra does today.

- Product boundary: [[architecture#Import do not execute]]
- Import gate: [[authorization#Import gate]]
- Finding pipeline: [[import-pipeline#Import run]] → [[findings#Deduplication]] → [[findings#Risk score]]
- Compliance: [[compliance#Status proposal]]
- Shipping evidence: [[reports#Generation]]
