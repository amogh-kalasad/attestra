This directory defines the high-level concepts, business logic, and architecture of **Attestra** using markdown. It is managed by [lat.md](https://www.npmjs.com/package/lat.md). Install with `npm i -g lat.md` and run `lat --help`.

# Attestra knowledge graph

Attestra turns imported security testing scanner results into de-duplicated, risk-ranked findings, maps them to PCI DSS / ISO 27001 / SOC 2 controls, and produces hashed, four-eyes-approved, signed reports. It does not run scanners.

## Index

Map of topic files in this vault. Use `lat section` or `lat search` to open one.

- [[architecture]] — system layers, design decisions, engagement flow, v0.1 boundaries
- [[authorization]] — signed authorization record, import gate, assets, actor header
- [[import-pipeline]] — parsers, NormalizedFinding, import_results run
- [[findings]] — fingerprint dedup, risk score, SLA, lifecycle, evidence
- [[compliance]] — hub-and-spoke mapping, status proposal, assessor confirm
- [[reports]] — HTML generation, four-eyes approval, HMAC signing
- [[audit]] — hash-chained audit log and verification
- [[interfaces]] — REST API, CLI, web dashboard, config, product marketing page
- [[runner]] — scoped scanner dispatch, SSRF/DNS pin, gate, durable jobs
- [[tests]] — pytest suite: fixtures, test modules, and what each verifies
- World-class VA + PT Phase 1 audit: [[architecture#World-class security testing audit (Phase 1)]] (`docs/WORLDCLASS_VAPT_PHASE1_AUDIT.md`)
- World-class risk scoring (Phase 5): [[architecture#World-class risk scoring (Phase 5)]] (`docs/WORLDCLASS_VAPT_PHASE5_RISK_SCORING.md`)
- World-class finding normalization (Phase 6): [[architecture#World-class finding normalization (Phase 6)]]
- World-class report engine sections (Phase 8): [[architecture#World-class report engine sections (Phase 8)]] (`docs/WORLDCLASS_VAPT_PHASE8_REPORT_ENGINE.md`)
- World-class report QA (Phase 9): [[architecture#World-class report QA (Phase 9)]] / [[reports#World-class report QA (Phase 9)]] (`docs/WORLDCLASS_VAPT_PHASE9_REPORT_QA.md`)
- World-class report QA (Phase 9): [[reports#World-class report QA (Phase 9)]]
- World-class ENG1 V21 regression (Phase 10): [[architecture#World-class ENG1 V21 regression (Phase 10)]] / [[tests#World-class Phase 10 ENG1 V21]] (`docs/WORLDCLASS_VAPT_PHASE10_ENG1_V21.md`)

MongoDB is the runtime store (see [[architecture#MongoDB migration (in progress)]]); cutover design notes live in `docs/mongodb_migration/`.

## Quick orientation

Entry points for common questions about what Attestra does today.

- Product boundary: [[architecture#Import do not execute]]
- Import gate: [[authorization#Import gate]]
- Finding pipeline: [[import-pipeline#Import run]] → [[findings#Deduplication]] → [[findings#Risk score]]
- Compliance: [[compliance#Status proposal]]
- Shipping evidence: [[reports#Generation]]
