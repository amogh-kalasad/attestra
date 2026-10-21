# Attestra Implementation Plan

Plan aligned to the consolidated DOCX roadmap and the agent prompt phases. Items marked **Done** were implemented in this pass.

## Wave A — Render stored data (DOCX Phase 1) — Done

1. Document control / report history table  
2. Scope environment column  
3. Test types + standards from `TEST_TYPES`  
4. Findings overview with retest column  
5. Retest report kind + template  
6. CVSS vector, OWASP/ASVS/WSTG fields  
7. Screenshot embeds with captions + SHA-256  
8. Tenant logo / cover title on built-in templates  
9. Metadata template config YAML  

**Verification:** `tests/test_report_coverage_enhancements.py`

## Wave B — Front matter (DOCX Phase 2 Must/Should templates) — Mostly done

Done: cover, TOC, disclaimer, methodology phases, risk legend, conclusion, DRAFT watermark, severity chart in technical, print page numbers.

Next (deferred):

- Engagement `box_type` (black/grey/white)  
- Distribution list model  
- Date sanity checks on submit/sign  
- Separate Impact / References / affected-URL structured fields (migrations)  
- HTTP pair pretty-print in findings  

## Wave C — Export quality (DOCX Phase 3) — Deferred

- Ship richer docxtpl template under `reports/templates/docx`  
- Document WeasyPrint install path in deployment checklist  
- Optional XLSX / generic JSON report export  

## Wave D — Testing coverage (DOCX Phase 4) — Deferred

- Authenticated scan profiles validation  
- Access-control / tamper test playbooks  
- Automatic screenshot capture pipeline  
- Checklist UX mapped to WSTG/ASVS  

## Wave E — Compliance / portal (DOCX Phase 5) — Partial

Done already in product: CERT-In and other packs, tickets (off), portal stubs, ageing/trend.

Next: dedicated OWASP Top 10 / ASVS framework packs (optional), dashboard polish, white-label email.

## Engineering conventions

- Prefer shared Jinja + `template_config.yaml` over per-framework template forks.  
- Do not invent control text; pack YAML titles remain summaries pending licensed-source review.  
- Preserve historical findings/retests; never overwrite evidence on retest.  
- Keep four-eyes signing and tenant isolation intact.  

## Rollback

Template and Python changes are non-destructive (no DB migration in this pass). Revert:

- `attestra/reports/render.py`  
- `attestra/reports/template_config.py`  
- `attestra/reports/data/template_config.yaml`  
- `attestra/reports/templates/_base.html.j2`  
- `attestra/reports/templates/technical.html.j2`  
- `attestra/reports/templates/retest.html.j2`  
- related tests/docs  

No Alembic revision was added; rollback does not require DB downgrade.
