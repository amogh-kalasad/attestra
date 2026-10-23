# Findings library and report templates

## Findings library

Per-tenant reusable writeups (`library_entries`): title, description, impact,
remediation, references, CWE, default severity, tags, tool rule ids, plus optional
importance / effort / fix steps and nginx, Apache, IIS and Cloudflare snippets
(migration `0018_library_fix_snippets`; empty values stay valid).

- **UI:** `/library` (search, create, "Add starter writeups"), `/library/{id}` (edit, delete, apply to a finding).
- **API** (`finding.write`: admin, lead, tester):
  - `GET /api/library?q=&tenant_id=` search (title, text, tags, rule ids, `cwe-79`)
  - `POST /api/library`, `GET|PUT|DELETE /api/library/{id}`
  - `POST /api/library/seed` adds about 30 starter web writeups (OWASP Top 10 style) the tenant does not have yet
  - `POST /api/library/import` multipart `file` (+ optional `fmt=json|csv`, `tenant_id`) imports an onboarding template: JSON list or CSV of `{title, severity, description, recommendation, owasp_top10?}` → library entries (skips existing titles; audited as `library.import`; rejects oversized files)
  - `POST /api/findings/{fid}/apply-library {"entry_id": n}`
  - `GET /api/findings/{fid}/library-suggestions`, `GET /api/engagements/{eid}/library-suggestions`
  - imports return `library_suggestions` (findings with a matching writeup)
- **Apply** fills only empty fields: description (+ impact), recommendation (+ references), CWE.
  A tester's text is never overwritten. Every change is audited.
- **Suggest** matches tool rule ids first (`zap:40018`, or a bare id), then CWE.

`tenant_id` defaults to the caller's home tenant (or their only membership).

## Report templates

`report_templates`: one row per tenant and report kind, or `*` for technical and
executive reports. Fields: Jinja source (empty = built-in library layout), cover
title, logo (PNG/JPEG/GIF up to 500 KB, stored as a data URI), section order
(`cover, summary, findings, compliance, scope, appendix`) and an enabled flag.

- **UI:** `/library/templates` (edit in a text box or upload a file, upload logo).
- **API** (`report.generate`): `GET /api/report-templates`, `PUT /api/report-templates/{kind}`,
  `POST /api/report-templates/{kind}/upload` (multipart `source` and/or `logo`), `DELETE /api/report-templates/{kind}`.
- Rendering uses `jinja2.sandbox.ImmutableSandboxedEnvironment` with autoescape and
  a plain-data context (no ORM objects or sessions). Templates are test-rendered on save.
- If there is no template, it is disabled, or it fails at render time, the built-in
  report template is used. The signed/hashed report flow is unchanged.

Code: `attestra/library/` (fix text helpers in `fix_snippets.py`). Migrations: `0012_findings_library` (RLS on both tables), `0018_library_fix_snippets` (importance/effort/fix steps/snippets).
Tests: `tests/test_findings_library.py`, `tests/test_fix_snippets.py`.
