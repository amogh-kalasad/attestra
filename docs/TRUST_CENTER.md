# Trust Center

A per-tenant public page built on the client portal (competitor gap report, recommendation 1).

## Rules
- **Off by default.** Only an `admin` can enable it and choose the slug: `PUT /api/v1/trust/tenants/{id}` with `{"enabled": true, "slug": "acme"}`. Public URL: `/trust/{slug}` (404 while disabled).
- **Nothing is published automatically.** A `tester`, `lead` or `admin` publishes each item explicitly: `POST /api/v1/trust/tenants/{id}/items` (or `/documents` for an upload). `POST /api/v1/trust/items/{id}/unpublish` hides it.
- Item kinds: `framework`, `badge`, `report` (signed reports only, same tenant), `document`, and, only if explicitly published, `finding` (title, severity and status only) or `evidence` (title and SHA-256 only, never the file).
- Published reports show a summary and a **live signature check** (hash + signature verified on every page view).
- **Access:** `public` items download directly; `nda` items need a request (`POST /trust/{slug}/items/{id}/request`, NDA checkbox required) that a `lead` or `admin` approves (`POST /api/v1/trust/requests/{id}/approve` or `/deny`). Approval returns a download token once; only its SHA-256 is stored. Download with `?token=`.
- **Audit:** configuration, publish/unpublish, every access request, decision and NDA download are written to the hash-chained audit log (`trust.*` actions).

## Data
Migration `0011_trust_center` adds `trust_centers`, `trust_items`, `trust_access_requests`, each with a `tenant_id` and a Postgres RLS policy (`attestra.rls.TRUST_POLICIES`). Uploaded documents are stored under `DATA_DIR/trust/{tenant_id}/`.
