# Infrastructure finding classification (ShieldByte Gap #6)

How Attestra separates **CDN / Cloudflare infrastructure noise** from **application security-header findings** in reports — without rebuilding classifiers.

## Classifiers (reuse only)

Existing modules classify edge noise at import / validation time:

| Signal | Module | Result |
|---|---|---|
| `cdn-cgi` / challenge-platform URLs | `attestra/finding_validation/infrastructure.py` | Informational when paired with cache / CORS / header-missing claims |
| Cloudflare cookies (`cf_clearance`, `__cf_bm`, …) | same | Informational SameSite/cookie findings |
| Static asset cache | same + `classify.py` | Informational on `/_next/`, `/static/`, … |

Do **not** mark every Cloudflare-proxied application finding as a false positive. App-path vulns stay eligible.

## Security context (merge hygiene)

`attestra/finding_normalize.py`:

- `path_context_bucket` → `app` | `cdn-cgi` | `challenge` | `static`
- `security_context_key` → `{host}@{bucket}`

Report consolidation (`attestra/reports/consolidate.py`) includes that key in pass-1 / pass-2 merge keys so the same header title on `/account` and `/cdn-cgi/...` does **not** share one report card. Cross-tool merge already required matching context.

## Report sections (additive)

`attestra/reports/render.py#_partition_infrastructure_findings` builds:

| Context key | Contents |
|---|---|
| `cdn_infrastructure_observations` | Informational CDN-challenge / CF-cookie / CDN-CORS / CDN-cache rows |
| `security_header_findings` | HSTS, CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy on **app** paths |

The main `findings` list is **unchanged** (technical detail, QA, signing, F-labels). Templates add:

- **CDN / Cloudflare Infrastructure Observations** (`#cdn-infrastructure`)
- **Security Headers and Browser Security Controls** (`#security-headers`)

Each header control stays individually traceable via its F-label. Executive copy is a concise group; technical keeps full cards.

## Tests

`tests/test_gap6_infrastructure_report.py` — classify reuse, partition, consolidate context split, template headings.
