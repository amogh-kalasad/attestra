# ShieldByte gap-closure source audit (#3, #6, #10)

Phase A inspect-only audit of Attestra before targeted implementation. Comparison gaps from Section 10 (ShieldByte vs Attestra), recommendations **#3, #6, #10 only**.

## Gap #3 — Supervised production safe-mutation

| Area | Baseline |
|---|---|
| Dev/demo T22 | Works when `ATTESTRA_AUTOMATED_VAPT_MUTATION` on + profile active/intrusive + scope policy + env in `dev,demo` |
| Production | Hard-forbidden (`FORBIDDEN_ENVIRONMENTS`); no supervised override |
| DELETE | Already denied |
| One-time four-eyes approval | **Missing** |
| Synthetic test-record-only + restore | **Missing** |
| Deny → NOT_TESTED | Partial (often SKIPPED) |

**Reuse:** `intrusive_policy`, signed auth / ownership / window, report four-eyes *pattern*, AASI human-approve *pattern*.  
**Add:** production-safe-mutation flag + approval grant model + consume/restore path.  
**Do not:** remove global production ban for ordinary intrusive tests.

## Gap #6 — Cloudflare noise + header grouping

| Area | Baseline |
|---|---|
| Classifier | `infrastructure.py` + `classify.py` already cover cdn-cgi, cf_clearance, challenge CORS, static cache |
| Crossmerge context | `security_context_key` separates app vs CDN buckets |
| Report sections | **Missing** named “CDN / Cloudflare Infrastructure Observations” and “Security Headers…” |
| Consolidate | May fold same-host headers across security contexts — needs context in keys |

**Reuse:** existing classifiers (do not build a second engine).  
**Edit:** report render/templates + consolidate context hygiene.

## Gap #10 — Versions, legend, stack remediation

| Area | Baseline |
|---|---|
| ScanRun.tool_version | Persisted; report shows recorded or “version not recorded” |
| AI adapter `version()` | Often name-only stubs (garak/promptfoo/safelabs) |
| Numbering legend | **Missing** |
| `detect_server_type` | Express+Cloudflare together → `None` → wrong nginx/Apache fallback |
| Node snippets | Mostly only on “Server version disclosed” |

**Edit:** adapter version probes, legend section, multi-layer stack + node snippets.

## Implementation order

B → #3, C → #6, D → #10, E → regression + lat + final status table.
