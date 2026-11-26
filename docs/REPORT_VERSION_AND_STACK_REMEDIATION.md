# Report versions, numbering legend, and stack remediation (Gap #10)

Additive ShieldByte Gap #10 behaviour for technical reports and library fix snippets.

## Scanner versions (never invent)

- `ScanRun.tool_version` and observation `tool_version` remain the only sources for the Tools and versions table. Missing values render as **version not recorded**.
- AI adapters `garak`, `promptfoo`, and `safelabs` probe the shared runtime via `attestra.scanner_runtime` helpers (`check_python_package` / `check_promptfoo`), matching the PyRIT pattern. When the probe fails, `version()` returns the tool name only — never a fabricated pin.

## Report Identifier and Numbering Legend

Technical HTML includes `#numbering-legend` when at least one identifier form is present. Rows are built by `attestra.reports.render._numbering_legend` and list **only** types that appear in this report:

| Type | Typical form |
|---|---|
| Engagement | `Engagement #N` |
| Finding | `F-N` (report-local order) |
| Scan / run | `Scan #N` |
| Import | `Import #N` |
| Auth profile | `Auth profile #N` (from authenticated scan runs; secrets never shown) |
| Retest | Retest on `F-N` |
| Evidence | `Fig. F-N-i` / sha256 |

Unused types are omitted — no placeholder rows. Report signing and hashes are unchanged aside from this additive section in newly generated drafts.

## Stack layers and Node/Express + Cloudflare

- `detect_stack_layers(*texts)` returns `{origin, edge, proxy}`.
- Express/Node + Cloudflare is a **layered** stack (`origin=node`, `edge=cloudflare`), not an ambiguity. `detect_server_type` therefore returns `node` (origin primary) instead of `None`.
- Classic multi-origin collisions without Node (e.g. nginx+apache) still return `None` so reports keep the nginx+Apache fallback pair.
- Per-finding `snippets_for_report(..., layers=...)` can emit both node (Helmet / app) and cloudflare (edge Transform Rules) snippets when both layers and texts exist.
- Additional `snippet_node` Helmet examples cover XCTO, CSP, Referrer-Policy, HSTS, clickjacking/frameguard, Permissions-Policy, and COEP/COOP/CORP without removing nginx/apache/iis/cloudflare snippets.

## Tests

`tests/test_gap10_report_stack_versions.py` covers Express+Cloudflare detection, layered snippets, mocked version probes, numbering-legend presence rules, and the legend section in generated technical HTML.
