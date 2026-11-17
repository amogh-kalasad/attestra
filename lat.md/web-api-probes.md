# Web and API safe probes

WP2 of the Attestra upgrade (workstreams B and C): read-only web and API probes, the injection catalogue, and API inventory import. Every probe is production-safe by construction, budgeted, rate-limited and off by default.

Flags (all default off, read from `attestra.config` once INT adds them, else from the environment): `ATTESTRA_PROBES_WEB_SAFE` (CORS, HOSTHDR, OREDIR, CACHE, SSIND active GETs, APIPOST fallback GETs), `ATTESTRA_GRAPHQL_PROBE` (GRAPHQL) and `ATTESTRA_API_IMPORT_ENABLED` (spec upload and capture merge). `ATTESTRA_PROBE_DELAY_MS` (default 250) spaces requests.

## Probe contract

Every probe module exports `META` and `run(client, base_url, *, ctx)` and returns the standard module dict plus `status_hint` and `validity_samples`.

[[attestra/automated_vapt/testing/_probe_base.py#ProbeMeta]] declares the safety tier, the request budget, `mutating=False` and the WSTG/CWE references. [[attestra/automated_vapt/testing/_probe_base.py#ProbeSession]] is the only sender: GET/HEAD/OPTIONS only, `follow_redirects=False`, session headers only for the target origin, a hard budget ([[attestra/automated_vapt/testing/_probe_base.py#BudgetExceeded]]), a delay between requests, and it stops at the first WAF block, challenge or 429 (never retries or evades). Each response is classified by the FND-01 response classifier, imported lazily; [[attestra/automated_vapt/testing/_probe_base.py#_fallback_classify]] applies the same contract conservatively until WP1's module is importable.

[[attestra/automated_vapt/testing/_probe_base.py#status_from_samples]] maps samples to the FND-06 vocabulary: any edge block makes a non-finding case `BLOCKED`, and no usable application response makes it `INCONCLUSIVE`, so a blocked probe never reads as PASSED. Disabled flags and missing identities return [[attestra/automated_vapt/testing/_probe_base.py#not_tested]] (`NOT_TESTED`). Findings carry `finding_confidence` (`confirmed` or `suspected`) and `severity_hint`; INT caps `suspected` at POTENTIAL. Evidence pairs are scrubbed of session values, redacted and size-capped by `ProbeSession.evidence`.

## CORS validation

Catalogue id `CORS` (WSTG-CLNT-07), tier T1, at most 6 requests.

[[attestra/automated_vapt/testing/cors_tests.py#run]] varies only the `Origin` header (an `.invalid` origin, `null`, and a target-host suffix origin) on GET, then sends one OPTIONS preflight. [[attestra/automated_vapt/testing/cors_tests.py#evaluate]] reuses [[attestra/automated_vapt/testing/information_disclosure_tests.py#observe_cors]]. A finding needs a credentialed reflection on an actual GET that returned application content and that reproduces on a second request. A wildcard without credentials and a permissive preflight alone are informational.

## Host header probe

Catalogue id `HOSTHDR` (WSTG-INPV-17), tier T1, at most 5 GETs.

[[attestra/automated_vapt/testing/host_header_tests.py#run]] sends a baseline GET, then one GET each with `X-Forwarded-Host`, `X-Host`, `Forwarded: host=` and an overridden `Host`, all set to a non-routable marker. The request URL, and so the approved destination and pinned IP, never changes. The marker in `Location` ([[attestra/automated_vapt/testing/host_header_tests.py#marker_in_location]]) is confirmed; new absolute links to the marker in the body ([[attestra/automated_vapt/testing/host_header_tests.py#marker_links]]) are suspected.

## Open redirect probe

Catalogue id `OREDIR` (WSTG-CLNT-04), tier T1, at most 12 GETs.

[[attestra/automated_vapt/testing/open_redirect_tests.py#candidates]] takes redirect-style parameters from captured URLs plus a few defaults. [[attestra/automated_vapt/testing/open_redirect_tests.py#run]] sends absolute, scheme-relative, backslash and encoded marker values, never follows redirects to another host, and records the chain: same-origin hops are followed within the budget, off-scope hops stop it. [[attestra/automated_vapt/testing/open_redirect_tests.py#points_at_marker]] decides a hit; same-site redirects are suppressed; meta-refresh or JS redirects to the marker are suspected.

## Cache posture

Catalogue id `CACHE` (WSTG-ATHN-06, CWE-524), tier T1, at most 6 GETs, needs the engagement login.

[[attestra/automated_vapt/testing/cache_posture_tests.py#run]] GETs captured non-static pages with the session and [[attestra/automated_vapt/testing/cache_posture_tests.py#assess_headers]] marks them `ok` (private / no-store) or `suspicious` (shared-cacheable or a CDN HIT). Only a suspicious CDN HIT gets one anonymous GET; an identical body hash makes it `confirmed`. No poisoning payloads, static assets excluded ([[attestra/automated_vapt/testing/cache_posture_tests.py#is_static]]), bodies kept only as a hash and 1 KB of redacted evidence. Without a session the case is NOT_TESTED.

## Injection catalogue

Every injection check declares its payload class, location, tier and WSTG reference.

[[attestra/automated_vapt/testing/injection_catalog.py#CHECKS]] lists them; [[attestra/automated_vapt/testing/injection_catalog.py#validate_catalog]] rejects duplicates, bad tiers and destructive, time-based or metadata payloads. [[attestra/automated_vapt/testing/injection_catalog.py#classify_outcome]] separates reflected, error signature, filtered, not reflected, blocked and inconclusive. [[attestra/automated_vapt/testing/injection_tests.py#run]] now tags each probe row with its check, outcome and response class, returns `validity_samples`, skips the boolean pair once the edge blocked, and reports `BLOCKED` instead of a silent pass. [[attestra/automated_vapt/testing/injection_catalog.py#coverage_rows]] feeds coverage reporting.

## Server-side sink indicators

Catalogue id `SSIND`, tier T0. Suspicions only, never payloads.

[[attestra/automated_vapt/testing/server_side_indicators.py#run]] reviews captured URLs ([[attestra/automated_vapt/testing/server_side_indicators.py#url_param_suspicions]]), imported API operations ([[attestra/automated_vapt/testing/server_side_indicators.py#inventory_suspicions]]) and captured responses ([[attestra/automated_vapt/testing/server_side_indicators.py#response_suspicions]]) for SSRF, XXE and SSTI sink indicators. Without captured traffic and with the web-safe flag on, it GETs at most 4 same-origin pages. It never sends an SSRF, XXE or template payload or an internal/metadata request. Suspicions make the case INCONCLUSIVE for manual review.

## GraphQL probe

Catalogue id `GRAPHQL` (WSTG-APIT-01), tier T1, at most 10 requests.

[[attestra/automated_vapt/testing/graphql_tests.py#candidate_urls]] uses tagged JS endpoints, imported operations and default paths. [[attestra/automated_vapt/testing/graphql_tests.py#run]] sends one `__typename` detection per candidate and one bounded introspection query as `GET ?query=` (POST only when the profile allows it and GET was refused). [[attestra/automated_vapt/testing/graphql_tests.py#assert_read_only]] refuses mutations, subscriptions and depth over 8, and bodies are read through a 512 KB cap. Disabled introspection is not a vulnerability. [[attestra/automated_vapt/testing/graphql_tests.py#root_field_plan]] picks argument-free root fields for a primary-versus-secondary identity comparison; without a second identity that part is NOT_TESTED.

## API posture

Catalogue id `APIPOST`, tier T0. Never a burst.

[[attestra/automated_vapt/testing/api_posture_tests.py#run]] reads rate-limit headers ([[attestra/automated_vapt/testing/api_posture_tests.py#rate_limit_headers]]) and version headers from responses T01 already captured, and builds an API version inventory ([[attestra/automated_vapt/testing/api_posture_tests.py#versions_in_url]]) from captured, JS-discovered and imported paths. Only without captured traffic and with the web-safe flag on does it send up to 3 GETs. Missing headers are informational; the case never raises a finding.

## API inventory import

OpenAPI 3.0/3.1, Swagger 2.0 (JSON or YAML), Postman v2.1 and HAR 1.2, behind `ATTESTRA_API_IMPORT_ENABLED`.

[[attestra/automated_vapt/api_inventory/__init__.py#parse_spec]] size-checks, decodes and detects the format, then calls [[attestra/automated_vapt/api_inventory/openapi.py#parse_openapi]], [[attestra/automated_vapt/api_inventory/postman.py#parse_postman]] or [[attestra/automated_vapt/api_inventory/har.py#parse_har]]. Results are a normalised [[attestra/automated_vapt/api_inventory/model.py#ApiInventory]] of [[attestra/automated_vapt/api_inventory/model.py#ApiOperation]] rows with a SHA-256, duplicates merged, out-of-scope servers marked, and unsupported constructs (external refs, callbacks, links, webhooks, scripts, websocket entries, unresolved variables) listed explicitly. HAR imports keep parameter and header names only, never values.

[[attestra/automated_vapt/core/capture_urls.py#build_capture_urls]] merges only GET/HEAD operations without path templates, in scope and without state-changing words; mutating operations never enter capture or replay. [[attestra/automated_vapt/core/js_api_discovery.py#endpoints_from_inventory]] turns operations into `source="spec"` endpoints and [[attestra/automated_vapt/core/js_api_discovery.py#ApiEndpoint]] tags GraphQL paths. [[attestra/automated_vapt/api_inventory/model.py#compute_coverage]] produces `result_json.api_coverage` (tested, untested, excluded mutating, excluded templated, out of scope).

## API inventory storage

Versioned documents in the `api_inventories` collection.

[[attestra/automated_vapt/api_inventory/store.py#save]] stores one document per tenant, engagement, asset and SHA-256: the same bytes return the existing version, a new file becomes the next version. [[attestra/automated_vapt/api_inventory/store.py#latest]] and [[attestra/automated_vapt/api_inventory/store.py#list_versions]] always filter by tenant, engagement and asset. [[attestra/automated_vapt/api_inventory/store.py#MemoryBackend]] backs the unit tests.

## API spec upload route

`POST /api/automated-vapt/engagements/{eid}/assets/{aid}/api-spec` (multipart `file`), a matching GET, and the UI form route.

[[attestra/automated_vapt/routes.py#upload_api_spec]] and [[attestra/automated_vapt/routes.py#ui_upload_api_spec]] require `asset.write`, engagement access, a web app or API target, and the import flag; [[attestra/automated_vapt/routes.py#list_api_specs]] needs `engagement.read`. The import is audited as `api_spec.import`. The target page shows the upload card only when `ui.target_page` passes `api_import_enabled`.
