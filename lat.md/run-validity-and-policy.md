# Run validity and policy

WP1 foundation for the automated security-test engine: response classification, run validity, server-side intrusive decisions, and per-case engagement readiness.

WAF, CDN challenge, rate-limit, and expired-session answers never count as a passed security control.

## Response classifier

[[attestra/automated_vapt/core/response_classifier.py#classify_response]] maps status, headers, and body to one `ResponseClass` with value-free reasons and a confidence.

Order: network failure, challenge (strong markers at any status, weak captcha markers only at 4xx/5xx), rate limit (429 / `retry-after`), WAF block (Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5, ModSecurity, Barracuda markers and WAF headers), origin error, redirect to a login path (`AUTH_REDIRECT`, or `AUTH_EXPIRED` for an authenticated request), 401/403 application denials, 404/410, then 2xx (a login form on an authenticated 2xx is `AUTH_EXPIRED`). A bare `cf-ray` header is recorded but is not a block.

Only `APP_AUTH_DENIED` and `AUTH_REDIRECT` are security-control evidence; [[attestra/automated_vapt/core/response_classifier.py#proves_enforcement]] also needs the authenticated request to return `APP_OK`. Modules attach `validity_samples` (classification dicts) and, when nothing was proven, `status_hint` BLOCKED / INCONCLUSIVE plus a `skip_reason` so orchestrators without the run-validity wiring record SKIPPED rather than PASSED. T03 and T07 no longer pass on a WAF 403 and no longer treat "not enforced" alone as a finding.

## Run validity

[[attestra/automated_vapt/core/run_validity.py#evaluate]] turns samples into VALID, PARTIALLY_BLOCKED, CHALLENGE_DETECTED, RATE_LIMITED, AUTH_EXPIRED, NETWORK_FAILED, or INCONCLUSIVE.

Precedence: 80% network failures, then session loss (guard or `AUTH_EXPIRED` sample), challenge, rate limit, WAF block, too few usable samples, VALID. `CaseValidity` accumulates per case; `aggregate_run` produces the persisted `{state, reasons, sample_count, by_class, affected_cases, computed_at, version: "rv1"}`. Rows written before WP1 read as `NOT_COMPUTED`.

[[attestra/automated_vapt/core/run_validity.py#gate_case_status]] returns PASSED only for a VALID case with no hint and no finding (legacy modules without samples keep PASSED). [[attestra/automated_vapt/core/run_validity.py#cap_validation_status]] downgrades CONFIRMED to POTENTIAL when the case is not VALID. AASI Phase 2: [[attestra/automated_vapt/core/run_validity.py#ai_tool_outcome_to_status]] maps empty / refused / rate-limited / failed AI-tool outcomes to ``NOT_TESTED`` (never PASSED); adapters with HTTP samples still use ``RATE_LIMITED`` validity state + gating. See [[aasi#Phase 2 coverage and AI-tool validity]].

## Intrusive policy

[[attestra/automated_vapt/core/intrusive_policy.py#decide_from_policy_input]] decides SSRF, UPLOAD, XSSSTORE, and T22 from server-side facts; `APP_ENV` is no longer used for target gating.

Allow needs all of: the per-test flag, an active or intrusive profile, the scope policy allowing the engagement/asset as an active profile, an asset environment in the allowlist (default `dev,demo`; production, prod, live, prd are always refused and refusing to parse), and a cleanup plan acknowledgement for UPLOAD and XSSSTORE. Any error denies. Modules read the stored decision with [[attestra/automated_vapt/core/intrusive_policy.py#decision_from_ctx]], which re-checks the flag and forbidden environments; no stored decision means deny. `force=True` is honoured only for in-process lab clients. T22 sends need the flag and the decision; an explicit `dry_run=False` cannot override them.

## Engagement readiness

[[attestra/automated_vapt/core/authorization_guard.py#readiness_problems]] mirrors the scope policy: halted or non-active status, no currently valid signed authorization, authorization not covering the asset environment, or outside the testing window.

[[attestra/automated_vapt/core/authorization_guard.py#assert_engagement_ready_for_case]] reloads the engagement before each case, re-runs those checks, and asks the scope policy the same question the scanner gate asks (scan rate limit excluded). Failures raise `ReadinessError` with a value-free code that becomes the case's NOT_TESTED reason.

## Policy parity tests

`tests/runner/test_opa_policy.py` keeps the Python policy and `scope.rego` in step; its base input carries every field the policy requires, including `ownership_required` and `authorization_required`.

## Checklist catalog

`attestra/auth_web/data/checklist_catalog.yaml` is the single catalog of WSTG 4.2 and ASVS 4.0.3 items with automation levels and mappings from automated test ids and scanner rules.

[[attestra/auth_web/checklist_catalog.py#validate_catalog]] reports duplicate refs or aliases, orphan or manual targets, registered test ids without a mapping or exception, legacy SSRF mappings, and bad regexes. SSRF maps to WSTG-INPV-19; `WSTG-BUSL-09-legacy-ssrf` is an alias for old rows.

## JWT posture

[[attestra/automated_vapt/testing/jwt_posture.py#assess_tokens]] reviews JWTs offline for algorithm, header, claim, and lifetime weaknesses.

Checks: weak or none algorithms, missing signature, self-referencing key headers, suspicious `kid`, missing `exp`/`aud`/`iss`, lifetimes over 24 hours, and sensitive claim names. Output uses hashed labels and claim names only, never token or claim values. SESSION reports it and treats high issues as a finding.

## Session lifecycle

[[attestra/automated_vapt/testing/session_lifecycle.py#run]] (case `SESSLIFE`) checks session id rotation on login, invalidation on logout, and expiry.

Rotation and logout run only against lab mock clients; on a live engagement session the case is passive (cookie and JWT lifetimes) and reports INCONCLUSIVE rather than PASSED, with the identity recorded as `profile#N`.

## OIDC metadata

[[attestra/automated_vapt/testing/oidc_metadata_tests.py#run]] (case `OIDCMETA`) sends one anonymous GET to `/.well-known/openid-configuration` on the target origin and reviews it offline.

It flags implicit or ROPC flows, missing PKCE S256, wildcard redirect metadata, non-TLS endpoints, and `alg: none`. Missing discovery is NOT_TESTED; a challenge or WAF answer is BLOCKED; an off-origin discovery URL is refused.

## Identity comparison

[[attestra/automated_vapt/testing/tenant_isolation_tests.py#compare_identities]] compares the same URLs as two engagement identities.

Tenant or owner values seen by only one identity prove the identities differ; the other identity seeing them is cross-identity access. T06 is INCONCLUSIVE when identities cannot be told apart. BIZ no longer reports an unusable session or an identical shared body as a finding.

## XSS reflection context

[[attestra/automated_vapt/testing/_reflection.py#classify_reflection_context]] labels where a canary lands (HTML text, quoted or unquoted attribute, URL attribute, event handler, script, style, comment, tag name) so reflected XSS findings name the context and whether a breakout is possible.

## Planner

[[attestra/automated_vapt/core/planner.py#plan_cases]] orders cases passive first, then authorization comparisons, then intrusive writes, and marks each run, skip, or defer with a reason.

[[attestra/automated_vapt/core/planner.py#rate_profile]] picks a one-request-per-second profile when a CDN/WAF was detected or the previous run was blocked. It sends no traffic and is opt-in.

## Guided business-flow plans

[[attestra/automated_vapt/guided/plans.py#list_plans]] lists evidence-only templates (workflow skipping, parameter tampering, replay limits, approval bypass, object ownership) for a human tester. [[attestra/automated_vapt/guided/plans.py#record_result]] requires evidence for PASSED or FINDING. Nothing calls this module until the UI wiring lands.
