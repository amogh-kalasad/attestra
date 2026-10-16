# Runner plane

Attestra can dispatch scanners under engagement scope. Imports remain the evidence path; runners write raw files then call [[attestra/services.py#import_results]].

## Scope authorization

Targets must match engagement assets and deny ScopeRules before allow-list checks.

[[attestra/runner/authorization.py#scope_for_engagement]] builds [[attestra/runner/authorization.py#AuthorizedScope]] from valid authorizations and assets. [[attestra/runner/authorization.py#authorize_target]] validates URL/path/image/host. Exact image match via [[attestra/runner/authorization.py#_image_allowed]]. SSRF policy: [[attestra/runner/authorization.py#validate_resolved_ips]], [[attestra/runner/authorization.py#BLOCKED_CIDRS]].

## DNS pin and safe HTTP

Resolve once, pin IP, re-authorize every redirect.

[[attestra/runner/dns_pin.py#pin_url]] returns [[attestra/runner/dns_pin.py#PinnedTarget]]. [[attestra/runner/http_safe.py#safe_get]] / [[attestra/runner/http_safe.py#safe_request]] connect only to the pinned IP, use SNI for `pin.host` on HTTPS, and refuse out-of-scope redirects with an audit entry. `follow_redirects=False` returns the redirect response without following.

## Dispatch gate

Every scan is checked at enqueue and again when a job resumes.

[[attestra/runner/gate.py#check]] enforces authorization, engagement window, intrusive/active profile, per-asset rate limit, ownership verification, and target pin. Failures raise [[attestra/runner/gate.py#GateError]] and audit `scan.refused`.

## Scanners and jobs

Adapters build argv without a shell; durable jobs run them and import raw output.

Adapters live under [[attestra/runner/scanners]]. [[attestra/jobs/durable.py#run_one_job]] claims work, re-checks the gate, hashes full raw output, and imports. Kill switch: [[attestra/services.py#halt_engagement]] sets `cancel_requested` and [[attestra/jobs/durable.py#signal_engagement_cancel]]. CLI: `attestra worker`.

### webcheck (passive headers and DNS)

Pure-Python adapter for security headers, HSTS, security.txt, and DNS posture.

[[attestra/runner/scanners/webcheck.py#WebcheckAdapter]] is registered as `webcheck` in [[attestra/runner/scanners/registry.py#_ADAPTERS]] and listed in [[attestra/runner/gate.py#URL_TOOLS]]. It requires `scope`, uses only [[attestra/runner/http_safe.py#safe_get]], writes `webcheck.json`, and merges [[attestra/runner/scanners/webcheck_dns.py#dns_checks]] into the same report. [[attestra/jobs/durable.py#run_one_job]] passes `scope=` for webcheck like zap.

### testssl baseline flags

[[attestra/runner/scanners/testssl.py#_flags]] for `profile=baseline` runs config checks only (`-p -S -P -f -H`) and never passes `-U` / `--vulnerable`. Non-baseline keeps the default full run (includes vulnerability checks).
