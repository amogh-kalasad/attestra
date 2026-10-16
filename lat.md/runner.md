# Runner plane

Attestra can dispatch scanners under engagement scope. Imports remain the evidence path; runners write raw files then call [[attestra/services.py#import_results]].

## Scope authorization

Targets must match engagement assets and deny ScopeRules before allow-list checks.

[[attestra/runner/authorization.py#scope_for_engagement]] builds [[attestra/runner/authorization.py#AuthorizedScope]] from valid authorizations and assets. [[attestra/runner/authorization.py#authorize_target]] validates URL/path/image/host. Exact image match via [[attestra/runner/authorization.py#_image_allowed]]. SSRF policy: [[attestra/runner/authorization.py#validate_resolved_ips]], [[attestra/runner/authorization.py#BLOCKED_CIDRS]].

A private IP target is reachable only after the owner confirmed it ([[authorization#Target ownership#Owner confirm for private IPs]]). [[attestra/runner/authorization.py#scope_for_engagement]] then adds its host to `private_ok_hosts`. Blocked ranges stay refused at pin time.

## DNS pin and safe HTTP

Resolve once, pin IP, re-authorize every redirect.

[[attestra/runner/dns_pin.py#pin_url]] returns [[attestra/runner/dns_pin.py#PinnedTarget]]. [[attestra/runner/http_safe.py#safe_get]] / [[attestra/runner/http_safe.py#safe_request]] connect only to the pinned IP, use SNI for `pin.host` on HTTPS, and refuse out-of-scope redirects with an audit entry. `follow_redirects=False` returns the redirect response without following.

## Dispatch gate

Every scan is checked at enqueue and again when a job resumes.

[[attestra/runner/gate.py#check]] enforces authorization, engagement window, intrusive/active profile, per-asset rate limit, ownership verification ([[attestra/runner/ownership.py#is_verified]]), tool fits the target kind, and target pin. Failures raise [[attestra/runner/gate.py#GateError]] and audit `scan.refused`.

[[attestra/runner/gate.py#tool_kind_problem]] refuses a tool that cannot scan the target kind and names the tools that can. Web tools (zap, nuclei, testssl, naabu) take web app, API or host targets. Code tools (semgrep, gitleaks, checkov) take repos. Trivy takes repos or images. testssl is also refused for an `http://` target, because there is no TLS to test.

## Scanners and jobs

Adapters build argv without a shell; durable jobs run them and import raw output.

Adapters live under `attestra/runner/scanners/` and are looked up by [[attestra/runner/scanners/registry.py#get_adapter]]. [[attestra/jobs/durable.py#run_one_job]] claims work, re-checks the gate, hashes full raw output, and imports. Kill switch: [[attestra/services.py#halt_engagement]] sets `cancel_requested` and [[attestra/jobs/durable.py#signal_engagement_cancel]]. CLI: `attestra worker`.

The job commits before the scanner starts, so the page shows Running and SQLite is not write-locked during the scan. If the adapter raises, or returns an error (no report, unreadable report, timeout, tool missing), [[attestra/jobs/durable.py#_fail_run]] marks the run failed with the reason, audits `scan.failed` and does not retry. Import errors are also saved as the run's reason. Findings with no matching target (for example a repo file path) are linked to the scanned target through `default_asset_id` in [[attestra/services.py#import_results]].

## Scanner runs

How an adapter runs one scanner: in Docker when an image is set, else the local tool, with a timeout and a check that the report can be read.

[[attestra/runner/scanners/base.py#ScannerAdapter#scan]] deletes any old report first, so a report from an earlier attempt is never imported. It uses Docker when [[attestra/runner/scanners/base.py#ScannerAdapter#uses_docker]] is true (Docker is found and a real digest-pinned image is set, not a placeholder, see [[attestra/config.py#image_is_placeholder]]). Otherwise it runs the local tool. If neither works, the run returns a clear error from [[attestra/runner/scanners/base.py#ScannerAdapter#unavailable_reason]].

Each image can be set with `ATTESTRA_IMAGE_<TOOL>`. Containers are built by [[attestra/runner/scanners/base.py#docker_run_argv]]: removed after the run, given a name so they can be stopped, and with the target host pinned to the gate's IP.

### Timeouts and output

Each tool has its own time limit, and scanner output goes to temporary files so a large output cannot hang the run.

[[attestra/runner/scanners/base.py#ScannerAdapter#timeout_s]] uses `ATTESTRA_SCANNER_TIMEOUT_<TOOL>`, else the larger of the tool default and [[attestra/config.py#SCANNER_TIMEOUT_S]]. ZAP has a 30 minute default because the active scan is long. On timeout or cancel, [[attestra/runner/scanners/base.py#run_process]] kills the process tree and [[attestra/runner/scanners/base.py#stop_container]] removes the container.

[[attestra/runner/scanners/base.py#run_process]] writes stdout and stderr to temporary files, not pipes, so a tool that prints a lot does not block. On Windows the worker opens no console window.

### Report check

A run succeeds only when the report file exists and the importer can read it. A non-zero exit code alone is not a failure.

[[attestra/runner/scanners/base.py#ScannerAdapter#validate_report]] parses the report with the matching importer. If the file is missing or cannot be parsed, the result carries an error with the exit code and the end of stderr. A valid report counts as success even when the tool exits 1 or 2 (ZAP on WARN or FAIL, semgrep on findings). Naabu may write an empty report when no ports are open.

### ZAP

ZAP runs only in Docker. The report folder is mounted at `/zap/wrk`, the only place the ZAP scripts write their JSON report.

[[attestra/runner/scanners/zap.py#ZapAdapter]] runs `zap-baseline.py` for the baseline profile and `zap-full-scan.py` for the active profile ([[attestra/runner/scanners/zap.py#zap_script]]). The target host is pinned to the gate's IP. After the run, [[attestra/runner/scanners/zap.py#ZapAdapter#quarantine_if_out_of_scope]] checks every site and alert URL against scope and quarantines the report if any is outside.

### webcheck (passive headers and DNS)

Pure-Python adapter for security headers, HSTS, security.txt, and DNS posture.

[[attestra/runner/scanners/webcheck.py#WebcheckAdapter]] is registered as `webcheck` in [[attestra/runner/scanners/registry.py#_ADAPTERS]] and listed in [[attestra/runner/gate.py#URL_TOOLS]]. It requires `scope`, uses only [[attestra/runner/http_safe.py#safe_get]], writes `webcheck.json`, and merges [[attestra/runner/scanners/webcheck_dns.py#dns_checks]] into the same report. [[attestra/jobs/durable.py#run_one_job]] passes `scope=` for webcheck like zap.

R10 Referrer-Policy ([[attestra/runner/scanners/webcheck.py#check_referrer_policy]]): no finding for `no-referrer` / `same-origin`; Info for `strict-origin` / `strict-origin-when-cross-origin`; Low for weaker values or a missing header.

R13 HSTS preload ([[attestra/runner/scanners/webcheck.py#check_hsts_not_preloaded]]): off unless `ATTESTRA_HSTS_PRELOAD_LOOKUP=1`; finding only for hstspreload.org statuses `unknown` / `pending` / `rejected` / `removed`; lookup failures become a report note (`preload lookup failed`) with no finding.

#### CSP analysis (C10)

Parse Content-Security-Policy and emit one finding per issue with directive evidence.

[[attestra/runner/scanners/webcheck.py#check_csp_policy]] flags `'unsafe-inline'`, `'unsafe-eval'`, bare `*` wildcards, `http:` sources, and missing `default-src` / `object-src` / `base-uri` / `frame-ancestors`. Check ids stay semantic (`csp:{directive}:{issue}`); fingerprint `variant` uses the matching ZAP Baseline `alertRef` when known (`10055-5` / `10055-6` / `10055-10`) and `param=Content-Security-Policy` so webcheck and ZAP merge. [[attestra/runner/scanners/webcheck.py#check_csp_base_uri]] remains a thin wrapper over the missing base-uri finding.

#### Cookie flags (C9)

One finding per cookie per missing Secure, HttpOnly, or SameSite on the primary response.

[[attestra/runner/scanners/webcheck.py#check_cookies]] uses headers already fetched (no extra requests). Variant / finding id is `cookie:{name}:{flag}`. [[attestra/runner/http_safe.py#safe_request]] keeps every Set-Cookie line (joined with newlines).

Session vs non-session severity: a cookie is a **session cookie** when it has neither `Max-Age` nor `Expires`, or its name matches session-like names (`session`, `sid`, `jsessionid`, `token`, `jwt`, `csrf`, …). Session cookies → Low for missing flags. Clearly non-session cookies (Max-Age/Expires set and a non-session name) → Info. Fully flagged cookies become C5 passed rows; no Set-Cookie → one skipped "not tested" row.

### testssl baseline flags

[[attestra/runner/scanners/testssl.py#_flags]] for `profile=baseline` runs config checks only (`-p -S -P -f -H`) and never passes `-U` / `--vulnerable`. Non-baseline keeps the default full run (includes vulnerability checks).

