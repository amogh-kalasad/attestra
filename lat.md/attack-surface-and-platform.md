# Attack surface and platform

Work package 4 adds passive attack-surface discovery, tenant hardening, worker operations metrics and an adapter SDK. Every new behaviour is behind a flag that defaults to off, and discovery only ever produces review candidates, never scan targets.

## Tenant strict mode

Strict tenant mode makes a repository built without an explicit tenant scope fail closed instead of seeing every tenant.

[[attestra/persistence/mongo/tenant.py#effective_scope]] resolves the scope a repository receives. `SYSTEM_SCOPE` is an explicit "all tenants" sentinel for system jobs and platform admins; plain `None` keeps the legacy unscoped behaviour while `TENANT_STRICT` is off, and becomes an empty scope plus a warning when it is on. [[attestra/persistence/mongo/repositories/base.py]] applies it in the constructor, so every repository inherits the rule. The sentinel is an empty frozenset subclass, so code that treats it as a plain set still matches nothing.

Call sites that pass `None` today (`services.tenant_ids_for`, the membership bridge, admin principals) must move to `SYSTEM_SCOPE` before the flag is flipped (see `attestra_plan/WIRING_WP4.md`).

## Tenant isolation and action matrix tests

These tests pin the role permission matrix and cross-tenant behaviour of the HTTP routes.

`tests/auth/test_action_matrix.py` checks every role against every permission and introspects each API and discovery route for its required permission. `tests/auth/test_tenant_isolation_routes.py` is Mongo-backed and skips when MongoDB is unavailable or needs authentication; `tests/persistence/test_tenant_strict.py` covers the sentinel and strict-mode rules without a database.

## Passive discovery

Passive discovery collects subdomain names for an apex that is already in an engagement's authorized scope, merges them deterministically and stores them as pending candidates.

[[attestra/discovery/pipeline.py#merge_observations]] normalizes names (IDNA, no IPs, wildcards or underscores), drops anything outside the apex or on the deny list, and merges sources. [[attestra/discovery/pipeline.py#run_passive_discovery]] runs only when `DISCOVERY_ENABLED` is on and records per-source errors instead of failing. Certificate transparency suggestions from [[attestra/runner/ct_suggestions.py]] are recorded through the same path. No provider API keys are used and no real domain is contacted by tests.

## Candidate store and approval

Candidates live in the `discovery_candidates` collection and are never scannable until a person approves them into a normal asset.

[[attestra/discovery/candidates.py#upsert_candidates]] is idempotent and keeps the review state; confidence comes from weighted sources. [[attestra/discovery/routes.py]] exposes list, approve and reject under `/api/engagements/{eid}/discovery`; approval needs the asset-write permission, re-checks the authorized scope, and creates the asset with intrusive testing off. The router returns 404 while the flag is off and for other tenants' candidates. The `_discovery_candidates.html` partial renders the list with text-only DOM writes.

## DNS chain and takeover fingerprints

CNAME chains are followed through an injected resolver, and takeover risk is labelled from passive evidence only.

[[attestra/discovery/dns_chain.py#follow_cname_chain]] detects loops, truncation, NXDOMAIN and SERVFAIL, and [[attestra/discovery/dns_chain.py#detect_wildcard]] probes a deterministic random label. [[attestra/discovery/takeover_fingerprints.py#assess]] returns suspected, not suspected or inconclusive from the signatures in `attestra/discovery/data/takeover_signatures.yaml`. A provider error page without a matching CNAME is never suspected, wildcard or resolver failures are inconclusive, and nothing ever tries to claim a resource.

## Snapshots and change events

Asset snapshots are append-only records of DNS, certificate, port, technology and header state, and each difference becomes a deduplicated change event.

[[attestra/discovery/snapshots.py#append_snapshot]] only inserts, skips an identical consecutive snapshot, links to the previous one, and stores change events from [[attestra/discovery/snapshots.py#diff_snapshots]] with a stable dedup key and attribution (source, actor, scan run).

## Asset change alerts

Significant asset changes are emailed once per change to the tenant's header-change recipients.

[[attestra/alerts/asset_changes.py#monitor_and_alert]] filters significant events (address records, certificate identity, ports, technology, headers), dedups them and calls `notify_asset_changes` in [[attestra/alerts/service.py]], which uses the existing send-once store. It never raises into a scan pipeline. [[attestra/alerts/headers.py]] gives header changes the same dedup keys.

## Cloud correlation and Prowler disclosure

Hostnames and CNAME targets are matched against known cloud storage and hosting patterns by string only, and the Prowler adapter discloses the read-only permissions it needs.

[[attestra/discovery/cloud_correlation.py#correlate]] covers AWS, Azure, GCP, DigitalOcean and Cloudflare R2 patterns. [[attestra/runner/scanners/prowler.py#permission_disclosure]] lists the read-only grants per provider and is attached to each Prowler result; Attestra does not store the cloud credentials.

## Discovery adapters

The subfinder, dnsx and httpx-probe adapters run ProjectDiscovery tools with strict rate and time limits, and their importers emit observations, never findings.

[[attestra/runner/scanners/subfinder.py]] passes an empty provider config so no API keys are read. [[attestra/runner/scanners/dnsx.py]] and [[attestra/runner/scanners/httpx_probe.py]] take at most 500 validated hosts from a host file; the httpx binary must be `httpx-toolkit` (or `ATTESTRA_HTTPX_BIN`), never the Python `httpx` client. The importers in `attestra/importers/` (subfinder, dnsx, httpx_probe) tolerate a truncated last line and reject malformed output. Registry and parser wiring is an integration step.

## Adapter SDK

The adapter SDK describes each scanner adapter's licence, safety tier, egress and resources, and checks a common contract.

[[attestra/runner/scanners/sdk.py]] defines `AdapterMeta`, safety tiers T0 to T3 and `contract_problems`. [[attestra/runner/scanners/base.py]] stamps `adapter_version` and the tool version into each result, resolves digest-pinned images from `ATTESTRA_IMAGE_<KEY>`, and exposes `health()`. `scripts/new_adapter.py` scaffolds a new adapter that passes the contract tests.

## Queue metrics and stuck jobs

The worker exports queue age, job duration, outcomes, retries, cancellations, busy slots and stuck jobs as Prometheus metrics.

[[attestra/observability.py]] gained gauges and the `record_job_*` helpers, plus `instrument_engine`, which is a no-op while OpenTelemetry is off. [[attestra/jobs/durable.py#run_one_job]] records outcome and duration, and [[attestra/jobs/durable.py#stuck_jobs]] lists running jobs whose heartbeat is older than `JOB_STALE_HEARTBEAT_S`. The worker pool refreshes the stuck gauge every minute, and [[attestra/jobs/launcher.py#stuck_job_summary]] feeds a UI badge. SLOs and alert rules are in `docs/upgrade/SLO.md`; `deploy/loadtest/attestra.js` refuses non-local targets unless explicitly allowed.

## Maintenance tick

The maintenance tick runs registered periodic tasks from the worker's housekeeping pass when `MAINTENANCE_ENABLED` is on.

[[attestra/jobs/maintenance.py#tick]] runs due tasks under a non-blocking lock, isolates failures and records an outcome metric per task. The built-in task refreshes threat-intel feeds when the feed store is installed. Last-run times are per process, so several workers each run the task.
