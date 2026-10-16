# Webhooks and workflow rules

Per-tenant outbound webhooks for key events, plus simple automation rules. Code: `attestra/webhooks/`. Tables: `webhook_endpoints`, `webhook_deliveries`, `workflow_rules`, `finding_assignments` (migration `0013_proof_webhooks`, with row-level security policies). All endpoints need the `webhook.manage` permission (admin, lead) and are limited to the caller's tenants.

## Events

| Event | Sent when |
|---|---|
| `finding.created` | A new finding is created by an import |
| `finding.status_changed` | A finding changes status (payload has `from` and `status`) |
| `finding.commented` | A comment is added on a finding (`comment_id`, `author_user_id`; body is not sent) |
| `retest.completed` | A retest is finalized (`retest_id`, `result`) |
| `report.signed` | A report is signed (`report_id`, `kind`, `version`, `sha256`, `signed_by`) |
| `cert.expiring` | Daily job: saved cert end date crossed the 30, 14 or 7 day band (`target`, `days_left`, `end_date`, `band`, `asset_id`, `engagement_id`). No secrets. Each band once per certificate. |

Finding payloads carry `finding_id`, `engagement_id`, `title`, `severity`, `status`, `risk_score`, `location`. Emitting never breaks the business action that triggered it. Run `attestra cert-expiry-check` daily (reads saved scan end dates only; no new network).

## Endpoints

- `POST /api/webhooks` with `tenant_id`, `url`, `name`, `format` (`json`, `slack`, `teams`) and `events` (empty = all). The response includes the signing `secret` **once**; store it then.
- `GET /api/webhooks`, `DELETE /api/webhooks/{id}` (deactivates), `GET /api/webhooks/{id}/deliveries` (last 200).
- URL rules (`guard.py`): https only, no credentials in the URL, no `localhost` / `.local` / `.internal`, and every resolved IP must be public (same check the runner uses). The URL is re-checked at send time and the connection goes to the validated IP with certificate checking for the host name; redirects are not followed.

## Formats and signing

- `json`: `{"id": <delivery id>, "event": ..., "data": {...}}`
- `slack`: incoming-webhook `text` + one section block.
- `teams`: message with an Adaptive Card (title + facts).

Every request has headers `X-Attestra-Event`, `X-Attestra-Delivery`, `X-Attestra-Timestamp` and `X-Attestra-Signature: sha256=<hex>`, where the hex is HMAC-SHA256 with the endpoint secret over `<timestamp>.<raw body>`. To verify: recompute it, compare in constant time, and reject timestamps more than 5 minutes old (`formats.verify` does this).

## Delivery and retries

Events are queued as `pending` deliveries. `POST /api/webhooks/dispatch` sends due deliveries (up to 50 per call) for the caller's tenants; there is no background scheduler yet, so call it from a cron or worker. A 2xx response is `delivered`. Otherwise it retries after 30 s, 2 min, 10 min, 30 min and 2 h, and is marked `failed` after 6 attempts. Each delivery records attempts, last status code and last error.

## Workflow rules

`POST /api/workflow-rules` with `tenant_id`, `action` and optional filters `event`, `min_severity` (default `info`), `status`. `GET /api/workflow-rules` lists them, `DELETE /api/workflow-rules/{id}` deactivates one. Rules run on finding events only:

- `notify`: send to `endpoint_id` (must belong to the same tenant), even if that endpoint is not subscribed to the event.
- `assign`: record a `FindingAssignment` to `assignee` (audited as `finding.assigned`).
- `ticket`: create or sync a ticket through the configured ticket integration; failures are audited as `workflow.ticket_skipped`.

Tests: `tests/test_webhooks.py`.