# Proof of exploit and replay

Attach proof to a finding (an HTTP request/response pair or a screenshot), then replay the saved request on retest to check whether the issue is fixed. Code: `attestra/proof/`. Tables: `proof_replays` (migration `0013_proof_webhooks`); proof itself is stored as normal evidence.

## Attaching proof

| Endpoint | Permission | Notes |
|---|---|---|
| `POST /api/findings/{id}/proof/http` | `finding.write` | Structured fields (`method`, `url`, headers, bodies, `status`) or `raw_request` / `raw_response` text. Optional `match`: text whose presence in the response proves the issue. |
| `POST /api/findings/{id}/proof/screenshot` | `finding.write` | Multipart `file` (PNG, JPEG, GIF or WebP only, checked by magic bytes) + `note`. |
| `GET /api/findings/{id}/proof` | `finding.read` | Lists proof evidence and all replays. |

- Before storing, credentials are redacted (`proof/redact.py`): `Authorization`, `Cookie`, `Set-Cookie`, API-key and CSRF headers, and any header, query parameter or JSON/form field whose name looks like a token, secret, password, session or key. Values become `[REDACTED]`.
- Proof goes through `services.add_evidence`, so it is hashed (SHA-256), masked and written to the audit log like any other evidence. Kinds: `http_pair` and `screenshot`.
- **Auto-capture:** on a ZAP or Nuclei import, if the tool output contains the request/response, one redacted pair is attached to each matching finding that has none yet (`proof/capture.py`). A capture failure never fails the import.

## Replay on retest

`POST /api/findings/{id}/proof/replay` (permission `retest.manage`), body `{"evidence_id": ..., "retest_id": optional, "allow_unsafe_methods": false}`.

Safety checks, in order:
1. Engagement must not be halted.
2. The stored pair's hash must still match; tampered proof is refused.
3. Only `GET`, `HEAD`, `OPTIONS` by default. Other methods need `allow_unsafe_methods: true` **and** a lead or admin caller.
4. The URL must be in the engagement's authorized scope (`authorize_target`), and the host is resolved once and pinned (`pin_url`). The request connects to that IP only and never follows redirects (`webhooks/transport.py`), so DNS rebinding cannot move it. Refusals are audited as `proof.replay_refused`.
5. Redacted header values are not sent.

The result is compared with the original (`replay.compare`) and only *suggested*:
- `still_open`: the `match` text is still in the response, or same status and response at least 90% similar.
- `fixed`: the `match` text is gone, or the status code changed.
- `inconclusive`: no response, request failed, or the same status with a different body.

The replay response is saved as new `http_pair` evidence and audited (`proof.replay`).

## Confirming

`POST /api/proof/replays/{rid}/confirm` (permission `retest.manage`), body `{"result": "fixed|still_open|inconclusive", "note": ""}`.

A tester confirms or overrides the suggestion. This creates a retest if none was given and finalizes it through the normal retest workflow (with its false-close guard), so the finding status changes only there. A replay can be confirmed once. Audited as `proof.replay_confirm`; a `retest.completed` webhook event follows.

Tests: `tests/test_proof_replay.py`.