# AASI V5.1 — Native target-bound egress helpers

Design note for `attestra/scanner_runtime/egress.py`. Adapters may call these helpers before a native (shared-venv) scanner run. They do **not** weaken engagement authorization, ownership, or the dispatch gate.

## Why this exists

A shared Python venv / host process is **not** network isolation. Digest-pinned Docker with `--add-host` and no unnecessary egress remains the preferred execution path. When an adapter must run a tool on the host (local CLI / shared venv), it should still:

1. Re-check that the DNS-pinned destination is allowed (block cloud metadata and other SSRF ranges).
2. Spawn the child with a sanitized environment (no host AWS / Mongo / session secrets).

**`HTTP_PROXY` / `HTTPS_PROXY` alone are insufficient.** Pointing traffic at a proxy does not prove the process cannot reach metadata endpoints, sibling tenants, or out-of-scope hosts. Treat proxy-only controls as fail-open theatre; fail closed unless the pin is valid and the runtime confines egress (container network policy, allow-listed connect, or equivalent).

## API

| Helper | Role |
|---|---|
| `assert_target_egress_allowed(pinned, *, allow_private)` | Raise `AuthorizationError` if the pin is missing/empty or `pinned.ip` fails `validate_resolved_ips` (metadata / CGNAT / link-local always blocked). |
| `scanner_process_env(*, extra=None, base=None)` | Build env for `run_process` / subprocess: strip AWS / Mongo / `ATTESTRA_SESSION*` and secret-shaped keys; keep PATH and system essentials; set `ATTESTRA_SCANNER_JOB=1`. |

### `assert_target_egress_allowed`

- Input is a gate-produced `PinnedTarget` (from `attestra.runner.dns_pin`).
- Reuses `attestra.runner.authorization.validate_resolved_ips` — same blocked CIDRs as DNS pin (`169.254.0.0/16`, CGNAT `100.64.0.0/10`, AWS IPv6 metadata, etc.).
- `allow_private=True` only relaxes RFC1918-style destinations already accepted by that helper; it never allows metadata.
- Missing / blank `host` or `ip` → refuse (`egress refused: pinned target missing`).
- Does **not** replace `authorize_target` / `gate.check`. Call after the pin exists.

### `scanner_process_env`

- Default `base` is `os.environ`.
- Drops `AWS_*`, `MONGO*` / `MONGODB*`, `ATTESTRA_SESSION*`, and keys whose names look like secrets (`SECRET`, `PASSWORD`, `TOKEN`, `API_KEY`, …).
- Keeps PATH and common OS essentials; keeps non-secret `ATTESTRA_*` (image digests, timeouts, flags).
- Always sets `ATTESTRA_SCANNER_JOB=1` (wins over `extra`).
- `extra` may add tool-specific vars; secret-shaped keys in `extra` are still dropped.
- Does **not** forward `HTTP_PROXY` by default — adapters that truly need a controlled proxy must pass it explicitly in `extra` and still satisfy pin checks.

## Integration (light)

Adapters (Garak / Promptfoo / SafeLabs / PyRIT / others) **may** call:

```python
from attestra.scanner_runtime.egress import assert_target_egress_allowed, scanner_process_env

assert_target_egress_allowed(pin, allow_private=scope.allow_private)
env = scanner_process_env(extra={"SOME_TOOL_FLAG": "1"})
# run_process(argv, env=env, ...)
```

Wiring into every adapter is intentionally deferred — this module is the shared primitive.

## Fail-closed guidance

| Situation | Expected behaviour |
|---|---|
| No `PinnedTarget` / empty IP | Refuse start |
| Pin resolves / points at `169.254.169.254` (or other blocked CIDR) | Refuse start |
| Shared venv without container egress policy | Prefer Docker; if native, still assert pin + sanitized env; do not claim isolation |
| Only `HTTP_PROXY` configured | Insufficient — do not treat as egress confinement |
| Authorization / ownership / signed RoE missing | Existing gate still refuses (unchanged) |

## Tests

`tests/scanner_runtime/test_egress.py` — public pin OK; missing/empty pin refuse; metadata and CGNAT blocked even with `allow_private`; private IP only when allowed; env strips AWS/Mongo/session secrets; job marker set; `HTTP_PROXY` not auto-forwarded.

## Out of scope

- Changing Docker `--network` / iptables / eBPF confinement
- Weakening `BLOCKED_CIDRS` or ownership / signed-authorization gates
- Mandatory adapter call sites (parent / later prompts)
