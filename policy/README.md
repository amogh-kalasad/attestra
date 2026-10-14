# Attestra scope policy (Phase 6.3)

`scope.rego` holds the dispatch-gate decisions that used to be hard-coded in
`attestra/runner/gate.py`: valid authorization for the asset environment, test
window, intrusive/active profile flag, per-asset rate limit and ownership.
Target allow-listing and DNS pinning still run in Python after the policy allows.

## Engines

| `ATTESTRA_POLICY_ENGINE` | What happens |
| --- | --- |
| `python` (default) | Built-in mirror of `scope.rego` (`attestra/runner/policy.py`). No OPA needed. |
| `opa-http` | POST to `$ATTESTRA_OPA_URL/v1/data/attestra/scope/decision` (default `http://127.0.0.1:8181`). |
| `opa-cli` | `opa eval` against `$ATTESTRA_POLICY_DIR` (default: this folder). Binary from `$ATTESTRA_OPA_BIN` or PATH. |

OPA errors, timeouts, missing binary or an undefined/malformed decision all **refuse** the scan.

## Verify

```
opa check --strict policy/
opa test policy/ -v
pytest tests/runner/test_opa_policy.py tests/runner/test_gate.py -q
opa run --server policy/          # then ATTESTRA_POLICY_ENGINE=opa-http
```

When you change a rule, change `scope.rego`, `scope_test.rego` **and** `evaluate_python`
together; `test_opa_cli_matches_mirror` fails if they drift (runs when OPA is installed).
