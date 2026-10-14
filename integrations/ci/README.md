# Attestra CI/CD gates (Phase 6.7)

Pipelines upload scanner output to Attestra and fail when the engagement policy is breached.

| File | Use |
|---|---|
| `attestra_ci.py` | Stdlib-only client: `POST /api/engagements/{eid}/imports`, then `GET /api/engagements/{eid}/gate`. |
| `github/attestra-gate.yml` | GitHub Actions workflow (Semgrep SARIF + Trivy JSON -> Attestra). |
| `gitlab/attestra-gate.gitlab-ci.yml` | GitLab CI include with the same flow. |

## Setup
1. In Attestra create an API key for a `tester` or `lead` user (`attestra` CLI / admin) on the engagement's tenant.
2. The engagement needs a **valid signed authorization** and the repo/image as an in-scope target, otherwise imports are refused (409/403) or findings show as unmatched.
3. Set `ATTESTRA_URL`, `ATTESTRA_ENGAGEMENT_ID`, `ATTESTRA_TOKEN` (secret). Optional `ATTESTRA_FAIL_ON` (`critical|high|medium|low|info`, default `high`) and `ATTESTRA_MAX_FINDINGS` (default `0`).

## Policy
The gate counts **open** findings (`new`, `triaged`, `validated`) at or above `fail_on`. Risk-accepted, fixed and false-positive findings never block. By default (`--scope uploaded`) only findings reported by the uploaded tool(s) count; `--scope engagement` gates on everything open.

Exit codes: `0` pass, `1` policy failed, `2` config error, `3` API/network error.

## Local try
```
python integrations/ci/attestra_ci.py --url http://127.0.0.1:8000 --token <key> --engagement 1 \
  --file trivy=tests/fixtures/trivy.json --fail-on high
```
