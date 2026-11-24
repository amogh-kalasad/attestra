# AASI V5.1 end-to-end verification (Anthive + mock LLM)

Live proof that the **implemented** V5.1 shared-env / native AI scanner path works, plus a classic **web_app** probe of the Anthive marketing site. Run on branch `attestra-asi-bundle`, local Mongo replica set `rs0`, shared root `E:\GitHub\attestra\.attestra-runtime`.

**Scope of what we implemented (under test):**

| Piece | Expected behaviour |
|---|---|
| Shared env installer | One venv; prefer `openai>=3,<4` (PyRIT); `garak==0.17.1 --no-deps`; anthropic + litellm present; no second venv |
| Native AI adapters | Garak / SafeLabs / Promptfoo / PyRIT `allows_docker=False`; Garak REST-only |
| Anthive site | `https://www.anthive.tech/` is a **marketing HTML site**, not an LLM chat API |
| AI live probes | Lab **mock LLM** (`scripts/aasi/mock_llm_target.py`) as `ai_app` |
| Classic web | `webcheck` against anthive.tech (ZAP peers need Docker Desktop daemon) |

Companions: [`AASI_V51_DEPENDENCIES.md`](./AASI_V51_DEPENDENCIES.md), [`AASI_V51_INSTALL.md`](./AASI_V51_INSTALL.md), [`AASI_V51_STATUS.md`](./AASI_V51_STATUS.md).

---

## Executive result

| Gate | Result | Evidence |
|---|---|---|
| Anthive HTTPS reachability | **PASS** | HTTP 200, ~28 683 B; title “Anthive — AI-Powered Digital Transformation”; DNS → `162.0.209.123` |
| Shared-env Python install (openai 3.x + garak `--no-deps`) | **PASS** | Exit 0; root `.attestra-runtime`; single `venv/` (no `*-venv`) |
| Import verification | **PASS** | openai `3.58.0`, garak `0.17.1`, pyrit `1.2.1`, anthropic `0.125.0`, litellm `1.110.3`, safelabs-eval `0.12.0` |
| Accepted `pip check` garak↔openai WARN only | **PASS** | Only WARN: garak wants openai&lt;3, have 3.58.0 |
| Mock LLM up (`:18080/health`) | **PASS** | `{"ok":true,"service":"aasi-mock-llm"}`; hundreds of POSTs during AI scans |
| API `/api/health` | **PASS** | mongo ok, replica set `rs0`, writable primary |
| Worker processing queue | **PASS** | `worker-98927b98c40f`, concurrency 2 |
| AASI status | **PASS** | `ATTESTRA_AASI=on` |
| Engagement + assets | **PASS** | eng `#1`; asset `#1` `ai_app` mock; asset `#2` `web_app` anthive.tech |
| Signed auth uploaded | **PASS** | auth `#1` production/staging/uat through 2027-11-24 |
| Loopback + `allow_private` gate | **PASS (FIXED)** | `validate_resolved_ips` allows loopback when `allow_private` (unit + live) |
| SafeLabs native → mock LLM | **PASS** | scan `#10` `done` (~20 s); `data/raw/scan-10/safelabs-report.json` |
| Garak REST native → mock LLM | **EXEC PASS / IMPORT FAIL** | scan `#11` exit 0 in ~16 min; RestGenerator; 93 probes / 26 084 attempts; report+HTML written; Attestra import failed on JSONL line (tqdm noise) |
| Promptfoo native | **SKIPPED** | Installer used `--skip-node` / `--skip-promptfoo` this pass |
| PyRIT native → mock LLM | **PASS** | scan `#12` `done` (~13 s); pyrit `1.2.1`; crescendo / 3 attacks |
| Anthive `web_app` webcheck | **PASS** | scan `#13` `done` (~4 s); **10 findings** imported for `https://www.anthive.tech/` |
| ZAP / Docker web DAST | **NOT RUN** | Docker **client** present; Desktop **daemon** pipe missing |

**Overall:** V5.1 shared-env openai policy and native SafeLabs + PyRIT execution against the lab mock LLM are **proven**. Anthive.tech is correctly treated as `web_app`; webcheck produced real imported findings. Garak REST **ran to completion** under the shared env (exit 0, digest present); Attestra marked the scan `failed` because the JSONL importer rejected a bad line (refuse text includes tqdm progress fragments) — follow-up to harden import. Promptfoo and ZAP remain follow-ups.

---

## Why anthive.tech is not the AI target

Fetched `https://www.anthive.tech/` (200). Content is AntHive marketing (Attestra / Answerra product pages). There is no public OpenAI-shaped `/v1/chat/completions` endpoint on that host for Garak RestGenerator / SafeLabs / Promptfoo / PyRIT.

| Target | Asset kind | Role in this E2E |
|---|---|---|
| `https://www.anthive.tech/` | `web_app` | Classic scanners (webcheck; ZAP when Docker daemon is up) |
| `http://127.0.0.1:18080/` (mock LLM) | `ai_app` (+ notes `allow_private`) | Native AASI scanners proving shared-env install |

Using anthive.tech as `ai_app` would queue AI tools against HTML and produce empty/failed reports — a false failure of the V5.1 stack.

---

## Environment snapshot

| Item | Value |
|---|---|
| Date | 2026-11-24 (local IST / UTC as recorded on scan rows) |
| Branch | `attestra-asi-bundle` |
| Repo | `E:\GitHub\attestra` |
| Shared root | `E:\GitHub\attestra\.attestra-runtime` |
| Installer | `python scripts/aasi/install_shared_env.py --root … --skip-node --skip-promptfoo` |
| Runtime env | `APP_ENV=local`; `ATTESTRA_SHARED_ENV_ROOT`; `ATTESTRA_AASI=on`; Mongo URI replica set `rs0`; `BYPASS_TARGET_OWNERSHIP_VERIFICATION=true`; `BYPASS_SIGNED_AUTHORIZATION_VERIFICATION=true` |
| MongoDB | `mongod` on `127.0.0.1:27017` (manual dbpath `data/mongo-rs0`; Windows service needed elevation) |
| Docker Desktop | Client 29.8.2; daemon `npipe:////./pipe/dockerDesktopLinuxEngine` **not** available this pass |
| Operator user | `vikram.lead` (API key Bearer) |
| Credits | Allocated; balance reduced as scans queued |

---

## Procedure (what we ran)

### A. Shared environment (V5.1 openai policy)

```powershell
cd E:\GitHub\attestra
$env:ATTESTRA_SHARED_ENV_ROOT = "$PWD\.attestra-runtime"
.\.venv\Scripts\python.exe scripts\aasi\install_shared_env.py --root $env:ATTESTRA_SHARED_ENV_ROOT --skip-node --skip-promptfoo
```

**Observed:** Exit 0; manifests under `.attestra-runtime/manifests/` for safelabs / garak / pyrit; layout `venv`, `tools`, `npm`, `manifests`, `logs`, `cache`, `tmp` only (no second Python venv).

### B. Mock LLM

```powershell
.\.venv\Scripts\python.exe scripts\aasi\mock_llm_target.py
# GET http://127.0.0.1:18080/health → {"ok": true, "service": "aasi-mock-llm"}
```

### C. API + worker

```powershell
# Mongo rs0 listening, then:
$env:ATTESTRA_SHARED_ENV_ROOT = "$PWD\.attestra-runtime"
$env:ATTESTRA_AASI = "on"
$env:BYPASS_TARGET_OWNERSHIP_VERIFICATION = "true"
$env:BYPASS_SIGNED_AUTHORIZATION_VERIFICATION = "true"
$env:ATTESTRA_MONGODB_URI = "mongodb://127.0.0.1:27017/?replicaSet=rs0"
.\.venv\Scripts\python.exe -m uvicorn attestra.api:app --host 127.0.0.1 --port 8000
.\.venv\Scripts\python.exe -m attestra.cli worker
```

### D. Engagement setup

1. Engagement `#1` (iso_27001_2022 / active), test window open.
2. Asset `#1` `ai_app` → `http://127.0.0.1:18080/` with notes containing `allow_private`.
3. Asset `#2` `web_app` → `https://www.anthive.tech/`.
4. Signed authorization `#1` uploaded (production/staging/uat).
5. Credits allocated via `/api/credits/allocate`.
6. Queued scans via `POST /api/engagements/1/scans`: safelabs `#10`, garak `#11`, pyrit `#12`, webcheck `#13`.

### E. Gate fixes during the run

Earlier refused attempts (`#1`–`#9`) documented the gates:

| Scan ids | Refuse reason | Fix |
|---|---|---|
| `#1`–`#5` | no valid authorization for asset environment | Upload signed auth PDF / auth record |
| `#6`–`#8` | blocked IP: 127.0.0.1 | Allow loopback in `validate_resolved_ips` when `allow_private=True` |
| `#9` | asset ownership not verified | Restart API/worker with `BYPASS_TARGET_OWNERSHIP_VERIFICATION=true` |

Unit coverage: `tests/security/test_ssrf_policy.py` includes `test_loopback_allowed_when_allow_private` (suite green for that module).

---

## Live scan results

### Scan `#10` — SafeLabs (native) — **PASS**

| Field | Value |
|---|---|
| Asset | `#1` mock LLM |
| Status | `done` |
| Window | started `2026-11-24T06:30:15.201Z` → ended `06:30:35.743Z` |
| tool_version | `safelabs-eval` |
| raw_sha256 | `ed95a043683dc5318b1de8584e6089ad9c3e8384913642c13569c5a0f96efaf3` |
| Artifact | `data/raw/scan-10/safelabs-report.json` |

Report summary: **30** ASI01-style results — **28** `uncertain`, **2** `pass` (stub replies / refusal heuristics). No confirmed vulnerable findings imported (expected for boring mock). Execution still **PASS**.

### Scan `#11` — Garak REST (native) — **EXECUTION PASS / IMPORT FAIL**

| Field | Value |
|---|---|
| Asset | `#1` mock LLM |
| Scan status | `failed` (Attestra post-process / import) |
| Garak process | **exit code 0**; report contains `completion` + `digest` |
| Window | started `2026-11-24T06:30:15.217Z` → ended `06:46:25.873Z` (~16 min) |
| Generator | `generators.rest.RestGenerator` → `http://127.0.0.1:18080/` |
| Config | `data/raw/scan-11/garak-generator.json`, `garak-run.yaml` (`generations: 1`) |
| Artifacts | `garak-report.report.jsonl` (~84 MB), `garak-report.report.html` (~2.1 MB) |
| Scale | 93 probes, 26 084 attempts, 124 evals, 93 probe_summaries |
| Imported findings | **0** (import aborted) |
| refuse_reason (abbrev.) | `garak output could not be read as garak: garak JSONL line 2393 is not valid JSON: Unterminated string…` plus tqdm fragments (`Preparing prompts`, `probes.web_injection.TaskXSS`) |

`garak-generator.json` proves REST-only path (no OpenAI generator):

```json
{
  "rest": {
    "RestGenerator": {
      "name": "attestra-ai-target",
      "uri": "http://127.0.0.1:18080/",
      "method": "post",
      "response_json": true,
      "response_json_field": "$.choices[0].message.content"
    }
  }
}
```

**Interpretation:** Native shared-env Garak **execution** against the mock LLM is proven. The failure is in Attestra’s strict JSONL parse (`attestra/importers/garak.py#_parse_records`) when a non-JSON line (progress / truncated content) appears in the payload it reads. Re-parsing the on-disk `.report.jsonl` line-by-line after the run completed found no bad lines — the bad payload may have been a mid-write snapshot or stdout mix-in. Follow-up: skip/tolerate bad JSONL lines or ensure only the finished report file is imported.

### Scan `#12` — PyRIT (native) — **PASS**

| Field | Value |
|---|---|
| Asset | `#1` mock LLM |
| Status | `done` |
| Window | started `2026-11-24T06:30:38.258Z` → ended `06:30:51.017Z` |
| tool_version | `pyrit 1.2.1` |
| raw_sha256 | `de4507d369f05aa3598cffa265bbf26a926c09950c873823b57abfca6b3648e9` |
| Artifacts | `data/raw/scan-12/pyrit-run.json`, `pyrit-results.json` |

Run config: scenario `crescendo`, `scenario_engine=pyrit-backed`, target `http://127.0.0.1:18080/`, external judge / adversarial egress **disabled**. Results: **3** attack conversations, **0** successes (stub safe replies) — import correctly yields **no** PyRIT findings. Execution **PASS**.

### Scan `#13` — webcheck vs anthive.tech — **PASS**

| Field | Value |
|---|---|
| Asset | `#2` `https://www.anthive.tech/` |
| Status | `done` |
| Window | started `2026-11-24T06:30:52.831Z` → ended `06:30:57.243Z` |
| tool_version | `webcheck` |
| raw_sha256 | `aa56523edea98eaa7cf27a7fa416f2a03e21095391d974501be846001f735938` |
| Artifact | `data/raw/scan-13/webcheck.json` |

Check tallies: **failed 10**, skipped 8, passed 7. Failed check ids: `hsts-present`, `x-content-type-options`, `referrer-policy`, `server-disclosure`, `waf-none-seen`, `sri`, `security-txt`, `dns-caa`, `dns-aaaa`, `dns-tlsa`.

### Anthive findings imported (engagement `#1`)

All **10** findings are `detected_by` / `tools: ["webcheck"]`, `asset_id=2`, location on anthive.tech:

| Id | Severity | Title |
|---|---|---|
| 1 | low | HSTS header missing on HTTPS |
| 2 | low | X-Content-Type-Options is missing or not nosniff |
| 3 | low | Referrer-Policy is not a strict value |
| 6 | low | External scripts or styles without Subresource Integrity |
| 8 | low | DNS: no CAA record |
| 4 | info | Server header discloses software |
| 5 | info | No WAF or CDN signature seen |
| 7 | info | security.txt missing or invalid |
| 9 | info | DNS: no IPv6 (AAAA) address |
| 10 | info | DNS: no DANE (TLSA) record |

Example remediation payload present on finding `#1` (nginx/apache/iis/cloudflare snippets + verification steps). Risk scoring applied (`risk-v1.1`).

---

## Pass / fail interpretation

| Observation | Interpretation |
|---|---|
| Installer exits 0; openai 3.x; garak imports; one venv | V5.1 openai policy **works** |
| `pip check` only garak↔openai WARN | Expected / accepted |
| SafeLabs / PyRIT scan_run `done` with 0 confirmed AI findings on mock | Execution **PASS** (stub is intentionally boring) |
| Garak RestGenerator config + live POSTs to mock | Native REST path **in use** (OpenAI generator not selected) |
| webcheck `done` + 10 anthive findings | Classic web path against real Anthive site **works** |
| Adapter tries Docker for garak/safelabs/pyrit | Would be **FAIL** (not observed this run) |
| Second venv created | Would be **FAIL** (not observed) |
| AI tool queued against anthive.tech HTML only | Misconfiguration — avoided |
| ZAP skipped (Docker daemon down) | Classic DAST incomplete; does **not** invalidate native AI or webcheck |

---

## Gaps / follow-ups

1. **Garak import hardening**: tolerate/skip invalid JSONL lines (or import only after `completion`/`digest`); re-import `data/raw/scan-11/garak-report.report.jsonl` once fixed.
2. **Promptfoo**: re-run `install_shared_env.py` **without** `--skip-node` / `--skip-promptfoo`; queue native promptfoo against mock.
3. **Docker Desktop daemon**: start engine; queue ZAP (or peers) against `https://www.anthive.tech/` for deeper web DAST.
4. Non-bypass proof: turn ownership / signed-auth bypasses **off** and re-run with verified ownership + valid Anthive signed authorization PDF.
5. Persist a reusable lab script (engagement / asset ids, scan queue) once this Mongo data set is stable.
6. Do **not** claim production readiness from this lab E2E alone (local bypasses, mock LLM, skipped Promptfoo/ZAP, Garak import fail).

---

## Document history

| When | Note |
|---|---|
| 2026-11-24 | Doc created; anthive reachability PASS; shared-env install started |
| 2026-11-24 | Interim: scans `#10`–`#13` queued; loopback/`allow_private` fix landed |
| 2026-11-24 | Results: SafeLabs `#10` PASS, PyRIT `#12` PASS, webcheck `#13` PASS (10 anthive findings); Garak `#11` still RUNNING; Promptfoo skipped; Docker daemon down |
| 2026-11-24 | Garak `#11` finished: process exit 0 / digest written; Attestra status `failed` on JSONL import (tqdm noise). Documented EXEC PASS / IMPORT FAIL per operator choice |
