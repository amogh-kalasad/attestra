# AASI Phase 6 — Attack-path graph + GitHub remediation PR proposals

Status: **Implemented** (Mongo graph helpers + draft PR proposal client + unit tests). Report rendering of paths and UI approval queues remain later work.

Branch: `attestra-asi-bundle`.

## What landed

| Piece | Path | Role |
| --- | --- | --- |
| Graph store | `attestra/aasi/graph.py` | `AasiGraphStore` over `aasi_graph_nodes` / `aasi_graph_edges` |
| Collections | `attestra.persistence.mongo.collections` | `AASI_GRAPH_NODES`, `AASI_GRAPH_EDGES` in `DOMAIN_COLLECTIONS` |
| Migration | `0006_aasi_graph` | Additive create + tenant/provenance indexes (after `0005_aasi_collections`) |
| PR proposals | `attestra/integrations/github_pr.py` | Draft remediation PRs; separate from Issues (`github.py`) |
| Tests | `tests/aasi/test_graph.py`, `tests/integrations/test_github_pr.py` | In-memory fakes / HTTP mocks |
| This note | `docs/ai_security/AASI_PHASE6_GRAPH_REMEDIATION.md` | Phase behaviour snapshot |

## Attack-path graph

### Provenance labels

Every edge carries exactly one of:

- **`observed`** — directly supported by scanner / evidence citations
- **`inferred`** — correlated / hypothesized; **must** be stored as `inferred` (no silent upgrade)
- **`demonstrated`** — requires non-empty **`proof_refs`** (replay / proof evidence ids) in addition to citations

### Edge required fields

| Field | Rule |
| --- | --- |
| `provenance` | One of the three labels above |
| `source` | Non-empty producer id (scanner, AASI role, retest, …) |
| `evidence_citations` | List (may be empty only for rare observed scaffolding; callers should cite) |
| `proof_refs` | Required when `provenance=demonstrated` |
| `created_at` / `updated_at` | UTC timestamps on insert |

Nodes are unique per `(tenant_id, engagement_id, key)`. All reads/writes filter by `tenant_id`.

### Risk: do not raise from inferred count

`risk_delta_for_edge` and `aggregate_path_risk` / `AasiGraphStore.path_risk_summary` **never** add risk solely because many `inferred` edges exist. Inferred contribution is always `0`. Observed / demonstrated may apply caller-supplied deltas; cardinality of inferred edges is reported (`inferred_count`) but excluded from `risk_delta`.

## GitHub remediation PR proposals

`GitHubIssuesClient` (`attestra/integrations/github.py`) continues to create **Issues** only.

`GitHubPRProposalClient` (`attestra/integrations/github_pr.py`) owns **pull-request proposals**:

1. **`propose`** — local draft proposal linked to a finding (`status=pending_approval`); **no** GitHub HTTP call
2. **`approve`** — customer / tenant actor approval (required)
3. **`create_draft_pr`** — POST `/repos/{repo}/pulls` with **`draft: true` only** after approval; refuses non-draft API responses
4. **`mark_awaiting_retest`** — fix claimed; retest required
5. **`close_on_retest_passed`** — sets `closed_retest_passed` only when `finding_status == "retest_passed"`

### Hard rules

- Draft-only by default (`draft=True`); never merge / push APIs
- Tenant authorization via injectable `authorizer` (default allow; tests use allow-list)
- Audit history appended on every transition (`proposal.audit`)
- Body always links the Attestra finding and states closure needs `retest_passed`
- Conceptual closure is tied to the finding workflow status field `retest_passed` (Attestra `models.TRANSITIONS` / retest services); this client does not transition the Finding itself

### Proposal statuses

`draft` → `pending_approval` → `approved` → `draft_pr_open` → `awaiting_retest` → `closed_retest_passed`  
Also: `rejected`, `cancelled`.

## Indexes (migration 0006)

- `aasi_graph_nodes`: `(tenant_id, engagement_id)`; unique partial `(tenant_id, engagement_id, key)`
- `aasi_graph_edges`: `(tenant_id, engagement_id)`; `(tenant_id, engagement_id, from_node_id, to_node_id)`; `(tenant_id, provenance)`

## Out of scope here

- Neo4j or any external graph database
- Automatic branch push / PR merge
- Report PDF path rendering (Phase 7)
- Changing `GitHubIssuesClient` or ticket webhook parsers
- Orchestrator wiring that emits graph edges from AASI decisions

## Exit criteria mapping

| Blueprint exit | How this phase satisfies it |
| --- | --- |
| Inferred paths labelled inferred | `provenance` stored and filterable as `inferred` |
| Demonstrated paths need replay evidence | `proof_refs` required for `demonstrated` |
| Risk not raised from more edges alone | Inferred edges excluded from `risk_delta` |
| Draft PRs need customer approval; never auto-push | Approval gate + draft-only create; no merge |
| Closure needs retest | `close_on_retest_passed` requires `finding_status="retest_passed"` |
