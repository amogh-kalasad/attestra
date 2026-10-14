# Attestra threat model (working note)

Scope: Attestra v0.1 import-and-report plane, plus planned runner plane (Phase 1). This is an engineering note, not a formal STRIDE worksheet.

## Assets

1. Client authorization documents and RoE text (legal proof of permission to test).
2. Raw scanner outputs and validation evidence (integrity for auditors).
3. Finding lifecycle and compliance assessments (audit trail).
4. Signed reports (hash + signature).
5. Signing keys and (later) per-tenant encryption keys.
6. Tenant-isolated engagement data.

## Actors

| Actor | Intent |
| --- | --- |
| Authorized tester / lead | Import results, triage, generate reports |
| Assessor / reviewer | Confirm controls; approve reports |
| Client viewer / auditor (planned) | Read-only evidence |
| Malicious insider with API access | Spoof identity, weaken four-eyes, exfiltrate |
| External attacker (when runners exist) | SSRF, scan out of scope, abuse egress |
| Compromised CI or host | Tamper with DB, evidence files, or keys |

## Main threats

### Out-of-scope scanning (planned runners)

If Attestra dispatches scanners, a forged or oversized target list must not reach hosts outside the engagement's authorized assets and window. Mitigations planned: `AuthorizedScope`, deny rules, ownership verification, dispatch gate, kill switch.

### SSRF and redirect abuse (planned runners)

DNS rebinding, link-local metadata IPs (`169.254.169.254`), CGNAT, and open redirects can turn a "safe" URL into an internal request. Mitigations planned: resolve-once DNS pin, blocked CIDRs, re-authorize every redirect, pinned connect IP.

### Tampering with audit or evidence

Altering `audit_events`, overwriting content-addressed files, or editing a signed report HTML must be detectable. Mitigations today: SHA-256 at capture, hash-chained audit `verify()`. Planned: DB append-only enforcement, download audit events, backup manifests.

### Identity spoofing via `X-Attestra-Actor` (mitigated)

Mitigated (Phase 2): Bearer API keys / signed session cookies, six roles with `require(permission)`, four-eyes by user id. Residual: enable OIDC (`ATTESTRA_OIDC_ENABLED`) and rotate `ATTESTRA_API_KEY_PEPPER` / `ATTESTRA_SESSION_SECRET` before shared deployment.

### Cross-tenant leaks (mitigated in app layer)

Mitigated (Phase 2): `scoped()` / `tenant_ids_for`, memberships, per-tenant storage under `DATA_DIR/tenants/<id>/`. Residual: Postgres RLS in a later phase.

### Secret and PII leakage in evidence

Scanner artifacts may contain credentials, PANs, cookies. Mitigation planned: masking at capture before hash/store.

## Non-goals (v0.1)

- Attestra is not a scanner; it does not perform attacks.
- Formal residual-risk acceptance for production SaaS waits on Phase 6+ infrastructure and an external pentest (Phase 8).
