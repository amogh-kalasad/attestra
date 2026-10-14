# Security Policy

## Reporting a vulnerability

Report security issues privately to the maintainers of this repository (open a private security advisory on GitHub, or contact the project owners listed on the repository). Do not file public issues for vulnerabilities that could expose client authorization documents, signing keys, audit evidence, or cross-tenant data.

Include: affected version, reproduction steps, impact, and whether you have a suggested fix. We aim to acknowledge reports within a few business days.

## Assets to protect

| Asset | Location / notes |
| --- | --- |
| Signed authorization / RoE documents | Hashed, write-once under `DATA_DIR/evidence` |
| Report signing key | `DATA_DIR/keys` (HMAC today; planned X.509/Ed25519) |
| Audit hash chain | `audit_events` table — must remain append-only |
| Imported scanner raw files and evidence | Content-addressed under `DATA_DIR` |
| Engagement finding and compliance data | Database (SQLite by default; Postgres planned) |

## Current trust boundaries (v0.1)

- Attestra **does not run scanners**. Testers import result files under a valid signed authorization.
- Write APIs require an `X-Attestra-Actor` header. This is a **placeholder identity** until real auth (API keys / OIDC) lands; anyone who can reach the API can spoof an actor name.
- Four-eyes report approval compares free-text actor names, not user IDs.
- There is no cross-tenant query isolation yet.

## Threats we actively care about

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the working threat model (out-of-scope scanning, SSRF when runners exist, audit/evidence tampering, identity spoofing, cross-tenant leaks).

## Safe development rules

- Never point scanners at external targets during development; use loopback fixtures only.
- Never commit `.venv`, `data/`, `*.db`, `.cache`, or signing keys.
- Do not hardcode credentials or API keys in source.
