# Reports and signing

Produces versioned HTML reports, freezes them by SHA-256, requires four-eyes approval, and signs with HMAC-SHA256.

## Kinds

Supported report kinds for [[attestra/reports/render.py#generate_report]].

[[attestra/reports/render.py#KINDS]]: `technical`, `executive`, `compliance` (framework required for compliance).

## Generation

How a report row and frozen HTML file are created.

[[attestra/reports/render.py#generate_report]]:

1. Build context from findings, imports, authorizations, and compliance results ([[attestra/reports/render.py#_context]]).
2. Render Jinja templates under [[attestra/reports/templates]].
3. Write content-addressed file under `data/reports/`.
4. Create [[attestra/models.py#Report]] with version, sha256, signature.
5. Audit the write.

## Four-eyes approval

Second-person approval before a report is considered approved.

[[attestra/reports/render.py#approve_report]] requires a different actor than the generator. Verification helper: [[attestra/reports/render.py#verify_report]]. API: `POST /api/reports/{rid}/approve`.

## Signing

HMAC-SHA256 integrity for reports within one Attestra install.

[[attestra/reports/signing.py]]:

- Per-install key at `data/keys/signing.key` ([[attestra/reports/signing.py#_key]])
- [[attestra/reports/signing.py#sign]] → `hmac-sha256:<key_id>:<mac>`
- [[attestra/reports/signing.py#verify]] uses constant-time compare

This proves integrity **within this Attestra instance**. It is not a third-party-verifiable public-key signature. Roadmap: cosign / X.509.

## Verification

Checking that a frozen report still matches its hash and signature.

Report verify endpoint and CLI check hash + signature. Tampering the frozen HTML breaks verification.
