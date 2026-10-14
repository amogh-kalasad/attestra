# Legal pack

Templates a delivery team adapts with the client's counsel before any testing.
They are starting points, not legal advice.

| File | Use |
| --- | --- |
| [RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md) | Rules of engagement (RoE): scope, windows, allowed techniques, contacts, stop conditions |
| [AUTHORIZATION_TEMPLATE.md](AUTHORIZATION_TEMPLATE.md) | Signed authorization to test, recorded in Attestra before any import or scan |

Attestra enforces the authorization in software: imports and runner jobs are
refused unless a currently valid signed authorization covers the target's
environment (see `services.import_results` and `attestra/runner/authorization.py`).
The PDF or signed scan of these documents is the file uploaded with
`add_authorization`.
