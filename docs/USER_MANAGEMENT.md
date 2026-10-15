# User management

Attestra has no open sign-up. People join through an **admin invite** or through SSO (OIDC/Keycloak).

## Users page (`/users`)
Admins and leads see users in their tenants with role, status, tenant, source (local or SSO) and last login.
Admins can change roles, disable or enable users, and issue password-reset links. Leads can only invite.

| Who   | May invite                         | Change role / disable / reset |
|-------|------------------------------------|-------------------------------|
| admin | any role                           | yes                           |
| lead  | tester, reviewer, client_viewer    | no                            |

Rules:
- The last active admin cannot be demoted or disabled.
- Disabled users cannot sign in. Their session cookies and API keys are rejected on the next request.
- Users created by SSO show in the list with source `sso`; their passwords are managed in the identity provider.

## Invites and resets
- An invite has an email, a role, and an optional tenant. For `client_viewer`/`auditor` an engagement can be chosen,
  which sets the tenant. `client_viewer` invites need a tenant.
- Each link carries a random single-use token. Only its SHA-256 hash is stored (`user_invites`).
  Invites expire after 72 hours (`ATTESTRA_INVITE_TTL_HOURS`), resets after 24 hours (`ATTESTRA_RESET_TTL_HOURS`).
- The link is shown once to copy. Email is sent only when `ATTESTRA_SMTP_HOST` is set
  (also `ATTESTRA_SMTP_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_STARTTLS`). It is off by default.
- Accepting (`/invite/<token>`) sets a username and password; resetting (`/reset/<token>`) sets a new password.
  Passwords need at least 12 characters, at least 4 distinct characters, and must not equal the username.
  They are hashed with scrypt like all local passwords.
- Accept and reset are limited to 10 attempts per minute per IP.
- Issuing a new reset revokes older unused resets for that user. Disabling a user revokes their pending links.

## API
| Method | Path | Who |
|--------|------|-----|
| GET | `/api/users?tenant_id=` | admin, lead |
| GET | `/api/users/invites` | admin, lead |
| POST | `/api/users/invites` `{email, role, tenant_id?, engagement_id?, ttl_hours?}` | admin, lead |
| DELETE | `/api/users/invites/{id}` | admin, lead |
| POST | `/api/users/{id}/role` `{role}` | admin |
| POST | `/api/users/{id}/disable`, `/enable` | admin |
| POST | `/api/users/{id}/reset-password` | admin |
| POST | `/api/invites/accept` `{token, username, password, display_name?}` | public, rate-limited |
| POST | `/api/password-reset` `{token, password}` | public, rate-limited |

## Audit
Events: `user.invite`, `user.invite_revoke`, `user.invite_accept`, `user.password_reset_issued`,
`user.password_reset`, `user.role_change`, `user.disable`, `user.enable`. Tokens are never logged.

## Storage
Migration `0014_user_invites` adds `user_invites` (Postgres RLS: tenant isolation) and `users.last_login_at`.
