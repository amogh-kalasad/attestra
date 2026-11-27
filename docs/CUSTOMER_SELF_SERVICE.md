# Customer self-service registration

Customers can create their own organization account without a CLI or admin invite.

## Enable / disable

| Variable | Default | Effect |
|---|---|---|
| `ATTESTRA_CUSTOMER_SELF_SERVICE_REGISTRATION` | `1` (on) | Show `/register` and accept `POST /api/register` |

Set to `0` / `false` / `off` to hide signup and return errors on POST.

## What registration creates

1. A new **tenant** (organization) with contact email and `plan=standard`
2. A **lead** user bound to that tenant (not platform `admin`)
3. A **tenant membership** for that lead
4. An organization **credit account** (existing subscription infrastructure / initial credits)
5. Optional **welcome email** when SMTP is configured

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/register` | Signup form |
| POST | `/register` | Form submit → redirect `/login` |
| POST | `/api/register` | JSON API (rate-limited) |

Login page links to `/register` when the flag is on.

## Welcome email

Uses [[attestra/users/mailer.py]] (`ATTESTRA_SMTP_*`). Includes organization name, username, and login URL from `ATTESTRA_PUBLIC_URL`. Never includes the password. Failures are logged; registration still succeeds.

## Subscription / feature access

No new commercial plans or payment gateways. Feature access remains:

- Role RBAC (`lead` permissions for the new tenant only)
- `SUBSCRIPTION_SERVICE` organization test-run credits (leads cannot `credits.allocate`)
- Existing ownership, signed-authorization, and scope gates

Customers cannot change their subscription permissions through this registration path.

## Out of scope (documented, not invented)

- Google / Microsoft SSO (future; no nonfunctional buttons)
- Payment providers, free trials, invoices, mandatory email verification

## Related

- Tests: `tests/test_customer_self_service_registration.py`
- Module: `attestra/users/registration.py`
