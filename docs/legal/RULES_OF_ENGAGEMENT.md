# Rules of engagement - template

> Replace every `<...>`. Delete sections that do not apply. Both parties sign the
> authorization (AUTHORIZATION_TEMPLATE.md) that references this document.

## 1. Parties
- **Client:** `<legal entity name>`, `<address>`
- **Testing provider:** `<legal entity name>`, `<address>`
- **Engagement reference:** `<Attestra engagement id / name>`

## 2. Objectives
`<What the assessment must show, e.g. PCI DSS 11.3 external and internal penetration test, ISO 27001 A.8.8 technical vulnerability management evidence.>`

## 3. Scope
| Target | Type | Environment | In CDE | Tests allowed |
| --- | --- | --- | --- | --- |
| `<https://app.example.com>` | web app | production | yes | web DAST, TLS, manual test |
| `<10.0.0.0/24>` | network | staging | no | host discovery, vulnerability assessment |

**Out of scope:** `<third-party SaaS, payment processor endpoints, employees' personal devices, ...>`.
Anything not listed above is out of scope. Targets hosted by a third party need that party's written consent, attached.

## 4. Testing windows
- Dates: `<start>` to `<end>` (must fall inside the authorization's validity).
- Hours: `<e.g. 09:00-18:00 IST, Mon-Fri>`; production intrusive tests only `<window>`.
- Freeze periods: `<release dates, sale events>`.

## 5. Allowed and prohibited techniques
- Allowed: `<automated scanning with the tools listed in section 8, authenticated testing with provided test accounts, manual verification>`.
- Prohibited unless separately approved in writing: denial-of-service or load testing, social engineering and phishing, physical access, destructive data changes, exfiltration of real customer data, pivoting beyond listed ranges.
- Rate limits: `<max requests/s per host>`; port discovery limited to `<top 100 / agreed list>`.

## 6. Data handling
- Test accounts: `<provided by client>`. No real cardholder or personal data is to be created or retained.
- Evidence is masked (PAN, secrets, tokens) before storage and kept for `<N>` days under the client's retention policy, then deleted.
- Credentials found during testing are reported, not used beyond proving access, and the client rotates them.

## 7. Communication and stop conditions
| Role | Name | Phone | Email |
| --- | --- | --- | --- |
| Client primary contact | `<>` | `<>` | `<>` |
| Client emergency / SOC | `<>` | `<>` | `<>` |
| Provider test lead | `<>` | `<>` | `<>` |

Testing stops immediately, and the client emergency contact is called, if:
service degradation is observed; a critical issue with active exploitation risk is found; evidence of a prior compromise is found; or the client asks to stop. Testing resumes only on written confirmation.

## 8. Tools
`<List the tools and versions to be used. See docs/LICENSES.md for licence notes.>`
Source IP addresses used for testing: `<IPs>`.

## 9. Reporting
- Critical findings: notified within `<24 h>` by phone and email.
- Draft report: `<date>`; final report after review; retest window `<dates>`.

## 10. Liability and confidentiality
`<Reference the master services agreement / NDA clauses. Have counsel review.>`
