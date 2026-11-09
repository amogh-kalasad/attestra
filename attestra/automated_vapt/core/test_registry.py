"""Registered Elite automated security-test cases and categories."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TestCase:
    id: str
    category: str
    title: str
    description: str


# Skeleton catalogue for E3; modules land in later Elite phases.
_CASES: tuple[TestCase, ...] = (
    TestCase("T01", "capture", "HTTP capture", "Capture HTTP request/response with HTTPX."),
    TestCase("T02", "capture", "Browser screenshot", "Capture browser screenshots via Playwright."),
    TestCase("T03", "authentication", "Authentication enforcement", "Verify auth gates on protected routes."),
    TestCase("T04", "authorization", "BOLA/IDOR", "Two-account object-level authorization check."),
    TestCase("T05", "authorization", "Role enforcement", "Validate server-side role checks."),
    TestCase("T06", "authorization", "Tenant isolation", "Cross-tenant access must fail."),
    TestCase("T07", "disclosure", "Sensitive data exposure", "Detect excessive data in responses."),
    TestCase(
        "SESSION",
        "session",
        "Session security",
        "Observe session cookie presence, Secure/HttpOnly/SameSite flags, and JWT alg structure.",
    ),
    TestCase(
        "INJ",
        "injection",
        "Reflected injection canary",
        "Safe ATTSTRA_CANARY query probes on common paths; flag only unencoded HTML reflection.",
    ),
    TestCase(
        "XSS",
        "xss",
        "Reflected XSS canary",
        "Safe reflected XSS canary on common query params; no stored writes.",
    ),
    TestCase(
        "FILE",
        "file",
        "Path traversal content proof",
        "Fake traversal probe; finding only when sensitive content markers appear.",
    ),
    TestCase("T08", "validation", "Response validation", "Classify results via the validation engine."),
    TestCase("T09", "validation", "False-positive handling", "Avoid false confirmed findings on secure apps."),
    TestCase("T10", "evidence", "Screenshot annotation", "Annotate screenshots with markers."),
    TestCase("T11", "evidence", "Evidence redaction", "Redact secrets from report evidence."),
    TestCase("T12", "evidence", "Evidence integrity", "Verify SHA-256 evidence hashes."),
    TestCase("T13", "integration", "Finding mapping", "Map confirmed results to Attestra findings."),
    TestCase("T14", "integration", "Report integration", "Include evidence in reports."),
    TestCase("T15", "import", "Burp import", "Import supported Burp Suite exports."),
    TestCase("T16", "scope", "Scope enforcement", "Reject out-of-scope targets."),
    TestCase("T17", "scope", "Tenant evidence isolation", "Reject unauthorized evidence retrieval."),
    TestCase("T18", "subscription", "Subscription enforcement", "Respect SUBSCRIPTION_SERVICE credit rules."),
    TestCase(
        "T19",
        "authentication",
        "API auth bypass",
        "Replay authenticated API GETs without a session and with a bad bearer; flag if data still returns.",
    ),
    TestCase(
        "T20",
        "authorization",
        "API IDOR / BOLA",
        "Swap harvested object ids into dynamic GET endpoints; flag foreign-id data access (confirm manually).",
    ),
    TestCase(
        "T21",
        "validation",
        "API input validation",
        "Replay authenticated GET params with quotes, long strings, wrong types, XSS and path traversal.",
    ),
    TestCase(
        "T22",
        "authorization",
        "API object mutation (BOLA write)",
        "Body-level object-id swap on captured POST/PUT/PATCH (never DELETE). "
        "Off by default (ATTESTRA_AUTOMATED_VAPT_MUTATION=0); when disabled the case is SKIPPED "
        "with a dry-run plan. Requires APP_ENV=local|test|development to send. "
        "Prefer a secondary (non-admin) login profile for confident IDOR.",
    ),
    TestCase(
        "BIZ",
        "authorization",
        "Business logic owner access",
        "Owner GET succeeds; foreign object GET must not return another owner's record (read-only).",
    ),
    TestCase(
        "ROLEDIFF",
        "authorization",
        "Multi-role access comparison",
        "Read-only compare of two roles (lab account_a/b or secondary profile) on shared API paths.",
    ),
    TestCase(
        "SSRF",
        "injection",
        "Scoped SSRF canary",
        "Probe URL-fetcher params with an Attestra canary; finding only with canary reflection. "
        "Off outside local/test/development unless ATTESTRA_AUTOMATED_VAPT_SSRF=1.",
    ),
    TestCase(
        "UPLOAD",
        "file",
        "Safe file-upload probe",
        "Upload a benign HTML marker and check anonymous fetch of the stored URL. "
        "Off outside local/test/development unless ATTESTRA_AUTOMATED_VAPT_UPLOAD=1.",
    ),
    TestCase(
        "SCOPE_SMOKE",
        "scope",
        "Scope smoke",
        "E3 no-op: validate engagement authorization and target scope, then complete.",
    ),
)


def list_categories() -> list[str]:
    return sorted({c.category for c in _CASES})


def list_test_cases(*, category: str | None = None) -> list[TestCase]:
    if not category:
        return list(_CASES)
    cat = category.strip().lower()
    return [c for c in _CASES if c.category == cat]


def get_test_case(test_id: str) -> TestCase | None:
    tid = (test_id or "").strip().upper()
    for c in _CASES:
        if c.id.upper() == tid:
            return c
    return None
