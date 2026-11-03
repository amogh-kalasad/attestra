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
