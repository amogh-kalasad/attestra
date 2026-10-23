"""RBAC roles and permission map."""

from __future__ import annotations

ROLES = ("admin", "lead", "tester", "reviewer", "client_viewer", "auditor")

# permission → roles that may perform it
PERMISSIONS: dict[str, frozenset[str]] = {
    "engagement.create": frozenset({"admin", "lead"}),
    "engagement.read": frozenset({"admin", "lead", "tester", "reviewer", "client_viewer", "auditor"}),
    "engagement.write": frozenset({"admin", "lead", "tester"}),
    "authorization.add": frozenset({"admin", "lead"}),
    "asset.write": frozenset({"admin", "lead", "tester"}),
    "asset.verify_ownership": frozenset({"admin", "lead"}),
    "import.create": frozenset({"admin", "lead", "tester"}),
    "finding.read": frozenset({"admin", "lead", "tester", "reviewer", "client_viewer", "auditor"}),
    "finding.write": frozenset({"admin", "lead", "tester"}),
    "scan.start": frozenset({"admin", "lead", "tester"}),
    "scan.read": frozenset({"admin", "lead", "tester", "reviewer", "auditor"}),
    "engagement.halt": frozenset({"admin", "lead"}),
    "engagement.resume": frozenset({"admin", "lead"}),
    "compliance.read": frozenset({"admin", "lead", "tester", "reviewer", "client_viewer", "auditor"}),
    # P0-1: only auditor (and admin break-glass) may confirm or overwrite control status.
    "compliance.confirm": frozenset({"admin", "auditor"}),
    "report.generate": frozenset({"admin", "lead", "tester"}),
    "report.submit": frozenset({"admin", "lead", "tester"}),
    "report.approve": frozenset({"admin", "lead", "reviewer"}),
    "report.sign": frozenset({"admin", "lead"}),
    "report.read": frozenset({"admin", "lead", "tester", "reviewer", "client_viewer", "auditor"}),
    "retest.manage": frozenset({"admin", "lead", "tester"}),
    # Portal remediation (P6-2): client_viewer may upload fix evidence / request retest
    # without gaining finding.write. Comments stay on can_add_comment (finding.write | client_viewer).
    "portal.evidence": frozenset({"admin", "lead", "tester", "client_viewer"}),
    "portal.retest_request": frozenset({"admin", "lead", "tester", "client_viewer"}),
    "audit.read": frozenset({"admin", "lead", "auditor"}),
    "user.manage": frozenset({"admin"}),
    "webhook.manage": frozenset({"admin", "lead"}),
    "share.create": frozenset({"admin", "lead", "tester"}),
    "share.manage": frozenset({"admin", "lead", "tester"}),
}


def has_permission(role: str, permission: str) -> bool:
    allowed = PERMISSIONS.get(permission)
    if allowed is None:
        return False
    return role in allowed
