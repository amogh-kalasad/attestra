"""Role-comparison helpers for authenticated website security testing.

Default mode is read-only: compare HTTP status, redirects, and visible controls
across roles. Intrusive IDOR / object-tampering probes require ``intrusive=True``;
callers must gate that flag with the existing scan gate (asset.intrusive_allowed
+ active profile) before enabling it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class RoleSnapshot:
    """Observed page state for one role at one URL (read-only capture)."""

    role_name: str
    url: str
    status_code: int | None = None
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    visible_controls: list[str] = field(default_factory=list)  # selectors or accessible names
    body_markers: list[str] = field(default_factory=list)  # non-secret UI markers only


@dataclass
class RoleDiff:
    """Differences between two roles for the same logical URL."""

    url: str
    role_a: str
    role_b: str
    status_differs: bool = False
    redirect_differs: bool = False
    controls_only_in_a: list[str] = field(default_factory=list)
    controls_only_in_b: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    intrusive: bool = False


@dataclass
class IntrusiveProbePlan:
    """Planned object-access probes — never executed by this module."""

    url_template: str
    object_ids: list[str]
    note: str = ""


def _key_url(url: str) -> str:
    """Normalize comparison key: ignore fragment; keep path/query."""
    parts = urlsplit(url or "")
    return f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path}?{parts.query}".rstrip("?")


def compare_roles(
    snapshots_a: list[RoleSnapshot] | tuple[RoleSnapshot, ...],
    snapshots_b: list[RoleSnapshot] | tuple[RoleSnapshot, ...],
    *,
    intrusive: bool = False,
) -> list[RoleDiff]:
    """Compare two role snapshot sets by URL (read-only).

    When ``intrusive`` is False (default), only status/redirect/visible-control
    differences are reported. Intrusive mode adds notes that object-level access
    differences may warrant gated IDOR follow-up; it does not send requests.
    """
    by_a = {_key_url(s.url): s for s in snapshots_a}
    by_b = {_key_url(s.url): s for s in snapshots_b}
    urls = sorted(set(by_a) | set(by_b))
    diffs: list[RoleDiff] = []
    for key in urls:
        a = by_a.get(key)
        b = by_b.get(key)
        role_a = a.role_name if a else (snapshots_a[0].role_name if snapshots_a else "a")
        role_b = b.role_name if b else (snapshots_b[0].role_name if snapshots_b else "b")
        diff = RoleDiff(url=key, role_a=role_a, role_b=role_b, intrusive=intrusive)
        if a is None:
            diff.notes.append(f"URL only visible/captured for role {role_b}")
            diffs.append(diff)
            continue
        if b is None:
            diff.notes.append(f"URL only visible/captured for role {role_a}")
            diffs.append(diff)
            continue

        if a.status_code != b.status_code:
            diff.status_differs = True
            diff.notes.append(f"status {a.status_code} vs {b.status_code}")

        final_a = a.final_url or a.url
        final_b = b.final_url or b.url
        if _key_url(final_a) != _key_url(final_b) or a.redirect_chain != b.redirect_chain:
            diff.redirect_differs = True
            diff.notes.append("redirect / final URL differs")

        set_a = set(a.visible_controls)
        set_b = set(b.visible_controls)
        diff.controls_only_in_a = sorted(set_a - set_b)
        diff.controls_only_in_b = sorted(set_b - set_a)
        if diff.controls_only_in_a or diff.controls_only_in_b:
            diff.notes.append("visible controls differ")

        if intrusive and (diff.status_differs or diff.controls_only_in_a or diff.controls_only_in_b):
            diff.notes.append(
                "intrusive follow-up eligible: callers must gate IDOR/tampering with the scan gate"
            )

        if (
            diff.status_differs
            or diff.redirect_differs
            or diff.controls_only_in_a
            or diff.controls_only_in_b
            or diff.notes
        ):
            diffs.append(diff)
    return diffs


def plan_object_access_probes(
    url_template: str,
    object_ids: list[str] | tuple[str, ...],
    *,
    intrusive: bool = False,
) -> IntrusiveProbePlan:
    """Return an IDOR/object-tampering probe plan, or raise if not intrusive.

    This helper does **not** perform HTTP requests. Callers that execute probes
    must set ``intrusive=True`` only after the existing scan gate allows an
    active/intrusive profile on the asset.
    """
    if not intrusive:
        raise PermissionError(
            "IDOR/object tampering requires intrusive=True; callers must gate with the scan gate"
        )
    if "{id}" not in url_template and "%s" not in url_template:
        raise ValueError("url_template must contain {id} or %s placeholder")
    cleaned = [str(x) for x in object_ids if str(x).strip()]
    if not cleaned:
        raise ValueError("object_ids must be non-empty")
    # Refuse obviously huge fan-out.
    if len(cleaned) > 25:
        raise ValueError("object_ids capped at 25 for intrusive plans")
    return IntrusiveProbePlan(
        url_template=url_template,
        object_ids=cleaned,
        note="Plan only — execute only under signed authorization and intrusive gate",
    )


def is_read_only_comparison(intrusive: bool = False) -> bool:
    """True when role comparison must stay observational (default)."""
    return not intrusive
