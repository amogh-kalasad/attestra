"""Decide which Nuclei templates are allowed for a scan profile."""

from __future__ import annotations

# Templates / tags treated as active (intrusive) — require asset.intrusive_allowed.
ACTIVE_TAGS = frozenset({"intrusive", "dos", "fuzz", "takeover"})
ACTIVE_TEMPLATE_GLOBS = ("*fuzz*", "*brute*", "*takeover*", "*intrusive*")


def is_active_profile(profile: str) -> bool:
    return profile.lower() in ("active", "intrusive")


def templates_allowed(*, profile: str, intrusive_allowed: bool) -> list[str]:
    """Return nuclei -tags / template selectors for the profile."""
    if is_active_profile(profile):
        if not intrusive_allowed:
            raise PermissionError("active nuclei templates require intrusive_allowed on the asset")
        return [ACTIVE_SELECTION]
    return [BASELINE_SELECTION]


# Real nuclei template tags (the old "cves,vulnerabilities,misconfiguration" names matched no tags).
BASELINE_SELECTION = "cve,misconfig,exposure"
ACTIVE_SELECTION = "cve,misconfig,exposure,vuln,intrusive"
# Never run these on the baseline profile, even when a template also carries an allowed tag.
BASELINE_EXCLUDED_TAGS = "intrusive,dos,fuzz,bruteforce,brute-force,takeover"
ALWAYS_EXCLUDED_TAGS = "dos"


def excluded_tags(*, profile: str) -> str:
    return ALWAYS_EXCLUDED_TAGS if is_active_profile(profile) else BASELINE_EXCLUDED_TAGS


def template_is_active(template_id: str, tags: list[str] | None = None) -> bool:
    tid = template_id.lower()
    if any(g.strip("*") in tid for g in ACTIVE_TEMPLATE_GLOBS):
        return True
    tags = tags or []
    return bool(ACTIVE_TAGS.intersection(t.lower() for t in tags))
