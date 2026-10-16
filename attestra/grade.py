"""Overall A–F site grade with Observatory-style score breakdown.

Start at 100. Each check result applies a modifier from MODIFIERS.
Bonuses apply only when the running score is already >= 90.
Not-tested checks (no data) do not change the score.
Suppressed / false-positive findings do not take points off.
Accepted-risk findings still count. Expired/invalid certificate caps the grade at F.
"""
# @lat: [[findings#Site grade]]

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# Points and short reasons. Easy to read and change.
# kind: penalty | bonus | cap_f
MODIFIERS: dict[str, dict[str, Any]] = {
    "csp_missing": {
        "points": -25,
        "reason": "Missing Content-Security-Policy",
        "kind": "penalty",
    },
    "csp_unsafe_inline": {
        "points": -10,
        "reason": "CSP present but script-src allows unsafe-inline",
        "kind": "penalty",
    },
    "csp_strong": {
        "points": 5,
        "reason": "Strong CSP (bonus only if score >= 90)",
        "kind": "bonus",
    },
    "hsts_missing": {
        "points": -20,
        "reason": "Missing Strict-Transport-Security",
        "kind": "penalty",
    },
    "hsts_short": {
        "points": -10,
        "reason": "HSTS max-age under 6 months",
        "kind": "penalty",
    },
    "hsts_preload": {
        "points": 5,
        "reason": "HSTS with preload and includeSubDomains (bonus if score >= 90)",
        "kind": "bonus",
    },
    "xcto_missing": {
        "points": -5,
        "reason": "Missing X-Content-Type-Options",
        "kind": "penalty",
    },
    "clickjacking": {
        "points": -20,
        "reason": "Missing X-Frame-Options and no CSP frame-ancestors",
        "kind": "penalty",
    },
    "referrer_missing": {
        "points": 0,
        "reason": "Missing Referrer-Policy (info only)",
        "kind": "penalty",
    },
    "referrer_good": {
        "points": 5,
        "reason": "Good Referrer-Policy (bonus if score >= 90)",
        "kind": "bonus",
    },
    "cookie_secure": {
        "points": -20,
        "reason": "Cookie without Secure on HTTPS",
        "kind": "penalty",
    },
    "cookie_httponly": {
        "points": -10,
        "reason": "Session cookie without HttpOnly",
        "kind": "penalty",
    },
    "cookie_samesite": {
        "points": 5,
        "reason": "SameSite set on cookies (bonus if score >= 90)",
        "kind": "bonus",
    },
    "tls_legacy": {
        "points": -20,
        "reason": "TLS 1.0 or 1.1 enabled",
        "kind": "penalty",
    },
    "tls_weak_cipher": {
        "points": -15,
        "reason": "Weak TLS cipher",
        "kind": "penalty",
    },
    "cert_expired": {
        "points": 0,
        "reason": "Certificate expired or invalid — grade capped at F",
        "kind": "cap_f",
    },
    "cert_expires_soon": {
        "points": -10,
        "reason": "Certificate expires in under 14 days",
        "kind": "penalty",
    },
    "http_no_https_redirect": {
        "points": -20,
        "reason": "http:// does not redirect to https:// on the same host",
        "kind": "penalty",
    },
}

# Grade bands: (minimum score inclusive, letter). Checked high to low.
GRADE_BANDS: list[tuple[int, str]] = [
    (100, "A+"),
    (90, "A"),
    (85, "A-"),
    (80, "B+"),
    (70, "B"),
    (65, "B-"),
    (60, "C+"),
    (50, "C"),
    (45, "C-"),
    (40, "D+"),
    (30, "D"),
    (25, "D-"),
    (0, "F"),
]

# Statuses that must not take points off.
_IGNORE_STATUSES = frozenset({"false_positive", "suppressed", "fp"})


@dataclass(frozen=True)
class BreakdownRow:
    check: str
    result: str  # pass | fail | not_tested | info | bonus_skipped
    points: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "result": self.result,
            "points": self.points,
            "reason": self.reason,
        }


def grade_from_score(score: int, *, cap_f: bool = False) -> str:
    """Map a 0–100+ score to a letter grade. Expired cert forces F."""
    if cap_f:
        return "F"
    s = max(0, int(score))
    for minimum, letter in GRADE_BANDS:
        if s >= minimum:
            return letter
    return "F"


# Lower rank = worse letter. Used to sort the sites dashboard (worst first).
_GRADE_RANK = {letter: i for i, (_, letter) in enumerate(reversed(GRADE_BANDS))}
_NOT_GRADED_RANK = len(_GRADE_RANK)  # after F so ungraded rows sort last


def grade_rank(letter: str | None) -> int:
    """Sort key for letter grades: F is 0 (worst), A+ is highest; None is last."""
    # @lat: [[interfaces#Web dashboard#Sites dashboard]]
    if not letter:
        return _NOT_GRADED_RANK
    return _GRADE_RANK.get(letter, _NOT_GRADED_RANK)


def _norm(text: str) -> str:
    return (text or "").lower()


def _finding_blob(f: Any) -> str:
    """Title + variant + evidence-ish fields for keyword matching."""
    if isinstance(f, dict):
        parts = [
            f.get("title") or "",
            f.get("variant") or "",
            f.get("param") or "",
            " ".join(f.get("tools") or []),
        ]
        return _norm(" ".join(str(p) for p in parts))
    parts = [
        getattr(f, "title", "") or "",
        getattr(f, "variant", "") or "",
        getattr(f, "param", "") or "",
        " ".join(getattr(f, "tools", None) or []),
    ]
    return _norm(" ".join(str(p) for p in parts))


def _status_of(f: Any) -> str:
    if isinstance(f, dict):
        return _norm(str(f.get("status") or ""))
    return _norm(str(getattr(f, "status", "") or ""))


def _is_ignored(f: Any) -> bool:
    return _status_of(f) in _IGNORE_STATUSES


def _match_flags(findings: Iterable[Any]) -> dict[str, bool]:
    """Detect which grade-relevant conditions are present in findings."""
    flags = {k: False for k in MODIFIERS}
    saw = {
        "csp_any": False,
        "csp_tested": False,
        "hsts_tested": False,
        "xcto_tested": False,
        "clickjack_tested": False,
        "referrer_tested": False,
        "cookie_tested": False,
        "tls_tested": False,
        "cert_tested": False,
        "redirect_tested": False,
        "samesite_ok": False,
        "referrer_ok": False,
        "csp_ok": False,
        "hsts_preload_ok": False,
    }

    for f in findings:
        if _is_ignored(f):
            continue
        blob = _finding_blob(f)
        if not blob:
            continue

        # CSP
        if "content-security-policy" in blob or "csp" in blob.split() or "csp:" in blob or "csp-" in blob:
            saw["csp_tested"] = True
            if "missing" in blob and ("content-security-policy" in blob or "csp" in blob):
                if "directive" not in blob or "content-security-policy" in blob:
                    flags["csp_missing"] = True
            if "unsafe-inline" in blob and ("script" in blob or "csp" in blob):
                flags["csp_unsafe_inline"] = True
                saw["csp_any"] = True
            if "unsafe-eval" in blob or "wildcard" in blob or "http://" in blob:
                saw["csp_any"] = True

        # HSTS
        if "strict-transport-security" in blob or "hsts" in blob:
            saw["hsts_tested"] = True
            if "missing" in blob or "not set" in blob or "no hsts" in blob:
                flags["hsts_missing"] = True
            if "max-age" in blob and ("short" in blob or "under" in blob or "low" in blob):
                flags["hsts_short"] = True
            if "preload" in blob and "includesubdomains" in blob.replace(" ", ""):
                # finding about missing preload is not a bonus
                if "missing" not in blob and "not" not in blob:
                    saw["hsts_preload_ok"] = True

        # X-Content-Type-Options
        if "x-content-type-options" in blob or "nosniff" in blob or "xcto" in blob:
            saw["xcto_tested"] = True
            if "missing" in blob:
                flags["xcto_missing"] = True

        # Clickjacking / frame
        if "x-frame-options" in blob or "frame-ancestors" in blob or "clickjack" in blob:
            saw["clickjack_tested"] = True
            if "missing" in blob:
                flags["clickjacking"] = True

        # Referrer-Policy
        if "referrer-policy" in blob or "referrer policy" in blob:
            saw["referrer_tested"] = True
            if "missing" in blob:
                flags["referrer_missing"] = True
            elif "strict-origin" in blob or "no-referrer" in blob:
                saw["referrer_ok"] = True

        # Cookies
        if "cookie" in blob and ("secure" in blob or "httponly" in blob or "samesite" in blob):
            saw["cookie_tested"] = True
            if "secure" in blob and ("missing" in blob or "without" in blob):
                flags["cookie_secure"] = True
            if "httponly" in blob and ("missing" in blob or "without" in blob):
                flags["cookie_httponly"] = True
            if "samesite" in blob and ("missing" in blob or "without" in blob):
                pass
            elif "samesite" in blob and "missing" not in blob:
                saw["samesite_ok"] = True

        # TLS
        if "tls 1.0" in blob or "tls1.0" in blob or "tls 1.1" in blob or "tls1.1" in blob:
            saw["tls_tested"] = True
            flags["tls_legacy"] = True
        if "weak cipher" in blob or "rc4" in blob or "export cipher" in blob or "null cipher" in blob:
            saw["tls_tested"] = True
            flags["tls_weak_cipher"] = True
        if "cipher" in blob or "protocol" in blob or "tls" in blob:
            if "testssl" in blob or "ssl" in blob or "tls" in blob:
                saw["tls_tested"] = True

        # Certificate
        if "certificate" in blob or "cert_" in blob or "cert " in blob:
            saw["cert_tested"] = True
            if "expired" in blob or "not yet valid" in blob or "invalid" in blob:
                flags["cert_expired"] = True
            if "expires" in blob and ("day" in blob or "soon" in blob):
                flags["cert_expires_soon"] = True

        # HTTP→HTTPS redirect (prompt 14 / phase 15)
        if "redirect" in blob and ("https" in blob or "http" in blob):
            saw["redirect_tested"] = True
            if (
                "does not redirect" in blob
                or "no redirect" in blob
                or "redirects to http" in blob
                or "another host" in blob
                or "other host" in blob
            ):
                flags["http_no_https_redirect"] = True

    # Bonuses when we saw the topic tested and no related penalty
    if saw["csp_tested"] and not flags["csp_missing"] and not flags["csp_unsafe_inline"] and not saw["csp_any"]:
        flags["csp_strong"] = True
    if saw["hsts_preload_ok"] and not flags["hsts_missing"] and not flags["hsts_short"]:
        flags["hsts_preload"] = True
    if saw["referrer_ok"] and not flags["referrer_missing"]:
        flags["referrer_good"] = True
    if saw["cookie_tested"] and saw["samesite_ok"] and not flags["cookie_secure"] and not flags["cookie_httponly"]:
        flags["cookie_samesite"] = True

    # Attach saw for not_tested decisions
    flags["_saw"] = saw  # type: ignore[assignment]
    return flags


# Which saw-* key means this modifier was in scope of the scan data.
_TESTED_BY: dict[str, str] = {
    "csp_missing": "csp_tested",
    "csp_unsafe_inline": "csp_tested",
    "csp_strong": "csp_tested",
    "hsts_missing": "hsts_tested",
    "hsts_short": "hsts_tested",
    "hsts_preload": "hsts_tested",
    "xcto_missing": "xcto_tested",
    "clickjacking": "clickjack_tested",
    "referrer_missing": "referrer_tested",
    "referrer_good": "referrer_tested",
    "cookie_secure": "cookie_tested",
    "cookie_httponly": "cookie_tested",
    "cookie_samesite": "cookie_tested",
    "tls_legacy": "tls_tested",
    "tls_weak_cipher": "tls_tested",
    "cert_expired": "cert_tested",
    "cert_expires_soon": "cert_tested",
    "http_no_https_redirect": "redirect_tested",
}


def score_from_findings(findings: Iterable[Any]) -> dict[str, Any]:
    """Compute grade, score, and breakdown from a list of finding-like objects.

    Each finding may be a dict or an ORM Finding. Returns a dict with
    grade, score, breakdown (list), cap_f (bool).
    """
    findings_list = list(findings)
    flags = _match_flags(findings_list)
    saw: dict[str, bool] = flags.pop("_saw")  # type: ignore[assignment]

    score = 100
    breakdown: list[BreakdownRow] = []
    cap_f = False

    # Apply penalties and caps first (order stable by MODIFIERS key order).
    for key, meta in MODIFIERS.items():
        tested_key = _TESTED_BY.get(key, "")
        tested = bool(saw.get(tested_key)) if tested_key else True
        kind = meta["kind"]
        points = int(meta["points"])
        reason = str(meta["reason"])

        if not tested:
            breakdown.append(BreakdownRow(key, "not_tested", 0, reason + " (not tested)"))
            continue

        active = bool(flags.get(key))
        if kind == "cap_f":
            if active:
                cap_f = True
                breakdown.append(BreakdownRow(key, "fail", 0, reason))
            else:
                breakdown.append(BreakdownRow(key, "pass", 0, reason.replace(" — grade capped at F", " OK")))
            continue

        if kind == "bonus":
            # Applied in a second pass after penalties.
            continue

        if active:
            score += points  # points are negative for penalties
            breakdown.append(BreakdownRow(key, "fail" if points < 0 else "info", points, reason))
        else:
            breakdown.append(BreakdownRow(key, "pass", 0, reason.replace("Missing ", "Has ").replace("without", "with")))

    if score < 0:
        score = 0

    # Bonuses only when score already >= 90 (Observatory style).
    for key, meta in MODIFIERS.items():
        if meta["kind"] != "bonus":
            continue
        tested_key = _TESTED_BY.get(key, "")
        tested = bool(saw.get(tested_key)) if tested_key else True
        points = int(meta["points"])
        reason = str(meta["reason"])
        if not tested:
            # already added as not_tested above for bonuses? We skipped bonuses in first loop.
            breakdown.append(BreakdownRow(key, "not_tested", 0, reason + " (not tested)"))
            continue
        active = bool(flags.get(key))
        if active and score >= 90:
            score += points
            breakdown.append(BreakdownRow(key, "pass", points, reason))
        elif active and score < 90:
            breakdown.append(BreakdownRow(key, "bonus_skipped", 0, reason + " (bonus needs score >= 90)"))
        else:
            breakdown.append(BreakdownRow(key, "pass", 0, "No bonus"))

    if score < 0:
        score = 0

    grade = grade_from_score(score, cap_f=cap_f)
    rows = [r.as_dict() for r in breakdown]
    # Sanity: applied points (excluding not_tested / bonus_skipped zeros that are informational)
    applied = sum(int(r["points"]) for r in rows)
    # Starting 100 + applied should equal score (cap_f does not change numeric score).
    expected = max(0, 100 + applied)
    # Reconcile if floating mismatch from double-count — trust recomputation:
    score = expected if not cap_f else expected
    if score < 0:
        score = 0
    grade = grade_from_score(score, cap_f=cap_f)

    return {
        "grade": grade,
        "score": score,
        "breakdown": rows,
        "cap_f": cap_f,
        "breakdown_sum_points": applied,
    }
