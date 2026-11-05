"""Central display-label layer for report output (HTML / PDF / DOCX).

Maps raw status keys, tool ids, snake_case check keys and machine notes into
consistent human text. Display only — never mutates stored data.
"""
# @lat: [[reports#Display labels]]

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

# --- Maps --------------------------------------------------------------------

TOOL_LABELS: dict[str, str] = {
    "zap": "Zap",
    "owasp zap": "OWASP Zap",
    "owasp_zap": "OWASP Zap",
    "nuclei": "Nuclei",
    "trivy": "Trivy",
    "semgrep": "Semgrep",
    "sarif": "SARIF",
    "testssl": "testssl.sh",
    "webcheck": "Webcheck",
    "gitleaks": "Gitleaks",
    "checkov": "Checkov",
    "naabu": "Naabu",
    "prowler": "Prowler",
    "kube_bench": "kube-bench",
    "burp": "Burp",
    "nessus": "Nessus",
    "observatory": "Observatory",
    "ssllabs": "SSL Labs",
    "cyclonedx": "CycloneDX",
    "dependency_track": "Dependency-Track",
    "automated_vapt": "Automated VAPT",
    "attestra-auto": "Attestra",
    "attestra_auto": "Attestra",
}

STATUS_LABELS: dict[str, str] = {
    "passed": "Passed",
    "pass": "Passed",
    "failed": "Failed",
    "fail": "Failed",
    "skipped": "Skipped",
    "blocked": "Blocked",
    "not_started": "Not Started",
    "not_tested": "Not Tested",
    "completed": "Completed",
    "done": "Completed",
    "new": "New",
    "draft": "Draft",
    "triaged": "Triaged",
    "validated": "Validated",
    "fixed": "Fixed",
    "false_positive": "False positive",
    "risk_accepted": "Risk accepted",
    "retest_passed": "Retest passed",
    "in_progress": "In Progress",
    "running": "Running",
    "queued": "Queued",
    "error": "Error",
    "requested": "Requested",
    "inconclusive": "Inconclusive",
    "met": "Met",
    "not_met": "Not met",
    "partial": "Partial",
    "not_assessed": "Not assessed",
    "not_applicable": "Not applicable",
    "no_exceptions": "No exceptions",
    "confirmed": "Confirmed",
    "unvalidated": "Unvalidated",
    "needs_manual_validation": "Needs manual validation",
    "potential": "Potential",
    "informational": "Informational",
    "not_reproducible": "Not reproducible",
    "accepted_risk": "Accepted risk",
    "submitted": "Submitted",
    "qa_approved": "QA approved",
    "signed": "Signed",
    "rejected": "Rejected",
    "bonus_skipped": "Bonus skipped",
    "info": "Info",
}

SEVERITY_LABELS: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

ENVIRONMENT_LABELS: dict[str, str] = {
    "production": "Production",
    "staging": "Staging",
    "uat": "UAT",
    "dev": "Dev",
    "demo": "Demo",
    "development": "Development",
    "qa": "QA",
    "test": "Test",
    "all": "All",
}

EXPOSURE_LABELS: dict[str, str] = {
    "internet": "Internet",
    "internal": "Internal",
    "partner": "Partner",
    "restricted": "Restricted",
}

# Explicit status-check display names (never auto Title Case these).
CHECK_LABELS: dict[str, str] = {
    "cache_control_directives": "Cache-control directives",
    "cache-control directives": "Cache-control directives",
    "content_security_policy_directives": "Content-Security-Policy directives",
    "content_security_policy_header": "Content-Security-Policy header",
    "content-security-policy header": "Content-Security-Policy header",
    "cookie_secure_flag": "Cookie Secure flag",
    "cookie_httponly_flag": "Cookie HttpOnly flag",
    "cookie_samesite_attribute": "Cookie SameSite attribute",
    "cross_origin_isolation_headers": "Cross-Origin isolation headers (COEP/COOP/CORP)",
    "cross-origin isolation headers (coep/coop/corp)": "Cross-Origin isolation headers (COEP/COOP/CORP)",
    "cross_domain_misconfiguration": "Cross-domain misconfiguration",
    "loosely_scoped_cookie": "Loosely scoped cookie",
    "modern_web_application": "Modern web application",
    "permissions_policy_feature_policy": "Permissions-Policy / Feature-Policy",
    "permissions-policy / feature-policy": "Permissions-Policy / Feature-Policy",
    "retrieved_from_cache": "Retrieved from cache",
    "session_management_response_identified": "Session management response identified",
    "storable_and_cacheable_content": "Storable and cacheable content",
    "strict_transport_security_hsts": "Strict-Transport-Security (HSTS)",
    "strict-transport-security (hsts)": "Strict-Transport-Security (HSTS)",
    "timestamp_disclosure_unix": "Timestamp disclosure (Unix)",
    "timestamp disclosure (unix)": "Timestamp disclosure (Unix)",
    "character_set_content_type": "Character set / Content-Type",
    "character set / content-type": "Character set / Content-Type",
    "x_content_type_options_header": "X-Content-Type-Options header",
    "x-content-type-options header": "X-Content-Type-Options header",
    "x_frame_options_header": "X-Frame-Options header",
    "x-frame-options header": "X-Frame-Options header",
    "x_xss_protection_header": "X-XSS-Protection header",
    "x-xss-protection header": "X-XSS-Protection header",
}

# Site-grades check keys (exact display strings).
SITE_GRADE_LABELS: dict[str, str] = {
    "csp_missing": "CSP missing",
    "csp_unsafe_inline": "CSP unsafe-inline",
    "csp_strong": "CSP strong",
    "hsts_missing": "HSTS missing",
    "hsts_short": "HSTS short",
    "hsts_preload": "HSTS preload",
    "cookie_secure": "Cookie Secure",
    "cookie_httponly": "Cookie HttpOnly",
    "cookie_samesite": "Cookie SameSite",
    "tls_legacy": "Legacy TLS",
    "tls_weak_cipher": "Weak TLS cipher",
}

# Evidence register kind labels.
EVIDENCE_KIND_LABELS: dict[str, str] = {
    "http_pair": "HTTP pair",
    "screenshot": "Screenshot",
    "log": "Log",
    "code": "Code",
    "package": "Package",
    "capture_failure": "Capture failure",
}

# Known humanize overrides (exact key match after lower/normalize).
HUMANIZE_OVERRIDES: dict[str, str] = {
    **SITE_GRADE_LABELS,
    "exact_fingerprint": "Exact fingerprint",
    "legacy_fingerprint": "Legacy fingerprint",
    "same_asset+cwe_and_location": "Same asset, CWE and location",
    "same_asset+cwe_and_location+cross_tool": "Same asset, CWE and location, cross-tool",
    "same_asset+cwe_and_location+same_param": "Same asset, CWE and location, same parameter",
    "same_asset+cwe_and_location+same_title_and_location": "Same asset, CWE and location, same title and location",
    "clickjacking": "Clickjacking",
    "http_no_https_redirect": "HTTP does not redirect to HTTPS",
    "refuse_reason": "Refusal reason",
}

_ACRONYMS = frozenset({
    "csp", "hsts", "tls", "ssl", "cwe", "cve", "api", "idor", "bola", "vapt", "http", "https",
    "dns", "spf", "dkim", "dmarc", "caa", "dane", "tlsa", "asvs", "wstg", "cvss", "epss", "kev",
    "pci", "nist", "owasp", "sarif", "xss", "sqli", "ssrf", "csrf", "jwt", "mtls", "cdn", "waf",
    "json", "xml", "html", "url", "uri", "uuid", "sha", "md5", "coa", "soc", "iis", "cors",
    "coep", "coop", "corp", "sql",
})

# Multi-word / header tokens preserved exactly when humanizing.
_HEADER_TOKENS: dict[str, str] = {
    "httponly": "HttpOnly",
    "samesite": "SameSite",
    "x-content-type-options": "X-Content-Type-Options",
    "x_content_type_options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "x_frame_options": "X-Frame-Options",
    "x-xss-protection": "X-XSS-Protection",
    "x_xss_protection": "X-XSS-Protection",
}

_FRAMEWORK_FALLBACK: dict[str, str] = {
    "iso_27001_2022": "ISO/IEC 27001:2022",
    "soc2": "SOC 2",
    "asvs_4_0": "OWASP ASVS 4.0",
    "nist_csf_2": "NIST CSF 2.0",
    "pci_dss_4": "PCI DSS 4.0",
    "cert_in_2022": "CERT-In 2022",
    "iso_42001_2023": "ISO/IEC 42001:2023",
    "dora_2022": "DORA 2022",
    "rbi_csf_2016": "RBI CSF 2016",
    "sebi_cscrf_2024": "SEBI CSCRF 2024",
}

# Words that must stay lowercase in Title Case (except at start).
_SMALL_TITLE = frozenset({
    "a", "an", "and", "as", "at", "by", "for", "in", "of", "on", "or", "per", "the", "to",
    "vs", "via", "with", "all", "always", "any", "only", "each", "every", "both", "from",
    "into", "over", "under", "than", "then", "when", "where", "while", "without",
})


def _norm_key(value: str) -> str:
    return (value or "").strip().lower().replace("-", "_").replace(" ", "_")


def tool_label(value: str | None) -> str:
    """Canonical scanner / importer display name (Zap, Nuclei, Automated VAPT, …)."""
    raw = (value or "").strip()
    if not raw:
        return ""
    key = raw.lower().replace("-", "_")
    if key in TOOL_LABELS:
        return TOOL_LABELS[key]
    if raw.lower() in TOOL_LABELS:
        return TOOL_LABELS[raw.lower()]
    # Bracketed tags like [zap]
    inner = re.fullmatch(r"\[([^\]]+)\]", raw)
    if inner:
        return tool_label(inner.group(1))
    return raw[:1].upper() + raw[1:] if raw else ""


def status_label(value: str | None) -> str:
    """Canonical status display label."""
    raw = (value or "").strip()
    if not raw:
        return ""
    key = _norm_key(raw)
    if key in STATUS_LABELS:
        return STATUS_LABELS[key]
    if raw in STATUS_LABELS.values():
        return raw
    return humanize(raw)


def severity_label(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    return SEVERITY_LABELS.get(raw.lower(), raw[:1].upper() + raw[1:].lower())


def environment_label(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    key = _norm_key(raw)
    return ENVIRONMENT_LABELS.get(key, humanize(raw))


def exposure_label(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    return EXPOSURE_LABELS.get(raw.lower(), humanize(raw))


def framework_label(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        from attestra.compliance.engine import load_library

        meta = load_library().frameworks.get(raw) or load_library().frameworks.get(raw.lower())
        if isinstance(meta, dict) and meta.get("name"):
            return str(meta["name"])
    except Exception:
        pass
    return _FRAMEWORK_FALLBACK.get(raw.lower(), humanize(raw))


def frameworks_label(values: Iterable[str] | None) -> str:
    names = [framework_label(v) for v in (values or []) if v]
    return ", ".join(names) if names else "none"


def check_label(value: str | None) -> str:
    """Status-check / site-grade display name from explicit maps (not Title Case)."""
    raw = (value or "").strip()
    if not raw:
        return ""
    low = raw.lower().strip()
    norm = _norm_key(raw)
    if low in CHECK_LABELS:
        return CHECK_LABELS[low]
    if norm in CHECK_LABELS:
        return CHECK_LABELS[norm]
    if norm in SITE_GRADE_LABELS:
        return SITE_GRADE_LABELS[norm]
    if low in SITE_GRADE_LABELS:
        return SITE_GRADE_LABELS[low]
    return humanize(raw)


def evidence_kind_label(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    return EVIDENCE_KIND_LABELS.get(_norm_key(raw), humanize(raw))


def evidence_note_label(note: str | None) -> str:
    """Rewrite 'auto-captured from nuclei' → 'auto-captured from Nuclei' (display only)."""
    raw = (note or "").strip()
    if not raw:
        return ""

    def _tool(m: re.Match) -> str:
        return f"{m.group(1)}{tool_label(m.group(2))}"

    return re.sub(r"(?i)\b(auto-captured from\s+)([a-z0-9_\-]+)", _tool, raw)


def humanize(key: str | None) -> str:
    """snake_case / kebab / plus-joined keys → sentence case with acronyms kept (not Title Case)."""
    raw = (key or "").strip()
    if not raw:
        return ""
    low = raw.lower()
    if low in HUMANIZE_OVERRIDES:
        return HUMANIZE_OVERRIDES[low]
    if low in CHECK_LABELS:
        return CHECK_LABELS[low]
    if _norm_key(raw) in CHECK_LABELS:
        return CHECK_LABELS[_norm_key(raw)]
    # soft:/ambiguous: prefixes from dedup
    for prefix in ("soft:", "ambiguous:"):
        if low.startswith(prefix):
            return f"{prefix[:-1].capitalize()}: {humanize(raw[len(prefix):])}"
    # plus-joined concept keys → "A, B and C"
    if "+" in raw:
        parts = [humanize(part) for part in raw.split("+") if part.strip()]
        if len(parts) <= 1:
            return parts[0] if parts else ""
        if len(parts) == 2:
            return f"{parts[0]} and {parts[1]}"
        return ", ".join(parts[:-1]) + f" and {parts[-1]}"
    # snake / kebab — sentence case (first word capital, rest lower unless acronym/header)
    parts = re.split(r"[_\s]+", raw.replace("-", " ").strip())
    out: list[str] = []
    for i, part in enumerate(parts):
        if not part:
            continue
        pl = part.lower()
        if pl in _HEADER_TOKENS:
            out.append(_HEADER_TOKENS[pl])
        elif pl in _ACRONYMS:
            out.append(pl.upper())
        elif pl in _SMALL_TITLE and i > 0:
            out.append(pl)
        elif part.isupper() or any(c.isdigit() for c in part):
            out.append(part)
        elif i == 0:
            out.append(part[:1].upper() + part[1:].lower())
        else:
            out.append(part.lower())
    return " ".join(out)


def plural(n: int | float | str | None, singular: str, plural_form: str | None = None) -> str:
    """Format a count with a singular/plural noun (never '(s)')."""
    try:
        count = int(n or 0)
    except (TypeError, ValueError):
        count = 0
    word = singular if count == 1 else (plural_form or (singular + "s"))
    return f"{count} {word}"


def _display_tz():
    name = os.environ.get("ATTESTRA_DISPLAY_TZ", "Asia/Kolkata")
    try:
        return ZoneInfo(name)
    except Exception:
        if name == "Asia/Kolkata":
            return timezone(timedelta(hours=5, minutes=30), "IST")
        return UTC


def format_date(value: Any) -> str:
    """ISO calendar date: 2026-11-04."""
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    text = str(value).strip()
    m = re.match(r"(\d{4}-\d{2}-\d{2})", text)
    return m.group(1) if m else text


def format_datetime(value: Any) -> str:
    """Display datetime once as '5 Nov 2026, 03:27 IST' (never 'IST India Standard Time').

    Uses day-month form (not ``YYYY-MM-DD HH:MM``) so pdf ``_human_times`` — which
    rematches ISO-like stamps even when a zone is already present — does not append
    a second ``IST``.
    """
    if value is None or value == "":
        return ""
    dt: datetime | None = None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        return value.isoformat()
    else:
        text = str(value).strip()
        # Strip verbose zone suffixes first.
        text = re.sub(r"\s+India Standard Time\b", "", text, flags=re.I)
        text = re.sub(r"\b([A-Z]{2,5})\s+\1\b", r"\1", text)  # IST IST
        # Already in display form — return as-is (zone collapsed above).
        if re.match(r"^\d{1,2} \w{3} \d{4}, \d{2}:\d{2}\s+[A-Z]{2,5}$", text):
            return text
        try:
            if text.endswith("Z"):
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(text)
        except ValueError:
            # Already human ISO-ish: convert date+time+zone without a second pass later.
            m = re.match(
                r"(\d{4}-\d{2}-\d{2})[ T](\d{1,2}):(\d{2})(?::\d{2})?(?:\.\d+)?\s*([A-Z]{2,5})?",
                text,
            )
            if m:
                try:
                    dt = datetime(
                        int(m.group(1)[0:4]),
                        int(m.group(1)[5:7]),
                        int(m.group(1)[8:10]),
                        int(m.group(2)),
                        int(m.group(3)),
                        tzinfo=_display_tz() if m.group(4) else UTC,
                    )
                except ValueError:
                    zone = m.group(4) or ""
                    return f"{m.group(1)} {int(m.group(2)):02d}:{m.group(3)}" + (f" {zone}" if zone else "")
            else:
                return text
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    local = dt.astimezone(_display_tz())
    zone = local.tzname() or "UTC"
    # Collapse verbose names.
    if "India" in (zone or "") or zone == "India Standard Time":
        zone = "IST"
    return f"{local.strftime('%d %b %Y, %H:%M').lstrip('0')} {zone}"


def words_title(value: str | None) -> str:
    """Capitalize first letter of each word for cover/engagement names (display only)."""
    raw = (value or "").strip()
    if not raw:
        return ""
    parts = re.split(r"(\s+)", raw)
    out: list[str] = []
    for part in parts:
        if not part or part.isspace():
            out.append(part)
            continue
        if part.isupper() and len(part) <= 4:
            out.append(part)
        else:
            out.append(part[:1].upper() + part[1:] if part else part)
    return "".join(out)


def section_title(value: str | None) -> str:
    """Title Case for section headings; keep small words lowercase except at start."""
    raw = (value or "").strip()
    if not raw:
        return ""
    words = raw.split(" ")
    out: list[str] = []
    for i, w in enumerate(words):
        core = w.strip("()[]:,.;\"'")
        if not core:
            out.append(w)
            continue
        low = core.lower()
        if low in _ACRONYMS:
            repl = low.upper()
        elif i and low in _SMALL_TITLE:
            repl = low
        elif any(c.isupper() for c in core[1:]) or any(c.isdigit() for c in core):
            repl = core
        else:
            repl = core[:1].upper() + core[1:].lower()
        j = w.find(core[0])
        out.append(w[:j] + repl + w[j + len(core) :])
    return " ".join(out)


def param_label(text: str | None) -> str:
    """Render [param: x] as (Parameter: x); otherinfo:/evidence: prefixes cleaned."""
    raw = text or ""
    raw = re.sub(r"\[param:\s*([^\]]+)\]", r"(Parameter: \1)", raw, flags=re.I)
    raw = re.sub(r"\botherinfo:\s*", "Other info: ", raw, flags=re.I)
    raw = re.sub(r"\bevidence:\s*", "Evidence: ", raw, flags=re.I)
    return raw


def dedup_label(rationale: str | None) -> str:
    """Humanize a stored dedup_rationale for the Deduplication column (sentence case)."""
    raw = (rationale or "").strip()
    if not raw:
        return ""
    return humanize(raw)


def consolidate_sentence(rationale: str | None) -> str:
    """Turn a merge rationale into a full sentence for the Consolidated row (no repeated label)."""
    raw = (rationale or "").strip().rstrip(";")
    if not raw:
        return ""
    raw = re.sub(r"(?i)^consolidated:\s*", "", raw).strip()
    # "same issue (key) reported by A, B"
    m = re.match(r"(?i)^same issue \((.+)\) reported by (.+)$", raw)
    if m:
        key, who = m.group(1), m.group(2)
        parts = [p.strip() for p in re.split(r",\s*", who) if p.strip()]
        labeled = [tool_label(p) if p == p.lower() else p for p in parts]
        if len(labeled) == 1:
            who_txt = labeled[0]
        elif len(labeled) == 2:
            who_txt = f"{labeled[0]} and {labeled[1]}"
        else:
            who_txt = ", ".join(labeled[:-1]) + f" and {labeled[-1]}"
        issue = humanize(key) if ("_" in key or "+" in key or key.islower()) else key
        return (
            f"The same issue ({issue}) was reported by {who_txt}. "
            "The related results are listed once under Sources."
        )
    # "5 Nuclei results on different URLs"
    if re.search(r"(?i)\bon different urls\b", raw) or re.search(r"(?i)\bresults?\b", raw):
        body = raw[0].upper() + raw[1:] if raw else raw
        if not body.endswith("."):
            body += "."
        if "related results are listed" not in body.lower():
            body += " The related results are listed once under Sources."
        return body
    body = raw[0].upper() + raw[1:] if raw else raw
    if not body.endswith("."):
        body += "."
    if "related results are listed" not in body.lower():
        body += " The related results are listed once under Sources."
    return body


def test_name_label(test_id: str | None, title: str | None = None) -> str:
    """T19 · API authentication bypass (keep API/IDOR/BOLA/HTTP uppercase)."""
    tid = (test_id or "").strip()
    tit = (title or "").strip()
    if not tit:
        return tid
    # Sentence case with acronym protection.
    words = tit.split(" ")
    out: list[str] = []
    for i, w in enumerate(words):
        core = w.strip("()[]:,.;\"'/")
        low = core.lower()
        if low in _ACRONYMS:
            out.append(w.replace(core, low.upper()))
        elif i == 0:
            out.append(w[:1].upper() + w[1:] if w else w)
        else:
            # keep existing internal caps (API) else lower
            if core.isupper() and len(core) <= 5:
                out.append(w)
            else:
                out.append(w[:1].lower() + w[1:] if w and w[0].isupper() and i > 0 else w)
    # Fix first word capital
    if out:
        o0 = out[0]
        out[0] = o0[:1].upper() + o0[1:] if o0 else o0
    body = " ".join(out)
    return f"{tid} · {body}" if tid else body


def automated_run_header(
    *,
    status: str,
    profile: str | None,
    finished_at: Any,
    case_count: int,
    image_count: int,
) -> str:
    """Status: Completed · Profile: Baseline · Finished: <dt> · 5 test cases, 0 images"""
    bits = [f"Status: {status_label(status)}"]
    if profile:
        bits.append(f"Profile: {words_title(profile.replace('_', ' '))}")
    if finished_at:
        bits.append(f"Finished: {format_datetime(finished_at)}")
    bits.append(f"{plural(case_count, 'test case')}, {plural(image_count, 'image')}")
    return " · ".join(bits)


# --- Sentence formatting for machine notes -----------------------------------

_PAGE_FRAC = re.compile(
    r"(?i)\bHTTP captured for (\d+)/(\d+) pages? \(([^)]+)\)(?:;\s*HTTP (\d+)x(\d+))?(?:;\s*auth:\s*(.+))?$"
)
_AUTH_BYPASS = re.compile(
    r"(?i)\bauth bypass:\s*(\d+) findings? across (\d+) endpoints?(?:;\s*auth:\s*(.+))?$"
)
_GENERIC_FINDINGS = re.compile(
    r"(?i)^([a-z _/-]+):\s*(\d+) findings? across (\d+) (endpoints?|probes?)(?:;\s*auth:\s*(.+))?$"
)
_NO_OBJECT_IDS = re.compile(
    r"(?i)^no object ids harvested from authenticated API responses\.?$"
)
_NO_BODIES = re.compile(
    r"(?i)^no captured POST/PUT/PATCH JSON bodies with object-id fields to mutate;\s*"
    r"JS discovery listed (\d+) write endpoints? but no request bodies were captured\.?$"
)
_AUTO_NOTE = re.compile(
    r"(?is)^auto:\s*(passed|failed|blocked)\s+by\s+(\S+)\s+at\s+(.+?)\s*-\s*\[([^\]]+)\]\s*(.+)$"
)
_ARROW_FINDINGS = re.compile(r"\s*->\s*")
_PLUS_MORE = re.compile(r"\(\+(\d+)\s*more\)", re.I)


def _fmt_auth_tail(tail: str | None) -> str:
    if not tail:
        return ""
    t = tail.strip()
    m = re.match(r"(?i)ready\s*\(profile\s*#?(\d+)\)", t)
    if m:
        return f"Authentication: ready (profile #{m.group(1)})."
    return f"Authentication: {t.rstrip('.')}."


def _fmt_source(source: str) -> str:
    """zap-scan-1+js -> Zap scan 1 with JavaScript."""
    s = source.strip()
    s = s.replace("+js", " with JavaScript").replace("+JS", " with JavaScript")
    s = re.sub(r"(?i)\bzap-scan-(\d+)", r"Zap scan \1", s)
    s = re.sub(r"(?i)\bnuclei-scan-(\d+)", r"Nuclei scan \1", s)
    s = re.sub(r"(?i)\bwebcheck-scan-(\d+)", r"Webcheck scan \1", s)
    s = re.sub(r"(?i)\bautomated[_-]vapt", "Automated VAPT", s)
    return s


def format_detail_sentence(text: str | None) -> str:
    """Turn raw automated-test / scan detail logs into readable sentences."""
    raw = (text or "").strip()
    if not raw:
        return ""
    # Normalize "(s)" plurals before pattern match so both forms are accepted.
    raw = re.sub(r"\b(\w+)\(s\)", r"\1s", raw)

    m = _PAGE_FRAC.match(raw)
    if m:
        ok, total, source, code, times, auth = m.groups()
        ok_i, total_i = int(ok), int(total)
        if ok_i == total_i:
            head = f"HTTP captured for all {total_i} pages ({_fmt_source(source)})."
        else:
            head = f"HTTP captured for {ok_i} of {total_i} pages ({_fmt_source(source)})."
        parts = [head]
        if code and times:
            if int(times) == total_i:
                parts.append(f"All {times} responses returned HTTP {code}.")
            else:
                parts.append(f"{times} responses returned HTTP {code}.")
        auth_s = _fmt_auth_tail(auth)
        if auth_s:
            parts.append(auth_s)
        return " ".join(parts)

    m = _AUTH_BYPASS.match(raw)
    if m:
        findings, endpoints, auth = m.groups()
        parts = [
            f"Authentication bypass: {plural(findings, 'finding')} across {plural(endpoints, 'endpoint')}."
        ]
        auth_s = _fmt_auth_tail(auth)
        if auth_s:
            parts.append(auth_s)
        return " ".join(parts)

    m = _GENERIC_FINDINGS.match(raw)
    if m:
        kind, findings, n, unit, auth = m.groups()
        label = humanize(kind.strip())
        unit_word = "endpoint" if unit.lower().startswith("endpoint") else "probe"
        parts = [f"{label}: {plural(findings, 'finding')} across {plural(n, unit_word)}."]
        auth_s = _fmt_auth_tail(auth)
        if auth_s:
            parts.append(auth_s)
        return " ".join(parts)

    if _NO_OBJECT_IDS.match(raw):
        return "No object IDs were harvested from authenticated API responses."

    m = _NO_BODIES.match(raw)
    if m:
        n = m.group(1)
        return (
            "No POST, PUT or PATCH JSON bodies with object ID fields were captured to mutate. "
            f"JavaScript discovery listed {plural(n, 'write endpoint')}, but no request bodies were captured."
        )

    # Fallback light cleanup
    out = re.sub(r"\b(\d+) page\(s\)", lambda m: plural(m.group(1), "page"), raw)
    out = re.sub(r"\b(\d+) finding\(s\)", lambda m: plural(m.group(1), "finding"), out)
    out = re.sub(r"\b(\d+) endpoint\(s\)", lambda m: plural(m.group(1), "endpoint"), out)
    out = re.sub(r"\b(\d+) probe\(s\)", lambda m: plural(m.group(1), "probe"), out)
    out = re.sub(r"\b(\d+) image\(s\)", lambda m: plural(m.group(1), "image"), out)
    out = re.sub(r"\b(\d+) test case\(s\)", lambda m: plural(m.group(1), "test case"), out)
    if out and out[0].islower():
        out = out[:1].upper() + out[1:]
    return out


def _dedupe_adjacent_words(text: str) -> str:
    """Drop duplicated adjacent words: 'Automated VAPT Automated VAPT', 'Zap Zap'."""
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r"\b([\w][\w+./-]*(?:\s+[\w][\w+./-]*){0,3})\s+\1\b", r"\1", text, flags=re.I)
    text = re.sub(r"\bFindings:\s*findings?\b", "Findings:", text, flags=re.I)
    return text


def format_checklist_note(note: str | None) -> str:
    """Format auth-checklist Notes column (auto: … → Automated: …)."""
    raw = (note or "").strip()
    if not raw:
        return ""
    m = _AUTO_NOTE.match(raw)
    if m:
        status, actor, ts, tool, rest = m.groups()
        actor_l = tool_label(actor) if actor.lower() in ("attestra-auto", "attestra_auto") else words_title(actor)
        tool_l = tool_label(tool)
        when = format_datetime(ts)
        rest = rest.strip()
        # Prefer detail-sentence rewrite for the parenthetical / trailing detail.
        detail_m = re.search(r"^(.+?):\s*(.+)$", rest, flags=re.I)
        if detail_m and "(" not in detail_m.group(1):
            head, tail = detail_m.group(1).strip(), detail_m.group(2).strip()
            # "automated run #1 T19: no issues (...)"
            head = re.sub(r"(?i)\bautomated run\b", "Automated VAPT run", head)
            head = re.sub(r"(?i)\bwebcheck import\b", "Webcheck import", head)
            head = re.sub(r"(?i)\bzap import\b", "Zap import", head)
            head = re.sub(r"(?i)\bnuclei import\b", "Nuclei import", head)
            # Strip a leading tool name that duplicates tool_l
            head = re.sub(rf"(?i)^{re.escape(tool_l)}\s+", "", head).strip()
            tail = _ARROW_FINDINGS.sub(". Findings: ", tail)
            tail = _PLUS_MORE.sub(lambda mm: f"and {mm.group(1)} more", tail)
            # Rewrite inner machine detail when present in parentheses or after colon.
            inner = re.match(r"(?i)^no issues\s*\((.+)\)\s*$", tail)
            if inner:
                tail = f"no issues ({format_detail_sentence(inner.group(1)).rstrip('.')})"
            else:
                # "… alerted -> findings #1 …"
                tail = format_detail_sentence(tail) if re.search(r"\(s\)|finding|endpoint|auth:", tail, re.I) else tail
            rest = f"{head}: {tail}"
        else:
            rest = re.sub(r"(?i)\bautomated run\b", "Automated VAPT run", rest)
            rest = re.sub(r"(?i)\bwebcheck import\b", "Webcheck import", rest)
            rest = re.sub(r"(?i)\bzap import\b", "Zap import", rest)
            rest = re.sub(r"(?i)\bnuclei import\b", "Nuclei import", rest)
            rest = re.sub(rf"(?i)^{re.escape(tool_l)}\s+", "", rest).strip()
            rest = _ARROW_FINDINGS.sub(". Findings: ", rest)
            rest = _PLUS_MORE.sub(lambda mm: f"and {mm.group(1)} more", rest)
        rest = re.sub(r"\bfindings?:\s*#", "Findings: #", rest, flags=re.I)
        rest = re.sub(r"\b(\w+)\(s\)", r"\1s", rest)
        out = f"Automated: {status_label(status)} by {actor_l} on {when}. {tool_l} {rest}".strip()
        return _dedupe_adjacent_words(out)
    # Blocked / detail-only notes
    if re.match(r"(?i)^blocked:\s*", raw) or re.match(r"(?i)^no object ids\b", raw):
        body = format_detail_sentence(re.sub(r"(?i)^blocked:\s*", "", raw))
        return f"Blocked: {body[0].lower() + body[1:] if body else body}".rstrip(".") + "."
    out = format_detail_sentence(raw)
    out = _ARROW_FINDINGS.sub(". Findings: ", out)
    out = _PLUS_MORE.sub(lambda mm: f"and {mm.group(1)} more", out)
    out = re.sub(r"\[(zap|nuclei|webcheck|automated_vapt)\]", lambda m: tool_label(m.group(1)), out, flags=re.I)
    return _dedupe_adjacent_words(out)


def recommendation_to_bullets(text: str | None) -> str:
    """Split long numbered/conditional remediation into HTML list items (display)."""
    raw = (text or "").strip()
    if not raw:
        return ""
    # Numbered 1. / 2. / (1) — at line start or mid-paragraph after a sentence break.
    parts = re.split(r"(?:^|\n|(?<=[.!;])\s+)(?:\d+[\.)]\s+|\(\d+\)\s+)", raw)
    parts = [p.strip(" \n;") for p in parts if p and p.strip()]
    if len(parts) >= 2:
        items = "".join(f"<li>{_escape_keep(p)}</li>" for p in parts)
        return f"<ul class=\"fix-steps\">{items}</ul>"
    # Semicolon-separated conditionals
    if raw.count(";") >= 2 and len(raw) > 180:
        chunks = [c.strip() for c in raw.split(";") if c.strip()]
        if len(chunks) >= 3:
            items = "".join(f"<li>{_escape_keep(c.rstrip('.'))}.</li>" for c in chunks)
            return f"<ul class=\"fix-steps\">{items}</ul>"
    return ""


def _escape_keep(text: str) -> str:
    from html import escape

    return escape(text, quote=False)


def register_jinja_filters(env: Any) -> None:
    """Attach display-label filters to a Jinja environment."""
    env.filters["tool_label"] = tool_label
    env.filters["status_label"] = status_label
    env.filters["severity_label"] = severity_label
    env.filters["environment_label"] = environment_label
    env.filters["exposure_label"] = exposure_label
    env.filters["framework_label"] = framework_label
    env.filters["frameworks_label"] = frameworks_label
    env.filters["humanize"] = humanize
    env.filters["check_label"] = check_label
    env.filters["evidence_kind_label"] = evidence_kind_label
    env.filters["evidence_note_label"] = evidence_note_label
    env.filters["plural"] = plural
    env.filters["format_date"] = format_date
    env.filters["format_datetime"] = format_datetime
    env.filters["words_title"] = words_title
    env.filters["section_title"] = section_title
    env.filters["param_label"] = param_label
    env.filters["dedup_label"] = dedup_label
    env.filters["consolidate_sentence"] = consolidate_sentence
    env.filters["format_detail_sentence"] = format_detail_sentence
    env.filters["format_checklist_note"] = format_checklist_note
    env.filters["test_name_label"] = test_name_label
    env.filters["recommendation_to_bullets"] = recommendation_to_bullets
    env.globals["plural"] = plural
    env.globals["automated_run_header"] = automated_run_header
    env.globals["recommendation_to_bullets"] = recommendation_to_bullets
    env.globals["test_name_label"] = test_name_label
