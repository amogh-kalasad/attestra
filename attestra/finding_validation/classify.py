# @lat: [[findings#Lifecycle#Validation class vs workflow status]]
"""General observation classifiers for scanner import and Elite create."""

from __future__ import annotations

import re
from typing import Any

from attestra.finding_validation.headers import (
    finding_claims_header_missing,
    hsts_present_in_evidence,
    permissions_policy_present_in_evidence,
)
from attestra.finding_validation.infrastructure import (
    is_cdn_challenge_url,
    is_cdn_cors_finding,
    is_infrastructure_cookie_finding,
)
from attestra.finding_validation.statuses import (
    CONFIRMED,
    FALSE_POSITIVE,
    INFORMATIONAL,
    NEEDS_MANUAL_VALIDATION,
    NOT_REPRODUCIBLE,
    POTENTIAL,
    UNVALIDATED,
)

_XSS_PROTECTION_RE = re.compile(
    r"(?i)xss-protection|xss.deprecated.header|x-xss-protection|xss_deprecated_header"
)

_WEAK_CIPHER_RE = re.compile(r"(?i)weak[-\s]?cipher|weak\s+cipher\s+suites|cipher\s+suite")

# Suite tokens: TLS_IANA names or cipher-ish tokens with algorithm markers.
_CIPHER_EVIDENCE_RE = re.compile(
    r"(?i)\bTLS_[A-Z0-9_]+\b"
    r"|(?:^|[^A-Za-z0-9_])(?:AES|RC4|DES|3DES|CHACHA20|GCM|CBC|CCM)(?:[^A-Za-z0-9_]|$)"
    r"|\b(?:ECDHE|DHE|RSA)_(?:RSA|ECDSA|PSK)_[A-Z0-9_]+\b"
)


def _empty_result(
    status: str,
    reasons: list[str],
    *,
    severity: str | None = None,
    cwe: int | None = None,
    owasp_top10: str | None = None,
    asvs_ref: str | None = None,
    wstg_ref: str | None = None,
    clear_injection_mapping: bool = False,
) -> dict[str, Any]:
    return {
        "validation_status": status,
        "reasons": reasons,
        "severity": severity,
        "cwe": cwe,
        "owasp_top10": owasp_top10,
        "asvs_ref": asvs_ref,
        "wstg_ref": wstg_ref,
        "clear_injection_mapping": clear_injection_mapping,
    }


def _joined_evidence(evidence_refs: list[Any] | None, evidence_texts: list[str] | None) -> list[str]:
    out: list[str] = []
    for item in evidence_refs or []:
        if item is None:
            continue
        out.append(str(item))
    for item in evidence_texts or []:
        if item:
            out.append(str(item))
    return out


def _has_cipher_suite_evidence(blobs: list[str]) -> bool:
    for blob in blobs:
        if blob and _CIPHER_EVIDENCE_RE.search(blob):
            return True
    return False


def classify_observation(
    *,
    title: str,
    description: str = "",
    recommendation: str = "",
    location: str = "",
    param: str = "",
    severity: str = "",
    cwe: int | None = None,
    rule_ids: list[str] | None = None,
    evidence_refs: list[Any] | None = None,
    evidence_texts: list[str] | None = None,
    tools: list[str] | None = None,
) -> dict[str, Any]:
    """Classify a scanner/Elite observation into a validation status.

    Never hardcodes engagement finding IDs. Scanner alerts default to unvalidated.
    """
    _ = (recommendation, severity, cwe, rule_ids, tools)  # reserved for future rules
    reasons: list[str] = []
    title_s = title or ""
    desc_s = description or ""
    loc = location or ""
    evidence_blobs = _joined_evidence(evidence_refs, evidence_texts)
    evidence_joined = "\n".join(evidence_blobs)

    # 1. Infrastructure Cloudflare cookie SameSite / cookie findings.
    if is_infrastructure_cookie_finding(title_s, param or "", loc, evidence_joined):
        reasons.append(
            "Cloudflare/infrastructure cookie (e.g. cf_clearance); not an application session cookie"
        )
        return _empty_result(INFORMATIONAL, reasons)

    # 2. CDN / challenge CORS.
    if is_cdn_cors_finding(title_s, loc, evidence_joined):
        if is_cdn_challenge_url(loc):
            reasons.append("CORS on CDN/challenge resource only; not application-owned")
            return _empty_result(INFORMATIONAL, reasons)
        reasons.append("CORS/cross-domain finding on CDN/challenge URL; needs ownership proof")
        return _empty_result(NEEDS_MANUAL_VALIDATION, reasons)

    # 3. Deprecated X-XSS-Protection header (not an XSS vulnerability).
    rule_blob = " ".join(str(r) for r in (rule_ids or []))
    if _XSS_PROTECTION_RE.search(title_s) or _XSS_PROTECTION_RE.search(rule_blob):
        reasons.append(
            "Deprecated X-XSS-Protection hardening observation; not an active XSS vulnerability"
        )
        return _empty_result(
            INFORMATIONAL,
            reasons,
            severity="info",
            cwe=693,
            owasp_top10="A05:2021-Security Misconfiguration",
            wstg_ref="",
            clear_injection_mapping=True,
        )

    # 4. Header-missing claims on CDN/challenge URLs (not the application origin).
    claim = finding_claims_header_missing(title_s, desc_s)
    if claim and is_cdn_challenge_url(loc):
        reasons.append(
            f"{claim} finding targets CDN/challenge URL; validate against application responses"
        )
        return _empty_result(INFORMATIONAL, reasons)

    # 5. Header-missing claim contradicted by evidence (same finding or supplied blobs).
    if claim == "hsts" and hsts_present_in_evidence(evidence_blobs):
        reasons.append(
            "Evidence shows Strict-Transport-Security with max-age; contradicts 'HSTS not set'"
        )
        return _empty_result(NOT_REPRODUCIBLE, reasons)
    if claim == "permissions_policy" and permissions_policy_present_in_evidence(evidence_blobs):
        reasons.append(
            "Evidence shows Permissions-Policy present; contradicts 'Permissions-Policy not set'"
        )
        return _empty_result(NOT_REPRODUCIBLE, reasons)

    # 6. Weak cipher without suite names in evidence.
    weak_blob = f"{title_s}\n{desc_s}\n{rule_blob}"
    if _WEAK_CIPHER_RE.search(weak_blob) and not _has_cipher_suite_evidence(evidence_blobs):
        reasons.append("Weak-cipher finding lacks cipher suite names or handshake evidence")
        return _empty_result(NEEDS_MANUAL_VALIDATION, reasons)

    # 7. Default: scanner alerts stay unvalidated until evidence-backed confirmation.
    reasons.append("Scanner/import observation; not confirmed without validation evidence")
    return _empty_result(UNVALIDATED, reasons)


def apply_classification_to_finding(finding: Any, result: dict[str, Any]) -> None:
    """Mutate finding validation fields from classify_observation result.

    Does not change workflow ``status``.
    """
    finding.validation_status = result.get("validation_status") or UNVALIDATED
    finding.validation_reasons = list(result.get("reasons") or [])

    if result.get("severity") is not None:
        finding.severity = result["severity"]
    if result.get("cwe") is not None:
        finding.cwe = result["cwe"]
    if result.get("owasp_top10") is not None:
        finding.owasp_top10 = result["owasp_top10"]
    if result.get("asvs_ref") is not None:
        finding.asvs_ref = result["asvs_ref"]
    if result.get("wstg_ref") is not None:
        finding.wstg_ref = result["wstg_ref"]

    if result.get("clear_injection_mapping"):
        owasp = (getattr(finding, "owasp_top10", None) or "").lower()
        if "injection" in owasp or "a03" in owasp:
            finding.owasp_top10 = result.get("owasp_top10") or "A05:2021-Security Misconfiguration"
        wstg = (getattr(finding, "wstg_ref", None) or "").lower()
        if "xss" in wstg or "inject" in wstg:
            finding.wstg_ref = result.get("wstg_ref") if result.get("wstg_ref") is not None else ""


def elite_status_to_validation(elite_status: str) -> str:
    """Map Elite evidence status strings onto finding validation_status values."""
    s = (elite_status or "").strip().upper()
    if s == "CONFIRMED":
        return CONFIRMED
    if s == "POTENTIAL":
        return POTENTIAL
    if s == "NEEDS_MANUAL_REVIEW":
        return NEEDS_MANUAL_VALIDATION
    if s == "INCONCLUSIVE":
        return NEEDS_MANUAL_VALIDATION
    if s == "NOT_VULNERABLE":
        return FALSE_POSITIVE
    return UNVALIDATED


def should_create_elite_finding(validation: dict[str, Any], fp_check: dict[str, Any]) -> bool:
    """Gate Elite finding create on CONFIRMED/POTENTIAL and FP checker."""
    status = (validation.get("status") or validation.get("validation_status") or "").strip().upper()
    if status not in ("CONFIRMED", "POTENTIAL"):
        return False
    if fp_check.get("is_likely_fp"):
        return False
    return True
