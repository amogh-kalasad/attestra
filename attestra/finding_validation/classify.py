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

# Hyphen, underscore, or space between XSS and Protection; ZAP 10016 rule id.
_XSS_PROTECTION_RE = re.compile(
    r"(?i)xss[-_\s]?protection|xss\.?deprecated[.\-_]?header|x-xss-protection"
    r"|xss_deprecated_header|(?:^|[\s,;])10016(?:$|[\s,;:])"
)

# Expect-CT header retired by browsers (Chrome 107+); never a Medium/Confirmed vuln.
_EXPECT_CT_RE = re.compile(
    r"(?i)expect[-_\s]?ct|expect\.?ct[.\-_]?header|(?:^|[\s,;/])expect-ct(?:$|[\s,;:])"
)

# SPF on a name without MX (often subdomain noise; apex may inherit/manage mail).
_SPF_NO_MX_RE = re.compile(
    r"(?i)(?:dns[/\s:_-]*spf|spf\s+record).{0,80}without\s+mx"
    r"|no\s+spf\s+record\s+on\s+host\s+without\s+mx"
    r"|(?:^|[\s,;/])dns-spf(?:$|[\s,;:])"
)

# DANE/TLSA missing — impractical without DNSSEC (e.g. Cloudflare proxy).
_DANE_TLSA_RE = re.compile(
    r"(?i)(?:no\s+)?dane(?:\s*\(?\s*tlsa\s*\)?)?"
    r"|no\s+tlsa\s+record"
    r"|(?:^|[\s,;/])dns-tlsa(?:$|[\s,;:])"
    r"|tlsa\s*\(dane\)"
)

# HTTPS already enforced (redirect / HTTPS-only) — no SSL-strip PoC assumed.
_HTTPS_ENFORCEMENT_RE = re.compile(
    r"(?i)(?:\b(?:301|308)\b).{0,100}https://"
    r"|location:\s*https://"
    r"|redirect(?:s|ed|ing)?\s+(?:permanently\s+)?(?:to\s+)?https"
    r"|http\s*(?:to|→|->)\s*https"
    r"|upgrades?\s+to\s+https"
    r"|https[-\s]?only"
    r"|http\s+not\s+served"
    r"|permanent\s+redirect.{0,60}https"
)

# Confirmed SSL-strip / MITM downgrade path — do not auto-cap HSTS severity.
_SSL_STRIP_POC_RE = re.compile(
    r"(?i)ssl[-\s]?strip|sslstrip"
    r"|mitm\s+downgrade|downgrade\s+attack\s+confirm"
    r"|confirmed\s+(?:ssl\s+)?stripp"
    r"|exploit(?:ed|ation)?\s+path.{0,60}(?:hsts|https|ssl\s*strip)"
)

_WEAK_CIPHER_RE = re.compile(r"(?i)weak[-\s]?cipher|weak\s+cipher\s+suites|cipher\s+suite")

# Suite tokens: IANA TLS_/SSL_ names, OpenSSL hyphenated suites, or algorithm markers.
# Protocol versions alone (TLS 1.0) do not count — suite or handshake proof required.
_CIPHER_EVIDENCE_RE = re.compile(
    r"(?i)\b(?:TLS|SSL)_[A-Z0-9_]+\b"
    r"|\b(?:(?:ECDHE|DHE|EECDH|EDH|AECDH)-)?(?:(?:RSA|ECDSA|DSS|PSK|anon)-)?"
    r"(?:AES(?:128|256)?(?:GCM|CCM)?|CHACHA20-POLY1305|RC4(?:-\d+)?|3DES|DES-CBC3|"
    r"CAMELLIA(?:128|256)?|ARIA(?:128|256)?)"
    r"(?:-(?:SHA(?:256|384)?|MD5|POLY1305|GCM-SHA\d+|CCM(?:8)?-SHA\d+))*\b"
    r"|(?:^|[^A-Za-z0-9_])(?:AES|RC4|DES|3DES|CHACHA20|GCM|CBC|CCM)(?:[^A-Za-z0-9_]|$)"
    r"|\b(?:ECDHE|DHE|RSA)_(?:RSA|ECDSA|PSK)_[A-Z0-9_]+\b"
)
_HANDSHAKE_SUITE_RE = re.compile(
    r"(?i)(?:ClientHello|ServerHello).{0,120}(?:cipher|suite)"
    r"|cipher\s*suite\s*[:=]\s*\S+"
    r"|offered\s+ciphers?\s*[:=]\s*\S+"
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
    """True when evidence text names a cipher suite or handshake cipher proof.

    Protocol version strings alone are insufficient (ENG1 F-10).
    """
    for blob in blobs:
        if not blob:
            continue
        if _CIPHER_EVIDENCE_RE.search(blob) or _HANDSHAKE_SUITE_RE.search(blob):
            return True
    return False


def _blob_has(pattern: re.Pattern[str], blobs: list[str]) -> bool:
    for blob in blobs:
        if blob and pattern.search(blob):
            return True
    return False


def _has_ssl_strip_poc(blobs: list[str]) -> bool:
    """True when evidence claims a confirmed SSL-strip / MITM downgrade path."""
    return _blob_has(_SSL_STRIP_POC_RE, blobs)


def _has_https_enforcement_evidence(blobs: list[str], location: str = "") -> bool:
    """True when evidence shows HTTP→HTTPS redirect or HTTPS-only serving."""
    if _blob_has(_HTTPS_ENFORCEMENT_RE, blobs):
        return True
    # Bare https:// location alone is not enough (HSTS checks already run on HTTPS).
    _ = location
    return False


def _is_spf_without_mx(title: str, description: str, rule_blob: str) -> bool:
    blob = f"{title}\n{description}\n{rule_blob}"
    return bool(_SPF_NO_MX_RE.search(blob))


def _is_dane_tlsa_missing(title: str, description: str, rule_blob: str) -> bool:
    blob = f"{title}\n{description}\n{rule_blob}"
    return bool(_DANE_TLSA_RE.search(blob))


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
    _ = (recommendation, cwe, tools)  # reserved for future rules
    reasons: list[str] = []
    title_s = title or ""
    desc_s = description or ""
    loc = location or ""
    evidence_blobs = _joined_evidence(evidence_refs, evidence_texts)
    evidence_joined = "\n".join(evidence_blobs)
    # Title/description count as context for HTTPS-enforcement / SSL-strip signals.
    context_blobs = list(evidence_blobs)
    if desc_s:
        context_blobs.append(desc_s)
    if title_s:
        context_blobs.append(title_s)

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
        # Remap off CWE-79 / Injection / reflected-XSS ASVS+WSTG onto CWE-693 misconfig.
        return _empty_result(
            INFORMATIONAL,
            reasons,
            severity="info",
            cwe=693,
            owasp_top10="A05:2021-Security Misconfiguration",
            asvs_ref="V14.4.3",
            wstg_ref="WSTG-CONF-12",
            clear_injection_mapping=True,
        )

    # 3b. Expect-CT obsolete (Chrome 107+); never Confirmed and never a Medium vuln.
    expect_blob = f"{title_s}\n{desc_s}\n{rule_blob}"
    if _EXPECT_CT_RE.search(expect_blob):
        reasons.append(
            "Expect-CT is deprecated and retired by browsers (Chrome 107+); "
            "Certificate Transparency is enforced via CT logs, not this header"
        )
        return _empty_result(
            INFORMATIONAL,
            reasons,
            severity="info",
            cwe=693,
            owasp_top10="A05:2021-Security Misconfiguration",
            asvs_ref="V14.4.3",
            wstg_ref="WSTG-CONF-12",
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

    # 5b. HSTS-missing honesty: no Medium/CVSS-5 default without SSL-strip PoC.
    # HTTPS redirect / HTTPS-only evidence → informational (grade −20 skipped via validation).
    # Otherwise stay unvalidated at Low so site-grade −20 can still apply.
    if claim == "hsts" and not _has_ssl_strip_poc(context_blobs):
        if _has_https_enforcement_evidence(context_blobs, loc):
            reasons.append(
                "Missing HSTS on HTTPS-only / HTTP→HTTPS redirect target without SSL-strip PoC; "
                "hardening observation (Low/informational), not a confirmed exploit path"
            )
            return _empty_result(INFORMATIONAL, reasons, severity="low")
        reasons.append(
            "Missing HSTS without SSL-strip PoC; severity capped to Low "
            "(not Medium/CVSS 5.0 by default)"
        )
        return _empty_result(UNVALIDATED, reasons, severity="low")

    # 5c. SPF on host without MX — subdomain noise; apex often owns mail posture.
    if _is_spf_without_mx(title_s, desc_s, rule_blob):
        reasons.append(
            "No MX on this host; SPF is often inherited or managed at the apex/root domain — "
            "informational unless this name sends mail"
        )
        return _empty_result(INFORMATIONAL, reasons, severity="info")

    # 5d. DANE/TLSA missing — impractical without DNSSEC (e.g. Cloudflare).
    if _is_dane_tlsa_missing(title_s, desc_s, rule_blob):
        reasons.append(
            "DANE/TLSA is impractical without DNSSEC (commonly unavailable on Cloudflare "
            "proxy setups) — informational optional hardening"
        )
        return _empty_result(INFORMATIONAL, reasons, severity="info")

    # 6. Weak cipher without suite names in evidence (or description extractors).
    weak_blob = f"{title_s}\n{desc_s}\n{rule_blob}"
    # Suite tokens in description count (Nuclei often puts names there); title alone does not.
    suite_blobs = list(evidence_blobs)
    if desc_s:
        suite_blobs.append(desc_s)
    if _WEAK_CIPHER_RE.search(weak_blob) and not _has_cipher_suite_evidence(suite_blobs):
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
        if "xss" in wstg or "inject" in wstg or "inpv" in wstg:
            finding.wstg_ref = (
                result.get("wstg_ref") if result.get("wstg_ref") is not None else "WSTG-CONF-12"
            )
        asvs = (getattr(finding, "asvs_ref", None) or "").lower()
        # CWE-79 catalog ASVS (V5.x input validation) is wrong for deprecated-header hardening.
        if asvs.startswith("v5.") or "inject" in asvs:
            finding.asvs_ref = result.get("asvs_ref") or "V14.4.3"


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
