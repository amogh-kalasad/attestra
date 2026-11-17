"""Offline JWT posture (D-02).

Decodes JWT header and claims locally and reports weaknesses. Never forges,
re-signs, replays or sends a token anywhere; output carries claim *names*,
algorithm names, booleans and lifetimes only, never the token or claim values.
Unsupported formats (JWE, opaque tokens) are reported as "not assessed".
"""

# @lat: [[run-validity-and-policy#JWT posture]]

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_SENSITIVE_CLAIM_RE = re.compile(
    r"(?i)(pass(word|wd)?|pwd|secret|private|api[_-]?key|ssn|social[_-]?security|credit|card[_-]?(number|no)|cvv|pin\b|"
    r"bank|iban|salary|dob|date[_-]?of[_-]?birth|national[_-]?id|aadhaar|pan[_-]?(number|no))"
)
_SYMMETRIC = {"HS256", "HS384", "HS512"}
_WEAK_ALGS = {"none", "", "hs1", "rs1"}
MAX_REASONABLE_LIFETIME_S = 24 * 3600

SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


def _b64url_json(segment: str) -> Any:
    pad = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode((segment + pad).encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def token_label(token: str, index: int = 0) -> str:
    """Stable, value-free label (short SHA-256 prefix) so evidence can refer to a token."""
    digest = hashlib.sha256((token or "").encode("utf-8")).hexdigest()[:10]
    return f"jwt#{index + 1}:{digest}"


def assess_token(token: str, *, now: float | None = None, index: int = 0) -> dict[str, Any]:
    """Assess one token. ``now`` is a UNIX timestamp (defaults to time.time())."""
    import time

    t = (token or "").strip()
    out: dict[str, Any] = {"label": token_label(t, index), "assessed": False, "issues": []}
    parts = t.split(".")
    if len(parts) == 5:
        out["reason"] = "jwe_encrypted_not_assessed"
        return out
    if len(parts) != 3 or not _JWT_SHAPE.match(t):
        out["reason"] = "unsupported_format"
        return out
    try:
        header = _b64url_json(parts[0])
        claims = _b64url_json(parts[1])
    except Exception:
        out["reason"] = "undecodable"
        return out
    if not isinstance(header, dict) or not isinstance(claims, dict):
        out["reason"] = "unsupported_format"
        return out
    out["assessed"] = True
    alg = str(header.get("alg") or "")
    issues: list[dict[str, str]] = []

    def issue(code: str, sev: str, detail: str) -> None:
        issues.append({"code": code, "severity": sev, "detail": detail})

    if alg.strip().lower() in _WEAK_ALGS:
        issue("alg_none_or_weak", SEV_HIGH, f"alg={alg or 'empty'}")
    if not parts[2] and alg.strip().lower() not in ("none", ""):
        issue("missing_signature", SEV_HIGH, "signature segment is empty")
    if alg.upper() in _SYMMETRIC:
        issue("symmetric_alg", SEV_INFO, f"{alg}: shared-secret signature; check key strength server-side")
    for h, code in (("jku", "jku_header"), ("x5u", "x5u_header"), ("jwk", "embedded_jwk")):
        if h in header:
            issue(code, SEV_MEDIUM, f"header '{h}' lets the token point at its own key material")
    if "kid" in header:
        kid = str(header.get("kid") or "")
        if any(ch in kid for ch in ("/", "\\", "..", "'", '"', ";", "|")):
            issue("kid_suspicious_chars", SEV_MEDIUM, "kid contains path/quote/command characters")
    present = {k: (k in claims) for k in ("exp", "nbf", "iat", "aud", "iss", "sub", "jti")}
    if not present["exp"]:
        issue("missing_exp", SEV_HIGH, "no expiry claim")
    if not present["aud"]:
        issue("missing_aud", SEV_LOW, "no audience claim")
    if not present["iss"]:
        issue("missing_iss", SEV_LOW, "no issuer claim")
    lifetime = None
    ts = now if now is not None else time.time()
    try:
        exp = float(claims["exp"]) if present["exp"] else None
        iat = float(claims["iat"]) if present["iat"] else None
        nbf = float(claims["nbf"]) if present["nbf"] else None
    except (TypeError, ValueError):
        exp = iat = nbf = None
        issue("non_numeric_time_claims", SEV_LOW, "exp/iat/nbf are not numeric")
    if exp is not None and iat is not None:
        lifetime = int(exp - iat)
        if lifetime > MAX_REASONABLE_LIFETIME_S:
            issue("long_lifetime", SEV_MEDIUM, f"lifetime {lifetime}s > {MAX_REASONABLE_LIFETIME_S}s")
    if exp is not None and exp < ts:
        issue("expired_token_in_use", SEV_INFO, "token already expired when observed")
    if nbf is not None and nbf > ts + 300:
        issue("nbf_in_future", SEV_INFO, "nbf is in the future")
    sensitive = sorted(k for k in claims if _SENSITIVE_CLAIM_RE.search(str(k)))
    if sensitive:
        issue("sensitive_claim_names", SEV_MEDIUM, ", ".join(sensitive))
    out.update(
        {
            "alg": alg,
            "typ": str(header.get("typ") or ""),
            "header_keys": sorted(str(k) for k in header),
            "claim_keys": sorted(str(k) for k in claims),
            "claims_present": present,
            "lifetime_s": lifetime,
            "sensitive_claim_names": sensitive,
            "issues": issues,
            "max_severity": _max_sev(issues),
        }
    )
    return out


def _max_sev(issues: list[dict[str, str]]) -> str:
    order = [SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]
    for sev in order:
        if any(i["severity"] == sev for i in issues):
            return sev
    return ""


def assess_tokens(tokens: list[str], *, now: float | None = None, limit: int = 5) -> dict[str, Any]:
    """Summary over several tokens; ``finding`` is True when any assessed token has a high issue."""
    rows = [assess_token(t, now=now, index=i) for i, t in enumerate(tokens[:limit])]
    assessed = [r for r in rows if r.get("assessed")]
    return {
        "tokens_seen": len(tokens),
        "tokens_assessed": len(assessed),
        "not_assessed": [{"label": r["label"], "reason": r.get("reason", "")} for r in rows if not r.get("assessed")],
        "tokens": assessed,
        "high_issues": sorted({i["code"] for r in assessed for i in r["issues"] if i["severity"] == SEV_HIGH}),
        "medium_issues": sorted({i["code"] for r in assessed for i in r["issues"] if i["severity"] == SEV_MEDIUM}),
        "finding": any(r.get("max_severity") == SEV_HIGH for r in assessed),
        "status": "assessed" if assessed else ("not_assessed" if rows else "no_tokens"),
    }
