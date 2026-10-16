"""testssl.sh importer: `--jsonfile` (flat list) and `--jsonfile-pretty` output."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe

_SKIP = {"OK", "INFO", "DEBUG", "FATAL", ""}
# Scanner diagnostics / noise — not TLS configuration findings.
# Stored as import/scan notes via extract_notes(); never become findings.
_NOTE_IDS = {"engine_problem", "scanTime", "service", "pre_128cipher"}
_SKIP_IDS = _NOTE_IDS
_ENGINE_NOTE_RE = re.compile(
    r"no engine or gost support|gost support via engine|scan.?engine",
    re.IGNORECASE,
)

# Weak cert / handshake signature hashes kept even at INFO/OK (R17).
_WEAK_SIG_RE = re.compile(r"\b(SHA224|SHA1|MD5)\b", re.IGNORECASE)
_CERT_SIG_IDS = {"cert_signatureAlgorithm", "signature_algorithm"}
_HANDSHAKE_SIG_RE = re.compile(
    r"(?:FS_TLS\d*_sig_algs|sig_algs|ServerHash|server.?hash|handshake.?sig)",
    re.IGNORECASE,
)
_OCSP_STAPLING_IDS = {"OCSP_stapling", "ocsp_stapling"}
_EMPTY_OCSP = {"", "--", "none", "n/a", "-"}

_WEAK_PROTOCOLS = {
    "SSLv2": "TLS: SSLv2 protocol offered",
    "SSLv3": "TLS: SSLv3 protocol offered",
    "TLS1": "TLS: TLS 1.0 protocol offered",
    "TLS1_1": "TLS: TLS 1.1 protocol offered",
}
_PROTOCOL_IDS = ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3")

# Cipher / bit-strength hints for summary and weak-cipher titles.
_CIPHER_BITS_RE = re.compile(r"\b(\d{2,4})\s*(?:bits?)?\s*$", re.IGNORECASE)
_WEAK_CIPHER_HINT = re.compile(
    r"\b(RC4|NULL|EXPORT|DES\b|3DES|MD5|CBC|anon)\b",
    re.IGNORECASE,
)


def _entries(doc) -> list[tuple[dict, str, str]]:
    """Yield (entry, host, port) for both output shapes."""
    out: list[tuple[dict, str, str]] = []
    if isinstance(doc, list):
        for e in doc:
            if isinstance(e, dict):
                host = str(e.get("ip", "")).split("/")[0]
                out.append((e, host, str(e.get("port", ""))))
        return out
    if isinstance(doc, dict):
        for target in doc.get("scanResult") or []:
            host = target.get("targetHost") or str(target.get("ip", "")).split("/")[0]
            port = str(target.get("port", ""))
            for value in target.values():
                if isinstance(value, list):
                    out += [(e, host, port) for e in value if isinstance(e, dict)]
    return out


def _by_id(entries: list[tuple[dict, str, str]]) -> dict[str, tuple[str, str]]:
    """Map check id → (severity, finding text); last wins."""
    out: dict[str, tuple[str, str]] = {}
    for e, _, _ in entries:
        cid = str(e.get("id", "")).strip()
        if not cid:
            continue
        out[cid] = (str(e.get("severity", "")).upper(), str(e.get("finding", "")))
    return out


def _has_ocsp_url(entries: list[tuple[dict, str, str]]) -> bool:
    for e, _, _ in entries:
        if str(e.get("id", "")) != "cert_ocspURL":
            continue
        finding = str(e.get("finding", "")).strip()
        if finding.lower() not in _EMPTY_OCSP:
            return True
    return False


def _is_handshake_sig_id(check: str) -> bool:
    return bool(_HANDSHAKE_SIG_RE.search(check))


def _is_r17_cert(check: str, finding: str) -> bool:
    if check in _CERT_SIG_IDS and _WEAK_SIG_RE.search(finding):
        return True
    if "signature" in check.lower() and not _is_handshake_sig_id(check) and _WEAK_SIG_RE.search(finding):
        return True
    if re.search(r"signature\s+algorithm", finding, re.IGNORECASE) and _WEAK_SIG_RE.search(finding):
        # Prefer handshake path when the id is clearly handshake-related.
        if _is_handshake_sig_id(check):
            return False
        return True
    return False


def _is_r17_handshake(check: str, finding: str) -> bool:
    if not _WEAK_SIG_RE.search(finding):
        return False
    return _is_handshake_sig_id(check)


def _is_r18(check: str, finding: str) -> bool:
    if check not in _OCSP_STAPLING_IDS:
        return False
    return "not offered" in finding.lower()


def _is_tool_note(check: str, finding: str, sev: str = "", host: str = "") -> bool:
    """True for testssl scanner diagnostics (engine/GOST/service), not TLS findings."""
    if check in _NOTE_IDS:
        return True
    if _ENGINE_NOTE_RE.search(finding or ""):
        return True
    # Pretty-JSON client warnings and orphan WARN rows with ip "/" are scan notes.
    h = (host or "").strip().strip("/")
    if sev == "WARN" and not h and ("engine" in check.lower() or check.startswith("clientProblem")):
        return True
    return False


def extract_notes(raw: bytes) -> list[str]:
    """Scanner tool notes/warnings from testssl JSON (not findings)."""
    doc = load_json_or_lines(raw)
    notes: list[str] = []
    seen: set[str] = set()

    def _add(text: str) -> None:
        t = (text or "").strip()
        if t and t not in seen:
            seen.add(t)
            notes.append(t)

    for e, host, _port in _entries(doc):
        check = str(e.get("id", ""))
        finding = str(e.get("finding", ""))
        sev = str(e.get("severity", "")).upper()
        if _is_tool_note(check, finding, sev, host):
            _add(finding or check)

    # Pretty JSON puts client warnings at the document root, outside scanResult.
    if isinstance(doc, dict):
        for key, value in doc.items():
            if not str(key).startswith("clientProblem") or not isinstance(value, list):
                continue
            for e in value:
                if isinstance(e, dict):
                    _add(str(e.get("finding", "")).strip() or str(e.get("id", "")).strip())
    return notes


def _offered(finding: str) -> bool:
    text = finding.lower()
    if "not offered" in text:
        return False
    return "offered" in text or "vulnerable" in text


def _expired_or_expiring(finding: str) -> bool:
    text = finding.lower()
    if "expired" in text or "not yet valid" in text:
        return True
    # e.g. "5 < 30 days" / "expires in"
    if "expir" in text and ("<" in text or "day" in text):
        # "55 >= 30 days" is healthy; "< 30" or "expires" is not.
        if ">=" in text or "ok" in text:
            return False
        return True
    return False


def _chain_failed(finding: str) -> bool:
    text = finding.lower()
    if "passed" in text or text.strip() in {"ok", "ok."}:
        return False
    return any(w in text for w in ("fail", "broken", "incomplete", "untrusted", "self.signed", "self-signed"))


def _clear_title(check: str, finding: str) -> str | None:
    """Human title for well-known TLS checks; None keeps the generic form."""
    if check in _WEAK_PROTOCOLS and _offered(finding):
        return _WEAK_PROTOCOLS[check]
    if check == "cert_expirationStatus" or check.startswith("cert_expiration"):
        return "TLS: certificate expired or expiring soon"
    if check == "cert_chain_of_trust":
        return "TLS: certificate chain of trust failed"
    if check.startswith("cipher") and _WEAK_CIPHER_HINT.search(finding):
        return f"TLS: weak cipher offered ({check})"
    return None


def parse(raw: bytes, *, today: date | None = None) -> list[NormalizedFinding]:
    """Parse testssl JSON. Optional ``today`` freezes the cert-expiry clock for tests."""
    from attestra.cert_expiry import (
        CERT_EXPIRY_VARIANT,
        days_from_expiration_text,
        expiry_band,
        finding_for_end_date,
        parse_not_after,
        today_utc,
    )

    doc = load_json_or_lines(raw)
    entries = _entries(doc)
    has_ocsp = _has_ocsp_url(entries)
    out: list[NormalizedFinding] = []
    # Per-host cert end date / expiry text for one band-based finding at the end.
    cert_after: dict[str, str] = {}
    cert_status: dict[str, str] = {}
    day = today or today_utc()
    for e, host, port in entries:
        sev = str(e.get("severity", "")).upper()
        check = str(e.get("id", ""))
        finding = str(e.get("finding", ""))
        location = f"{host}:{port}" if port else host
        cves = [c for c in str(e.get("cve", "")).split() if c.upper().startswith("CVE-")]

        # Tool notes (engine_problem / GOST / service) stay off the findings list.
        if _is_tool_note(check, finding, sev, host):
            continue

        # Collect cert dates; emit one band finding per host after the loop.
        if check == "cert_notAfter" and finding.strip():
            cert_after[location] = finding.strip()
            continue
        if check in {"cert_expirationStatus", "cert_expiration"}:
            cert_status[location] = finding
            continue

        if _is_r17_handshake(check, finding):
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id=check,
                    title="TLS: weak handshake signature hash offered (SHA224/SHA1/MD5)",
                    severity="low",
                    location=location,
                    description=finding,
                    recommendation="Prefer SHA256+ handshake signature algorithms; disable SHA224/SHA1/MD5.",
                    cwe=327,
                    cves=cves,
                    param=check,
                    variant="handshake",
                )
            )
            continue

        if _is_r17_cert(check, finding):
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id=check,
                    title="TLS: weak signature or hash algorithm offered (SHA224/SHA1/MD5)",
                    severity="low",
                    location=location,
                    description=finding,
                    recommendation="Prefer SHA256+ signature algorithms; disable SHA224/SHA1/MD5.",
                    cwe=327,
                    cves=cves,
                    param=check,
                    variant="cert_signatureAlgorithm",
                )
            )
            continue

        if _is_r18(check, finding) and has_ocsp:
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id=check,
                    title="TLS: OCSP stapling not offered",
                    severity="info",
                    location=location,
                    description=finding,
                    recommendation="Enable OCSP stapling when an OCSP responder URL is present on the certificate.",
                    cwe=299,
                    cves=cves,
                    param=check,
                    variant=check,
                )
            )
            continue

        if check == "cert_chain_of_trust" and _chain_failed(finding):
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id=check,
                    title="TLS: certificate chain of trust failed",
                    severity="high",
                    location=location,
                    description=finding,
                    recommendation="Serve the full intermediate chain with the leaf certificate.",
                    cwe=295,
                    cves=cves,
                    param=check,
                    variant="cert_chain_of_trust",
                )
            )
            continue

        if check in _WEAK_PROTOCOLS and _offered(finding) and sev in _SKIP:
            # INFO "offered" for deprecated protocols still matters for PCI.
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id=check,
                    title=_WEAK_PROTOCOLS[check],
                    severity="medium" if check.startswith("TLS") else "high",
                    location=location,
                    description=finding,
                    recommendation="Disable SSLv2/SSLv3 and TLS 1.0/1.1; offer TLS 1.2+ only.",
                    cwe=326,
                    cves=cves,
                    param=check,
                    variant=check,
                )
            )
            continue

        if check in _SKIP_IDS or sev in _SKIP:
            continue
        severity = "low" if sev == "WARN" else norm_severity(sev)
        title = _clear_title(check, finding) or f"TLS: {check} - {finding}"[:500]
        variant = check
        if check == "cert_chain_of_trust":
            variant = "cert_chain_of_trust"
        out.append(
            NormalizedFinding(
                tool="testssl",
                rule_id=check,
                title=title,
                severity=severity,
                location=location,
                description=finding,
                recommendation="Review the TLS configuration against PCI DSS 4.2.1 and current Mozilla guidance.",
                cwe=parse_cwe(e.get("cwe")) or 326,
                cves=cves,
                param=check,
                variant=variant,
            )
        )

    # One expiry finding per host from notAfter (preferred) or expirationStatus text.
    hosts = sorted(set(cert_after) | set(cert_status))
    for location in hosts:
        end = parse_not_after(cert_after.get(location, ""))
        if end is not None:
            nf = finding_for_end_date(
                end=end,
                location=location,
                tool="testssl",
                rule_id="cert_notAfter",
                today=day,
            )
            if nf is not None:
                out.append(nf)
            continue
        status_text = cert_status.get(location, "")
        if not _expired_or_expiring(status_text):
            continue
        left = days_from_expiration_text(status_text)
        if left is None:
            # Keep a clear expired finding when the text says expired but has no date.
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id="cert_expirationStatus",
                    title="TLS: certificate expired",
                    severity="high",
                    location=location,
                    description=status_text,
                    recommendation="Replace the expired certificate and reload the TLS service.",
                    cwe=298,
                    param="cert_expirationStatus",
                    variant=CERT_EXPIRY_VARIANT,
                )
            )
            continue
        band = expiry_band(left)
        if band is None:
            continue
        # Synthesize an end date so title/severity stay consistent with the band helper.
        from datetime import timedelta

        synth_end = day + timedelta(days=left)
        nf = finding_for_end_date(
            end=synth_end,
            location=location,
            tool="testssl",
            rule_id="cert_expirationStatus",
            today=day,
        )
        if nf is not None:
            nf.description = status_text or nf.description
            out.append(nf)
    return out


def _cipher_bits(finding: str) -> int | None:
    """Cipher strength from a cipher-* line: the last integer token (… AESGCM 256).

    Earlier integers are often ECDH curve bits (for example ``ECDH 521``) and must
    not win over the trailing cipher bit length.
    """
    parts = finding.split()
    last: int | None = None
    for token in parts:
        if token.isdigit() and 40 <= int(token) <= 8192:
            last = int(token)
    if last is not None:
        return last
    m = _CIPHER_BITS_RE.search(finding.strip())
    return int(m.group(1)) if m else None


def _cipher_name(finding: str) -> str:
    """Best-effort cipher suite name from a cipher-* finding line."""
    parts = finding.split()
    for p in parts:
        if p.startswith(("TLS_", "SSL_")) or "ECDHE" in p or "DHE-" in p or "AES" in p:
            if p.startswith(("TLSv", "SSLv")):
                continue
            return p
    return finding.strip()[:80] or "—"


def _pick_host_port(entries: list[tuple[dict, str, str]]) -> tuple[str, str]:
    """Prefer a real hostname over empty / placeholder ips from engine rows."""
    for _e, host, port in entries:
        h = (host or "").strip().strip("/")
        if h and h not in {"/", "-"}:
            return h, port
    if entries:
        return entries[0][1], entries[0][2]
    return "", ""


def summarize(raw: bytes) -> dict[str, Any]:
    """Build a TLS summary box from raw testssl JSON.

    Returns a dict with ``scanned=True`` and display fields. Callers that have no
    testssl data should use ``{"scanned": False}`` and show "not scanned".
    """
    doc = load_json_or_lines(raw)
    entries = _entries(doc)
    if not entries:
        return {"scanned": False}
    by_id = _by_id(entries)
    host, port = _pick_host_port(entries)

    protocols: list[str] = []
    for pid in _PROTOCOL_IDS:
        if pid not in by_id:
            continue
        _sev, finding = by_id[pid]
        state = "offered" if _offered(finding) else "not offered"
        label = {
            "SSLv2": "SSLv2",
            "SSLv3": "SSLv3",
            "TLS1": "TLS 1.0",
            "TLS1_1": "TLS 1.1",
            "TLS1_2": "TLS 1.2",
            "TLS1_3": "TLS 1.3",
        }[pid]
        protocols.append(f"{label}: {state}")

    best: tuple[int, str] | None = None
    weakest: tuple[int, str] | None = None
    for e, _, _ in entries:
        cid = str(e.get("id", ""))
        if not cid.startswith("cipher-"):
            continue
        sev = str(e.get("severity", "")).upper()
        finding = str(e.get("finding", ""))
        if sev not in {"OK", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN"}:
            continue
        if "not offered" in finding.lower():
            continue
        bits = _cipher_bits(finding)
        name = _cipher_name(finding)
        if bits is None:
            continue
        if best is None or bits > best[0]:
            best = (bits, name)
        if weakest is None or bits < weakest[0]:
            weakest = (bits, name)

    _exp_sev, exp_finding = by_id.get("cert_expirationStatus", ("", ""))
    _after_sev, not_after = by_id.get("cert_notAfter", ("", ""))
    cert_expiry = not_after.strip() or exp_finding.strip() or "—"

    _chain_sev, chain_finding = by_id.get("cert_chain_of_trust", ("", ""))
    if not chain_finding:
        chain_ok = "—"
    elif _chain_failed(chain_finding):
        chain_ok = f"failed ({chain_finding.strip()})"
    else:
        chain_ok = "OK"

    _sig_sev, cert_sig = by_id.get("cert_signatureAlgorithm", ("", ""))
    cert_signature = cert_sig.strip() or "—"

    handshake_parts: list[str] = []
    for hid in ("FS_TLS12_sig_algs", "FS_TLS13_sig_algs"):
        if hid in by_id:
            handshake_parts.append(f"{hid}: {by_id[hid][1].strip()}")
    handshake_signatures = "; ".join(handshake_parts) if handshake_parts else "—"

    _ocsp_sev, ocsp_finding = by_id.get("OCSP_stapling", by_id.get("ocsp_stapling", ("", "")))
    _url_sev, ocsp_url = by_id.get("cert_ocspURL", ("", ""))
    ocsp_url_s = ocsp_url.strip()
    if ocsp_finding:
        ocsp = ocsp_finding.strip()
        if ocsp_url_s and ocsp_url_s.lower() not in _EMPTY_OCSP:
            ocsp = f"{ocsp} (URL present)"
        elif ocsp_url_s.lower() in _EMPTY_OCSP or not ocsp_url_s:
            ocsp = f"{ocsp} (no OCSP URL on certificate)"
    else:
        ocsp = "—"

    return {
        "scanned": True,
        "host": f"{host}:{port}" if port else host,
        "protocols": protocols or ["—"],
        "best_cipher": f"{best[1]} ({best[0]} bit)" if best else "—",
        "weakest_cipher": f"{weakest[1]} ({weakest[0]} bit)" if weakest else "—",
        "cert_expiry": cert_expiry,
        "chain_ok": chain_ok,
        "cert_signature": cert_signature,
        "handshake_signatures": handshake_signatures,
        "ocsp": ocsp,
    }
