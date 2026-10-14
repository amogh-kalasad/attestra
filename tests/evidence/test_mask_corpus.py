"""Phase 5.1: masking corpus leaves 0 unmasked PANs/credentials."""
# @lat: [[tests#Phase 5 evidence hardening#Masking corpus]]

from __future__ import annotations

import random

from attestra.evidence.mask import luhn_ok, mask_bytes

# Well-known Luhn-valid test PANs (not live cards).
_VALID_PANS = [
    "4111111111111111",
    "5500000000000004",
    "340000000000009",
    "6011000000000004",
    "378282246310005",
]


def _luhn_complete(partial: str) -> str:
    """Append a check digit so the number passes Luhn."""
    base = partial
    for d in range(10):
        cand = base + str(d)
        if luhn_ok(cand):
            return cand
    raise RuntimeError("could not complete Luhn")


def test_luhn_valid_pans_masked():
    for pan in _VALID_PANS:
        assert luhn_ok(pan)
        out, report = mask_bytes(f"card={pan}".encode(), "text/plain")
        text = out.decode()
        assert pan not in text
        assert report["pan"] >= 1
        assert "*" in text


def test_non_luhn_digit_strings_untouched():
    junk = "1234567890123456"  # 16 digits, fails Luhn
    assert not luhn_ok(junk)
    out, report = mask_bytes(f"id={junk}".encode(), "text/plain")
    assert junk in out.decode()
    assert report["pan"] == 0


def test_corpus_1000_zero_leaks():
    rng = random.Random(42)
    lines: list[str] = []
    secrets: list[str] = []
    for i in range(1000):
        kind = i % 5
        if kind == 0:
            prefix = "".join(str(rng.randint(0, 9)) for _ in range(15))
            pan = _luhn_complete(prefix)
            secrets.append(pan)
            lines.append(f"PAN {pan} at checkout")
        elif kind == 1:
            tok = f"eyJhbGciOiJIUzI1NiJ9.{'a' * 20}.{'b' * 20}"
            secrets.append(tok)
            lines.append(f"Authorization: Bearer {tok}")
        elif kind == 2:
            pwd = f"s3cr3t{rng.randint(1000, 9999)}"
            secrets.append(pwd)
            lines.append(f"password={pwd}")
        elif kind == 3:
            email = f"user{i}@example.com"
            secrets.append(email)
            lines.append(f"contact {email}")
        else:
            key = f"sk_live_{rng.randint(10**8, 10**9 - 1)}"
            secrets.append(key)
            lines.append(f"api_key={key}")

    raw = "\n".join(lines).encode()
    masked, report = mask_bytes(raw, "text/plain")
    text = masked.decode()
    leaked = [s for s in secrets if s in text]
    assert leaked == [], f"{len(leaked)} secrets leaked, e.g. {leaked[:3]}"
    assert report["pan"] + report["jwt"] + report["password"] + report["email"] + report["api_key"] + report[
        "auth_header"
    ] >= 1000


def test_cookie_and_auth_headers():
    raw = b"Cookie: session=abc123\nAuthorization: Basic dXNlcjpwYXNz\n"
    out, report = mask_bytes(raw, "text/plain")
    text = out.decode()
    assert "abc123" not in text
    assert "dXNlcjpwYXNz" not in text
    assert report["cookie_header"] >= 1
    assert report["auth_header"] >= 1


def test_binary_skipped():
    data = b"\x00\x01\x02" + b"\xff" * 100
    out, report = mask_bytes(data, "application/octet-stream")
    assert out == data
    assert report.get("skipped") == "binary"
