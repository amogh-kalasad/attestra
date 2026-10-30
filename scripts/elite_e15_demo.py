#!/usr/bin/env python3
"""Elite E15 demo: BOLA against secure vs vulnerable local mocks.

Runs offline against ASGI TestClients (no network). Prints classification
differences. Enable flag is not required for this scripted demo.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from attestra.automated_vapt.testing import idor_bola_tests
from attestra.automated_vapt.validation.vulnerability_validator import validate_result
from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app


def _classify(module_result: dict) -> dict:
    obs = module_result.get("observations") or {}
    protected = bool(obs.get("exposed_secrets"))
    return validate_result(
        {
            "executed": True,
            "in_scope": True,
            "auth_valid": True,
            "identity_ok": True,
            "expected_control_defined": True,
            "protected_data_exposed": protected,
            "authorization_bypass": bool(module_result.get("finding_candidate") and protected),
            "reproducible": True,
            "evidence_supports": True,
            "finding_candidate": bool(module_result.get("finding_candidate")),
            "authorized_access": bool(obs.get("authorized_ok") and obs.get("unauthorized_blocked")),
        }
    )


def main() -> int:
    secure = TestClient(create_secure_app(), base_url="http://localhost:8765")
    vuln = TestClient(create_vulnerable_app(), base_url="http://localhost:8765")
    s_mod = idor_bola_tests.run(secure, "http://localhost:8765/")
    v_mod = idor_bola_tests.run(vuln, "http://localhost:8765/")
    s_val = _classify(s_mod)
    v_val = _classify(v_mod)
    print("=== Elite E15 BOLA demo (local mocks) ===")
    print("Secure mock:", s_val["status"], s_val["reasons"])
    print("Vulnerable mock:", v_val["status"], v_val["reasons"])
    ok = s_val["status"] == "NOT_VULNERABLE" and v_val["status"] == "CONFIRMED"
    print("Demo OK:" if ok else "Demo FAILED:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
