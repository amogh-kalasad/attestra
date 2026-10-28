"""Scope policy decision point (Phase 6.3).

The dispatch decisions live in ``policy/scope.rego``. ``attestra.runner.gate``
collects facts from the database, builds the OPA ``input`` with
:func:`build_input`, and asks :func:`decide` for an allow / refuse decision.

Engines (``ATTESTRA_POLICY_ENGINE``):

* ``python``   (default) built-in evaluator that mirrors ``scope.rego`` exactly,
  so dev machines and CI without OPA keep working. Parity is tested.
* ``opa-http`` POST to an OPA server: ``{ATTESTRA_OPA_URL}/v1/data/attestra/scope/decision``.
* ``opa-cli``  run ``opa eval`` against ``ATTESTRA_POLICY_DIR`` (no server needed).

Any OPA error, timeout or malformed answer is a refusal (fail closed).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

POLICY_PACKAGE_PATH = "attestra/scope/decision"
REQUIRED_FIELDS = (
    "asset_found",
    "engagement_status",
    "asset_environment",
    "authorized_environments",
    "today",
    "window_start",
    "window_end",
    "tool",
    "profile",
    "intrusive_allowed",
    "recent_scan_count",
    "rate_limit",
    "asset_kind",
    "ownership_verified",
    "ownership_required",
    "authorization_required",
)
OWNERSHIP_KINDS = frozenset({"web_app", "api", "host"})
ACTIVE_PROFILES = frozenset({"active", "intrusive"})
INVALID_INPUT = "invalid policy input"


def _default_policy_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "policy"


def engine() -> str:
    return os.environ.get("ATTESTRA_POLICY_ENGINE", "python").strip().lower()


def opa_url() -> str:
    return os.environ.get("ATTESTRA_OPA_URL", "http://127.0.0.1:8181").rstrip("/")


def policy_dir() -> Path:
    return Path(os.environ.get("ATTESTRA_POLICY_DIR", str(_default_policy_dir())))


def opa_timeout_s() -> float:
    return float(os.environ.get("ATTESTRA_OPA_TIMEOUT_S", "5"))


class PolicyError(Exception):
    """OPA could not be reached or returned something unusable."""


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""


def _iso(d: date | None) -> str | None:
    return d.isoformat() if d else None


def build_input(
    *,
    asset_found: bool,
    engagement_status: str,
    asset_environment: str,
    authorized_environments,
    today: date,
    window_start: date | None,
    window_end: date | None,
    tool: str,
    profile: str,
    intrusive_allowed: bool,
    recent_scan_count: int,
    rate_limit: int,
    asset_kind: str,
    ownership_verified: bool,
    ownership_required: bool,
    authorization_required: bool,
) -> dict[str, Any]:
    return {
        "asset_found": bool(asset_found),
        "engagement_status": engagement_status or "",
        "asset_environment": asset_environment or "",
        "authorized_environments": sorted(authorized_environments or []),
        "today": today.isoformat(),
        "window_start": _iso(window_start),
        "window_end": _iso(window_end),
        "tool": tool or "",
        "profile": profile or "",
        "intrusive_allowed": bool(intrusive_allowed),
        "recent_scan_count": int(recent_scan_count),
        "rate_limit": int(rate_limit),
        "asset_kind": asset_kind or "",
        "ownership_verified": bool(ownership_verified),
        "ownership_required": bool(ownership_required),
        "authorization_required": bool(authorization_required),
    }


# ------------------------------------------------------------------ python mirror


def _valid(inp: Any) -> bool:
    if not isinstance(inp, dict) or any(f not in inp for f in REQUIRED_FIELDS):
        return False
    return (
        all(
            isinstance(inp[f], bool)
            for f in (
                "asset_found",
                "intrusive_allowed",
                "ownership_verified",
                "ownership_required",
                "authorization_required",
            )
        )
        and isinstance(inp["authorized_environments"], list)
        and all(isinstance(inp[f], (int, float)) and not isinstance(inp[f], bool) for f in ("recent_scan_count", "rate_limit"))
        and isinstance(inp["today"], str)
    )


def evaluate_python(inp: dict[str, Any]) -> Decision:
    """Pure-Python twin of policy/scope.rego. Keep the two in lock-step."""
    if not _valid(inp):
        return Decision(False, INVALID_INPUT)
    today = inp["today"]
    intrusive = inp["profile"] == "active" or (
        inp["tool"] == "nuclei" and str(inp["profile"]).lower() in ACTIVE_PROFILES
    )
    auth_ok = (not inp["authorization_required"]) or (
        inp["asset_environment"] in inp["authorized_environments"]
    )
    ownership_ok = not (
        inp["ownership_required"]
        and not inp["ownership_verified"]
        and inp["asset_kind"] in OWNERSHIP_KINDS
    )
    checks = (
        (inp["asset_found"] is True, "asset not found for engagement"),
        (inp["engagement_status"] != "halted", "engagement is halted"),
        (auth_ok, "no valid authorization for asset environment"),
        (not (inp["window_start"] is not None and today < inp["window_start"]), "before engagement window"),
        (not (inp["window_end"] is not None and today > inp["window_end"]), "after engagement window"),
        (not (intrusive and not inp["intrusive_allowed"]), "intrusive/active profile not allowed on asset"),
        (inp["recent_scan_count"] < inp["rate_limit"], "scan rate limit exceeded for asset"),
        (ownership_ok, "asset ownership not verified"),
    )
    for ok, reason in checks:
        if not ok:
            return Decision(False, reason)
    return Decision(True, "")


# ------------------------------------------------------------------ OPA engines


def _parse_result(result: Any) -> Decision:
    if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
        raise PolicyError(f"malformed OPA decision: {result!r}")
    if result["allow"]:
        return Decision(True, "")
    return Decision(False, str(result.get("reason") or "refused by policy"))


def evaluate_opa_http(inp: dict[str, Any], *, url: str | None = None, timeout: float | None = None, opener=None) -> Decision:
    endpoint = f"{url or opa_url()}/v1/data/{POLICY_PACKAGE_PATH}"
    body = json.dumps({"input": inp}).encode()
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={"Content-Type": "application/json"})
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout or opa_timeout_s()) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise PolicyError(f"OPA request failed: {exc}") from exc
    if "result" not in payload:
        # Undefined decision (e.g. policy not loaded) -> refuse.
        raise PolicyError("OPA returned no result (policy not loaded?)")
    return _parse_result(payload["result"])


def opa_binary() -> str | None:
    return os.environ.get("ATTESTRA_OPA_BIN") or shutil.which("opa")


def evaluate_opa_cli(inp: dict[str, Any], *, binary: str | None = None, pdir: Path | None = None) -> Decision:
    exe = binary or opa_binary()
    if not exe:
        raise PolicyError("opa binary not found (set ATTESTRA_OPA_BIN or install OPA)")
    argv = [exe, "eval", "--format", "json", "--stdin-input", "-d", str(pdir or policy_dir()),
            "data." + POLICY_PACKAGE_PATH.replace("/", ".")]
    try:
        proc = subprocess.run(argv, input=json.dumps(inp), capture_output=True, text=True,
                              timeout=opa_timeout_s() * 4, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError(f"opa eval failed: {exc}") from exc
    if proc.returncode != 0:
        raise PolicyError(f"opa eval exit {proc.returncode}: {proc.stderr.strip()[:500]}")
    try:
        out = json.loads(proc.stdout)
        value = out["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise PolicyError("opa eval returned no decision") from exc
    return _parse_result(value)


def decide(inp: dict[str, Any]) -> Decision:
    """Evaluate the scope policy with the configured engine. Never fails open."""
    eng = engine()
    try:
        if eng == "python":
            return evaluate_python(inp)
        if eng in ("opa", "opa-http", "http"):
            return evaluate_opa_http(inp)
        if eng in ("opa-cli", "cli"):
            return evaluate_opa_cli(inp)
    except PolicyError as exc:
        return Decision(False, f"policy engine error: {exc}")
    return Decision(False, f"policy engine error: unknown engine {eng!r}")
