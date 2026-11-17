"""Session lifecycle checks (D-01, case id ``SESSLIFE``).

Three questions, answered with an authorized test account only:

* **Rotation** (WSTG-SESS-03 / ASVS V3.2.1): does a new login issue a new session id,
  or does the server keep a session id the client presented before login?
* **Logout invalidation** (WSTG-SESS-06 / ASVS V3.3.1): after logout, is the old
  session id refused when replayed?
* **Expiry** (WSTG-SESS-07 / ASVS V3.3.2): cookie ``Max-Age``/``Expires`` and JWT
  lifetime, observed passively.

Rotation and logout need a login/logout flow, so they run only against in-process lab
mock clients. On a live engagement session the module is passive (expiry only): it
never logs the engagement session out, never logs in, and records an identity label
(``profile#N``), never a token or cookie value.
"""

# @lat: [[run-validity-and-policy#Session lifecycle]]

from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parsedate_to_datetime
from typing import Any

from attestra.automated_vapt.core.response_classifier import (
    ResponseClass,
    classify_httpx,
    is_blocking,
    is_security_control_evidence,
    samples_to_json,
    skip_reason_for,
)

TEST_ID = "SESSLIFE"
CATEGORY = "session"
LONG_COOKIE_S = 30 * 24 * 3600

ROTATED = "rotated"
NOT_ROTATED = "not_rotated"
INVALIDATED = "invalidated"
NOT_INVALIDATED = "not_invalidated"
NOT_ASSESSED = "not_assessed"

_SESSION_NAME_RE = re.compile(r"(?i)(sess|sid$|^sid|token|auth|jwt|connect\.sid|aspxauth)")


def is_session_cookie_name(name: str) -> bool:
    return bool(_SESSION_NAME_RE.search(name or ""))


def session_values(cookies: Mapping[str, str] | None) -> dict[str, str]:
    """Session-like cookies only (values stay in memory; never returned in results)."""
    return {str(k): str(v) for k, v in (cookies or {}).items() if is_session_cookie_name(str(k))}


def assess_rotation(before: Mapping[str, str], after: Mapping[str, str]) -> dict[str, Any]:
    """Compare session cookie values across a login. Pure; returns names and booleans only."""
    b, a = session_values(before), session_values(after)
    common = sorted(set(b) & set(a))
    if not a:
        return {"result": NOT_ASSESSED, "reason": "no session cookie after login", "names": []}
    if not common:
        return {"result": ROTATED, "reason": "login issued new session cookie names", "names": sorted(a)}
    same = [n for n in common if b[n] == a[n]]
    if same:
        return {"result": NOT_ROTATED, "reason": "session id unchanged across login", "names": same}
    return {"result": ROTATED, "reason": "session id changed on login", "names": common}


def assess_logout(replay_status_class: ResponseClass | None) -> dict[str, Any]:
    """Classify the replay of a pre-logout session id against a protected page."""
    if replay_status_class is None:
        return {"result": NOT_ASSESSED, "reason": "no replay"}
    if replay_status_class is ResponseClass.APP_OK:
        return {"result": NOT_INVALIDATED, "reason": "old session id still accepted after logout"}
    if replay_status_class in (ResponseClass.APP_AUTH_DENIED, ResponseClass.AUTH_REDIRECT, ResponseClass.AUTH_EXPIRED):
        return {"result": INVALIDATED, "reason": "old session id refused after logout"}
    return {"result": NOT_ASSESSED, "reason": f"replay answered {replay_status_class.value}"}


def cookie_lifetime_s(set_cookie: str, *, now_ts: float | None = None) -> int | None:
    """Lifetime in seconds from a Set-Cookie line (Max-Age wins over Expires); None = session cookie."""
    import time

    low = set_cookie or ""
    m = re.search(r"(?i);\s*max-age\s*=\s*(-?\d+)", low)
    if m:
        return int(m.group(1))
    m = re.search(r"(?i);\s*expires\s*=\s*([^;]+)", low)
    if m:
        try:
            exp = parsedate_to_datetime(m.group(1).strip()).timestamp()
            return int(exp - (now_ts if now_ts is not None else time.time()))
        except (TypeError, ValueError):
            return None
    return None


def expiry_posture(set_cookie_lines: list[str], jwt_summary: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Passive expiry observations (cookie names + lifetimes, JWT lifetimes). Value-free."""
    cookies: list[dict[str, Any]] = []
    long_lived: list[str] = []
    for line in set_cookie_lines or []:
        name = (line.split("=", 1)[0] or "").strip()
        if not is_session_cookie_name(name):
            continue
        life = cookie_lifetime_s(line)
        cookies.append({"name": name, "persistent": life is not None and life > 0, "lifetime_s": life})
        if life is not None and life > LONG_COOKIE_S:
            long_lived.append(name)
    jwt_lifetimes = [t.get("lifetime_s") for t in ((jwt_summary or {}).get("tokens") or []) if t.get("lifetime_s") is not None]
    return {
        "session_cookies": cookies,
        "long_lived_session_cookies": long_lived,
        "jwt_lifetimes_s": jwt_lifetimes,
        "observed": bool(cookies or jwt_lifetimes),
    }


def _set_cookie_lines(resp: Any) -> list[str]:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return []
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        return [str(v) for v in get_list("set-cookie")]
    raw = headers.get("set-cookie") if hasattr(headers, "get") else None
    return [str(raw)] if raw else []


def _jar(client: Any) -> dict[str, str]:
    jar = getattr(client, "cookies", None)
    try:
        return {str(k): str(v) for k, v in dict(jar or {}).items()}
    except Exception:
        return {}


def _identity_label(auth: Any) -> str:
    pid = getattr(auth, "profile_id", None)
    return f"profile#{pid}" if pid is not None else "lab-mock-account"


def _run_lab(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Login twice / logout / replay against an in-process lab mock (never a live target)."""
    from attestra.automated_vapt.testing._http import absolute, clear_cookies

    user = str(kwargs.get("lab_user") or "viewer")
    pw = str(kwargs.get("lab_password") or "viewer-pass")
    protected = absolute(base_url, str(kwargs.get("protected_path") or "/app"))
    samples = []

    def do_login() -> Any:
        return client.post(absolute(base_url, "/login"), data={"username": user, "password": pw}, follow_redirects=False)

    clear_cookies(client)
    first = do_login()
    first_jar = _jar(client)
    lines = _set_cookie_lines(first)
    if int(getattr(first, "status_code", 0) or 0) not in (200, 302, 303) or not session_values(first_jar):
        return {
            "test_id": TEST_ID, "category": CATEGORY, "status_hint": "NOT_TESTED", "skip_reason": "no_lab_login",
            "observations": {"detail": "lab login did not yield a session cookie"},
            "finding_candidate": False, "evidence_hints": [], "validity_samples": [],
        }
    # Second login while presenting the first session id (fixation / static id check).
    do_login()
    second_jar = _jar(client)
    rotation = assess_rotation(first_jar, second_jar)

    authed = client.get(protected, follow_redirects=False)
    authed_cls = classify_httpx(authed, authed=True)
    samples.append(authed_cls)
    old_cookies = session_values(second_jar)
    client.get(absolute(base_url, "/logout"), follow_redirects=False)
    clear_cookies(client)
    replay = None
    if old_cookies:
        try:
            for k, v in old_cookies.items():
                client.cookies.set(k, v)
        except Exception:
            pass
        replay = client.get(protected, follow_redirects=False)
    replay_cls = classify_httpx(replay) if replay is not None else None
    if replay_cls is not None:
        samples.append(replay_cls)
    logout = assess_logout(replay_cls.cls if replay_cls is not None else None)
    if authed_cls.cls is not ResponseClass.APP_OK:
        logout = {"result": NOT_ASSESSED, "reason": "protected page not reachable with the session"}
    clear_cookies(client)
    expiry = expiry_posture(lines)
    if any(is_blocking(c) for c in samples):
        return {
            "test_id": TEST_ID, "category": CATEGORY, "status_hint": "BLOCKED", "skip_reason": skip_reason_for(samples),
            "observations": {"mode": "lab", "rotation": rotation, "logout": {"result": NOT_ASSESSED}, "expiry": expiry},
            "finding_candidate": False, "evidence_hints": [], "validity_samples": samples_to_json(samples),
        }
    finding = rotation["result"] == NOT_ROTATED or logout["result"] == NOT_INVALIDATED
    result = {
        "test_id": TEST_ID,
        "category": CATEGORY,
        "observations": {
            "mode": "lab",
            "identity": "lab-mock-account",
            "rotation": rotation,
            "logout": logout,
            "expiry": expiry,
            "replay_class": replay_cls.cls.value if replay_cls is not None else None,
            "replay_denied": bool(replay_cls is not None and is_security_control_evidence(replay_cls)),
        },
        "finding_candidate": finding,
        "detail": ", ".join(
            x for x in (
                "session id not rotated on login" if rotation["result"] == NOT_ROTATED else "",
                "logout does not invalidate the session" if logout["result"] == NOT_INVALIDATED else "",
            ) if x
        ) or "session rotated on login and invalidated on logout",
        "evidence_hints": ["POST /login x2 (session ids compared, values not stored)", "GET /logout", "GET protected with old id"],
        "validity_samples": samples_to_json(samples),
    }
    if not finding and NOT_ASSESSED in (rotation["result"], logout["result"]):
        result["status_hint"] = "INCONCLUSIVE"
        result["skip_reason"] = "lifecycle_partially_assessed"
    return result


def _run_engagement(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Passive only: never logs the engagement session in or out."""
    from attestra.automated_vapt.testing._http import find_jwt_candidates
    from attestra.automated_vapt.testing._session import probe_urls, request_auth
    from attestra.automated_vapt.testing.jwt_posture import assess_tokens

    header_map = {str(k): str(v) for k, v in dict(getattr(auth, "headers", None) or {}).items()}
    jwt = assess_tokens(find_jwt_candidates(*[f"{k}={v}" for k, v in header_map.items()]))
    lines: list[str] = []
    samples = []
    for url in probe_urls(base_url, kwargs, api=False, limit=2):
        try:
            pair = request_auth(client, "GET", url, auth, base_url)
        except Exception:
            continue
        from attestra.automated_vapt.core.response_classifier import classify_pair

        samples.append(classify_pair(pair, authed=True))
        for k, v in (pair.response_headers or {}).items():
            if str(k).lower() == "set-cookie":
                lines.extend(str(v).split("\n"))
    expiry = expiry_posture(lines, jwt)
    finding = bool(expiry["long_lived_session_cookies"]) or "missing_exp" in jwt.get("high_issues", [])
    result: dict[str, Any] = {
        "test_id": TEST_ID,
        "category": CATEGORY,
        "observations": {
            "mode": "engagement_session",
            "identity": _identity_label(auth),
            "rotation": {"result": NOT_ASSESSED, "reason": "needs a login flow; not run against the live engagement session"},
            "logout": {"result": NOT_ASSESSED, "reason": "logging out would end the engagement session; not run"},
            "expiry": expiry,
        },
        "finding_candidate": finding,
        "evidence_hints": ["passive Set-Cookie / JWT lifetime observation"],
        "validity_samples": samples_to_json(samples),
    }
    if any(is_blocking(c) for c in samples) and not finding:
        result["status_hint"] = "BLOCKED"
        result["skip_reason"] = skip_reason_for(samples)
    elif not finding:
        # Rotation/logout were not assessed: never claim a full PASS.
        result["status_hint"] = "INCONCLUSIVE"
        result["skip_reason"] = "lifecycle_passive_only"
    return result


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """SESSLIFE entry point (same signature as other authz modules)."""
    from attestra.automated_vapt.testing._session import resolve_mode

    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_engagement(client, base_url, auth, **kwargs)
    if mode == "lab":
        return _run_lab(client, base_url, **kwargs)
    return {
        "test_id": TEST_ID,
        "category": CATEGORY,
        "status_hint": "NOT_TESTED",
        "skip_reason": "no_auth_session",
        "observations": {"detail": "no ready engagement login profile; session lifecycle not tested"},
        "finding_candidate": False,
        "evidence_hints": [],
        "validity_samples": [],
    }
