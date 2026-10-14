#!/usr/bin/env python3
"""Attestra CI/CD gate (Phase 6.7).

Uploads a scanner result file (SARIF, Trivy JSON, ...) to
``POST {ATTESTRA_URL}/api/engagements/{eid}/imports`` and then asks
``GET /api/engagements/{eid}/gate`` whether the pipeline may pass.

Exit codes: 0 = policy passed, 1 = policy failed (blocking findings),
2 = usage/config error, 3 = API/network error.

Standard library only, so it runs on any runner with Python 3.9+.

Environment (flags override):
  ATTESTRA_URL            e.g. https://attestra.example.com
  ATTESTRA_TOKEN          API key (Bearer), role tester/lead/admin
  ATTESTRA_ENGAGEMENT_ID  engagement id
  ATTESTRA_FAIL_ON        critical|high|medium|low|info  (default: high)
  ATTESTRA_MAX_FINDINGS   allowed blocking findings     (default: 0)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

LEVELS = ("critical", "high", "medium", "low", "info")


def _request(method: str, url: str, token: str, *, body: bytes | None = None, ctype: str | None = None, timeout: int = 120) -> dict:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "attestra-ci/1"}
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - URL is operator-supplied
            raw = r.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"{method} {url} -> HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"{method} {url} -> {e.reason}") from e
    return json.loads(raw or b"{}")


def _multipart(fields: dict[str, str], file_field: str, path: Path) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    out = bytearray()
    for k, v in fields.items():
        out += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    out += (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"{path.name}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    out += path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Upload scan results to Attestra and enforce the CI policy.")
    p.add_argument("--file", action="append", default=[], help="result file; repeat as TOOL=PATH or PATH with --tool")
    p.add_argument("--tool", default=os.getenv("ATTESTRA_TOOL", ""), help="importer name: sarif | trivy | zap | nuclei ...")
    p.add_argument("--url", default=os.getenv("ATTESTRA_URL", ""))
    p.add_argument("--token", default=os.getenv("ATTESTRA_TOKEN", ""))
    p.add_argument("--engagement", default=os.getenv("ATTESTRA_ENGAGEMENT_ID", ""))
    p.add_argument("--fail-on", default=os.getenv("ATTESTRA_FAIL_ON", "high"), choices=LEVELS)
    p.add_argument("--max-findings", type=int, default=int(os.getenv("ATTESTRA_MAX_FINDINGS", "0")))
    p.add_argument("--scope", choices=("uploaded", "engagement"), default=os.getenv("ATTESTRA_GATE_SCOPE", "uploaded"),
                   help="'uploaded' gates only on findings from the uploaded tool(s); 'engagement' on all open findings")
    p.add_argument("--no-gate", action="store_true", help="upload only; never fail the pipeline")
    a = p.parse_args(argv)

    if not (a.url and a.token and a.engagement and a.file):
        print("attestra-ci: --url, --token, --engagement and --file are required (or ATTESTRA_* env vars)", file=sys.stderr)
        return 2
    base = a.url.rstrip("/")
    eid = str(a.engagement).strip()

    uploads: list[tuple[str, Path]] = []
    for spec in a.file:
        tool, sep, path = spec.partition("=")
        if not sep:
            tool, path = a.tool, spec
        if not tool:
            print(f"attestra-ci: no tool for {spec}; use --tool or TOOL=PATH", file=sys.stderr)
            return 2
        fp = Path(path)
        if not fp.is_file():
            print(f"attestra-ci: file not found: {fp}", file=sys.stderr)
            return 2
        uploads.append((tool, fp))

    try:
        for tool, fp in uploads:
            body, ctype = _multipart({"tool": tool}, "file", fp)
            res = _request("POST", f"{base}/api/engagements/{eid}/imports", a.token, body=body, ctype=ctype)
            print(f"attestra-ci: imported {fp.name} as {tool}: import #{res.get('id')} "
                  f"{res.get('new_findings', 0)} new, {res.get('updated_findings', 0)} merged, "
                  f"{res.get('unmatched_findings', 0)} unmatched (sha256 {str(res.get('sha256', ''))[:12]})")
        if a.no_gate:
            return 0
        tools = sorted({t for t, _ in uploads}) if a.scope == "uploaded" else [None]
        failed = False
        for tool in tools:
            q = f"fail_on={a.fail_on}&max_findings={a.max_findings}" + (f"&tool={urllib.parse.quote(tool)}" if tool else "")
            g = _request("GET", f"{base}/api/engagements/{eid}/gate?{q}", a.token)
            label = tool or "engagement"
            c = g.get("open_counts", {})
            print(f"attestra-ci: gate[{label}] fail_on={a.fail_on} max={a.max_findings} -> "
                  f"{'PASS' if g.get('passed') else 'FAIL'} (blocking {g.get('blocking_count', 0)}; "
                  + ", ".join(f"{k}={c.get(k, 0)}" for k in LEVELS) + ")")
            for f in g.get("blocking", [])[:20]:
                print(f"  - [{f['severity']}] #{f['id']} {f['title']} @ {f.get('location', '')}")
            failed = failed or not g.get("passed")
    except RuntimeError as e:
        print(f"attestra-ci: {e}", file=sys.stderr)
        return 3
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
