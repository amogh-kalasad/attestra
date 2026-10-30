"""Sensitive data exposure probes for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing.api_security_tests import run as run_api

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    result = run_api(client, base_url, **kwargs)
    result["test_id"] = "T07"
    result["category"] = "disclosure"
    return result
