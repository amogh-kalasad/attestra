"""Passive attack-surface discovery (Workstream A, WP4).

Everything here produces *candidates* and *observations*, never assets or findings:

* candidates are stored per tenant/engagement in ``discovery_candidates`` with
  provenance, confidence, resolution status and an approval state;
* a candidate becomes an Asset only through an explicit approval by a user with
  ``asset.write`` on the engagement (``discovery.routes``), which goes through the
  normal ``services.add_asset`` path; it is never auto-added and never scanned before;
* takeover results are "suspected" only; nothing ever tries to claim a resource.

The whole feature is off unless ``config.DISCOVERY_ENABLED`` (``ATTESTRA_DISCOVERY_ENABLED``)
is set. No provider API keys are read or required.
"""
# @lat: [[attack-surface-and-platform#Passive discovery]]

from __future__ import annotations

import os

_TRUE = frozenset({"1", "true", "yes", "on"})


class DiscoveryDisabled(RuntimeError):
    """Raised when a discovery entry point is called while the feature flag is off."""


def discovery_enabled() -> bool:
    """``config.DISCOVERY_ENABLED`` once INT wires it, else ``ATTESTRA_DISCOVERY_ENABLED`` (default off)."""
    try:
        from attestra import config

        val = getattr(config, "DISCOVERY_ENABLED", None)
    except Exception:  # noqa: BLE001
        val = None
    if val is not None:
        return bool(val)
    return os.environ.get("ATTESTRA_DISCOVERY_ENABLED", "").strip().lower() in _TRUE


def require_enabled() -> None:
    if not discovery_enabled():
        raise DiscoveryDisabled("asset discovery is off (set ATTESTRA_DISCOVERY_ENABLED=1)")
