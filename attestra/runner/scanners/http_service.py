"""GPL/AGPL scanners (OpenVAS, MobSF) are never bundled or linked.

They run as separate services that Attestra would reach over HTTP. Each one is
off by default and needs an explicit enable flag plus a base URL. Results come
back into Attestra through the normal importers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

SERVICES = {
    "openvas": {"licence": "AGPL-3.0 (gvmd) / GPL-2.0+ (scanner)", "env": "OPENVAS"},
    "mobsf": {"licence": "GPL-3.0", "env": "MOBSF"},
}


class ServiceDisabled(RuntimeError):
    pass


@dataclass(frozen=True)
class HttpServiceConfig:
    name: str
    base_url: str
    licence: str


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def service_config(name: str, env: dict | None = None) -> HttpServiceConfig:
    """Return the configured service, or raise ServiceDisabled. Nothing is contacted here."""
    env = os.environ if env is None else env
    key = name.lower()
    if key not in SERVICES:
        raise KeyError(f"unknown HTTP scanner service {name!r}; choose from {sorted(SERVICES)}")
    prefix = f"ATTESTRA_{SERVICES[key]['env']}"
    if not _truthy(env.get(f"{prefix}_ENABLED")):
        raise ServiceDisabled(f"{key} is disabled; set {prefix}_ENABLED=1 and {prefix}_URL to use it")
    url = (env.get(f"{prefix}_URL") or "").strip()
    if not url.startswith(("https://", "http://")):
        raise ServiceDisabled(f"{prefix}_URL must be an http(s) URL")
    return HttpServiceConfig(name=key, base_url=url.rstrip("/"), licence=SERVICES[key]["licence"])


def enabled_services(env: dict | None = None) -> list[str]:
    out = []
    for name in SERVICES:
        try:
            service_config(name, env)
        except ServiceDisabled:
            continue
        out.append(name)
    return out
