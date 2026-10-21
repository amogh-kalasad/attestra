"""Load metadata-driven report template configuration from YAML."""
# @lat: [[reports#Template configuration]]

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

DATA = Path(__file__).parent / "data" / "template_config.yaml"


@lru_cache(maxsize=1)
def load_template_config() -> dict:
    """Return the built-in template configuration dict."""
    return yaml.safe_load(DATA.read_text(encoding="utf-8")) or {}


def clear_template_config_cache() -> None:
    load_template_config.cache_clear()


def kind_config(kind: str) -> dict:
    """Section metadata for one report kind, or empty dict if unknown."""
    cfg = load_template_config()
    return dict((cfg.get("kinds") or {}).get(kind) or {})


def cvss_legend() -> dict[str, str]:
    return dict(load_template_config().get("cvss_legend") or {})


def methodology_phases() -> list[str]:
    return list(load_template_config().get("methodology_phases") or [])


def disclaimer_text() -> str:
    return str(load_template_config().get("disclaimer") or "").strip()
