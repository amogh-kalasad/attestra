"""Organization-level domain ownership (per-hostname DNS / well-known file)."""

from attestra.org_ownership.service import (
    WELL_KNOWN_DOWNLOAD_NAME,
    add_ownership_host,
    backfill_ownership_hosts,
    confirm_ownership_host,
    ensure_org_ownership_host,
    get_ownership_host,
    host_card,
    list_ownership_hosts,
    renew_org_ownership_host_if_expired,
    sync_assets_from_org_host,
    verify_ownership_host,
)

__all__ = [
    "WELL_KNOWN_DOWNLOAD_NAME",
    "add_ownership_host",
    "backfill_ownership_hosts",
    "confirm_ownership_host",
    "ensure_org_ownership_host",
    "get_ownership_host",
    "host_card",
    "list_ownership_hosts",
    "renew_org_ownership_host_if_expired",
    "sync_assets_from_org_host",
    "verify_ownership_host",
]
