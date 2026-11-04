"""Application persistence bootstrap: MongoDB only."""

from __future__ import annotations

import logging

from attestra import config

log = logging.getLogger("attestra.bootstrap")


def init_persistence(*, use_migrations: bool = True) -> str:
    """Initialize MongoDB persistence. Returns ``mongo``."""
    from attestra.persistence.mongo.client import init_mongo

    config.ensure_dirs()
    init_mongo(apply_migrations=use_migrations)
    log.info("persistence_backend=mongo")
    return "mongo"
