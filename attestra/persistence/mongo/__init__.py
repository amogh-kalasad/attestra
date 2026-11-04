"""MongoDB-native persistence for Attestra."""

from __future__ import annotations

from attestra.persistence.mongo.client import close_client, get_client, get_db, init_mongo
from attestra.persistence.mongo.health import ping

__all__ = ["close_client", "get_client", "get_db", "init_mongo", "ping"]
