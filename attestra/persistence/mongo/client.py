"""MongoDB client lifecycle: pool, database selection, init/shutdown."""

from __future__ import annotations

import logging
from typing import Any

from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import PyMongoError

from attestra.persistence.mongo import config as mongo_config

log = logging.getLogger("attestra.persistence.mongo")

_client: MongoClient | None = None
_db_name: str | None = None


class MongoNotInitializedError(RuntimeError):
    pass


class LiveDatabaseInTestsError(RuntimeError):
    pass


def _guard_test_db(name: str | None) -> None:
    """Hard guard: under pytest, only throwaway ``attestra_test_*`` databases may be used."""
    import sys

    if "pytest" in sys.modules and not (name or "").startswith("attestra_test_"):
        raise LiveDatabaseInTestsError(
            f"refusing MongoDB database {name!r} under pytest; tests must use attestra_test_* databases"
        )


def _build_client(uri: str | None = None) -> MongoClient:
    kwargs: dict[str, Any] = {
        "serverSelectionTimeoutMS": mongo_config.MONGODB_SERVER_SELECTION_TIMEOUT_MS,
        "connectTimeoutMS": mongo_config.MONGODB_CONNECT_TIMEOUT_MS,
        "socketTimeoutMS": mongo_config.MONGODB_SOCKET_TIMEOUT_MS,
        "maxPoolSize": mongo_config.MONGODB_MAX_POOL_SIZE,
        "uuidRepresentation": "standard",
        "tz_aware": True,
    }
    if mongo_config.MONGODB_TLS:
        kwargs["tls"] = True
        if mongo_config.MONGODB_TLS_CA_FILE:
            kwargs["tlsCAFile"] = mongo_config.MONGODB_TLS_CA_FILE
    return MongoClient(uri or mongo_config.MONGODB_URI, **kwargs)


def init_mongo(
    uri: str | None = None,
    *,
    db_name: str | None = None,
    apply_migrations: bool = True,
) -> Database:
    """Create the shared client, optionally run schema migrations, return the DB handle."""
    global _client, _db_name
    _guard_test_db(db_name or (_db_name if _client is not None and uri is None and db_name is None else None) or mongo_config.MONGODB_DB)
    if _client is not None and uri is None and db_name is None:
        return get_db()
    close_client()
    _client = _build_client(uri)
    _db_name = db_name or mongo_config.MONGODB_DB
    # Fail fast if the server is unreachable.
    _client.admin.command("ping")
    db = _client[_db_name]
    if apply_migrations:
        from attestra.persistence.mongo.migrations import apply_pending

        apply_pending(db)
    log.info("mongo_initialized", extra={"db": _db_name})
    return db


def get_client() -> MongoClient:
    if _client is None:
        raise MongoNotInitializedError("call init_mongo() before using MongoDB")
    return _client


def get_db() -> Database:
    if _client is None or _db_name is None:
        raise MongoNotInitializedError("call init_mongo() before using MongoDB")
    _guard_test_db(_db_name)
    return _client[_db_name]


def close_client() -> None:
    global _client, _db_name
    if _client is not None:
        try:
            _client.close()
        except PyMongoError:
            pass
    _client = None
    _db_name = None


def reset_for_tests() -> None:
    """Drop client state without disposing remote data (tests call drop_database separately)."""
    close_client()
