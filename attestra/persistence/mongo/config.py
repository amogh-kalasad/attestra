"""MongoDB connection settings (env-driven)."""

from __future__ import annotations

import os

# Default points at local replica-set used for transactions in tests/dev.
MONGODB_URI = os.environ.get("ATTESTRA_MONGODB_URI", "mongodb://127.0.0.1:27017/?replicaSet=rs0")
MONGODB_DB = os.environ.get("ATTESTRA_MONGODB_DB", "attestra")
MONGODB_SERVER_SELECTION_TIMEOUT_MS = int(os.environ.get("ATTESTRA_MONGODB_SERVER_SELECTION_TIMEOUT_MS", "5000"))
MONGODB_CONNECT_TIMEOUT_MS = int(os.environ.get("ATTESTRA_MONGODB_CONNECT_TIMEOUT_MS", "5000"))
MONGODB_SOCKET_TIMEOUT_MS = int(os.environ.get("ATTESTRA_MONGODB_SOCKET_TIMEOUT_MS", "30000"))
MONGODB_TLS = os.environ.get("ATTESTRA_MONGODB_TLS", "").lower() in ("1", "true", "yes")
MONGODB_TLS_CA_FILE = os.environ.get("ATTESTRA_MONGODB_TLS_CA_FILE", "") or None
MONGODB_MAX_POOL_SIZE = int(os.environ.get("ATTESTRA_MONGODB_MAX_POOL_SIZE", "50"))
# GridFS bucket name for durable artifacts.
MONGODB_GRIDFS_BUCKET = os.environ.get("ATTESTRA_MONGODB_GRIDFS_BUCKET", "attestra_artifacts")
