"""MongoDB GridFS write-once storage backend.

URI scheme: ``mongo://<key>`` where ``key`` is the storage object key
(same relative path shape as ``local://``). Legacy ``local://`` and ``s3://``
URIs are not rewritten here; callers resolve them via the active backend or
migration tooling.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from gridfs import GridFSBucket
from gridfs.errors import NoFile
from pymongo.database import Database

from attestra.persistence.mongo import config as mongo_config
from attestra.persistence.mongo.client import get_db
from attestra.persistence.mongo.repositories.ops import ArtifactRepository
from attestra.storage.local import StorageError

_SAFE = re.compile(r"[^A-Za-z0-9._/-]+")


def _safe_key(key: str) -> str:
    return _SAFE.sub("_", key).lstrip("/")


class MongoStorage:
    """Write-once GridFS storage. Identical bytes re-put is idempotent."""

    def __init__(self, db: Database | None = None, *, bucket_name: str | None = None, tenant_ids=None):
        self.db = get_db() if db is None else db
        self.bucket_name = bucket_name or mongo_config.MONGODB_GRIDFS_BUCKET
        self.bucket = GridFSBucket(self.db, bucket_name=self.bucket_name)
        self._artifacts = ArtifactRepository(self.db, tenant_ids=tenant_ids)

    def _uri_for_key(self, key: str) -> str:
        return f"mongo://{_safe_key(key)}"

    def _parse(self, key_or_uri: str) -> str:
        if key_or_uri.startswith("mongo://"):
            return key_or_uri[len("mongo://") :]
        return _safe_key(key_or_uri)

    def put(self, key: str, data: bytes) -> str:
        rel = _safe_key(key)
        uri = self._uri_for_key(rel)
        sha = hashlib.sha256(data).hexdigest()
        existing = self._artifacts.get_by_uri(uri)
        if existing:
            if existing.get("sha256") == sha:
                return uri
            raise StorageError(f"refusing overwrite of existing object: {key}")
        # Also refuse if GridFS already has this filename with different content.
        prior = self.db[f"{self.bucket_name}.files"].find_one({"filename": rel})
        if prior is not None:
            try:
                blob = self.get(uri)
            except FileNotFoundError:
                blob = b""
            if blob == data:
                # Repair missing metadata row.
                self._artifacts.register(
                    uri,
                    sha,
                    gridfs_id=prior["_id"],
                    key=rel,
                    size=len(data),
                )
                return uri
            raise StorageError(f"refusing overwrite of existing object: {key}")
        grid_id = self.bucket.upload_from_stream(
            rel,
            data,
            metadata={"sha256": sha, "immutable": True},
        )
        self._artifacts.register(uri, sha, gridfs_id=grid_id, key=rel, size=len(data))
        return uri

    def get(self, uri: str) -> bytes:
        rel = self._parse(uri)
        try:
            stream = self.bucket.open_download_stream_by_name(rel)
        except NoFile as exc:
            raise FileNotFoundError(uri) from exc
        try:
            return stream.read()
        finally:
            stream.close()

    def exists(self, uri: str) -> bool:
        rel = self._parse(uri)
        doc = self.db[f"{self.bucket_name}.files"].find_one({"filename": rel}, {"_id": 1})
        return doc is not None

    def metadata(self, uri: str) -> dict[str, Any] | None:
        return self._artifacts.get_by_uri(uri if uri.startswith("mongo://") else self._uri_for_key(uri))
