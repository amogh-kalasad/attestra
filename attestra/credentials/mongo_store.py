"""Fernet-encrypted credential blobs stored in MongoDB (ciphertext only).

The Fernet key remains outside Mongo (``ATTESTRA_CREDENTIAL_FERNET_KEY``).
Plaintext never enters MongoDB documents or logs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from attestra.credentials.store import SecretsError, resolve_fernet_key
from attestra.persistence.mongo.client import get_db
from attestra.persistence.mongo.serialization import utcnow

COLLECTION = "credential_secrets"


class EncryptedMongoStore:
    """Drop-in style secret store backed by a Mongo collection of ciphertext."""

    def __init__(self, db=None):
        self.db = db or get_db()
        self.col = self.db[COLLECTION]
        self.col.create_index("ref", unique=True)

    def _fernet(self) -> Fernet:
        return Fernet(resolve_fernet_key())

    def put(self, ref: str, payload: dict[str, Any] | str) -> str:
        raw = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
        token = self._fernet().encrypt(raw.encode("utf-8")).decode("ascii")
        self.col.update_one(
            {"ref": ref},
            {
                "$set": {
                    "ref": ref,
                    "ciphertext": token,
                    "sha256": hashlib.sha256(token.encode()).hexdigest(),
                    "updated_at": utcnow(),
                },
                "$setOnInsert": {"created_at": utcnow()},
            },
            upsert=True,
        )
        return ref

    def get(self, ref: str) -> str:
        doc = self.col.find_one({"ref": ref})
        if not doc:
            raise SecretsError(f"credential not found: {ref}")
        try:
            return self._fernet().decrypt(doc["ciphertext"].encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise SecretsError("credential decrypt failed") from exc

    def delete(self, ref: str) -> None:
        self.col.delete_one({"ref": ref})
