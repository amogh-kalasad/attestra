"""Pluggable storage backends for evidence and artifacts."""
# @lat: [[architecture#Evidence integrity]]

from __future__ import annotations

from typing import Protocol, runtime_checkable

from attestra import config


@runtime_checkable
class Storage(Protocol):
    def put(self, key: str, data: bytes) -> str:
        """Store bytes; return URI. Must refuse overwrite of existing key."""
        ...

    def get(self, uri: str) -> bytes:
        ...

    def exists(self, uri: str) -> bool:
        ...


def get_storage() -> Storage:
    backend = (config.STORAGE_BACKEND or "local").lower()
    if backend == "s3":
        from attestra.storage.s3 import S3Storage

        return S3Storage()
    from attestra.storage.local import LocalStorage

    return LocalStorage()
