"""Local filesystem write-once storage."""

from __future__ import annotations

import re
from pathlib import Path

from attestra import config


class StorageError(Exception):
    pass


def _safe_key(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]+", "_", key).lstrip("/")


class LocalStorage:
    """Write-once files under DATA_DIR. URI form: ``local://relative/path``."""

    def __init__(self, root: Path | None = None):
        self.root = (root or config.DATA_DIR).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key_or_uri: str) -> Path:
        if key_or_uri.startswith("local://"):
            rel = key_or_uri[len("local://") :]
        else:
            rel = _safe_key(key_or_uri)
        path = (self.root / rel).resolve()
        if not str(path).startswith(str(self.root)):
            raise StorageError("path escapes storage root")
        return path

    def put(self, key: str, data: bytes) -> str:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() == data:
                rel = path.relative_to(self.root).as_posix()
                return f"local://{rel}"
            raise StorageError(f"refusing overwrite of existing object: {key}")
        path.write_bytes(data)
        path.chmod(0o444)
        rel = path.relative_to(self.root).as_posix()
        return f"local://{rel}"

    def get(self, uri: str) -> bytes:
        path = self._path(uri)
        if not path.exists():
            raise FileNotFoundError(uri)
        return path.read_bytes()

    def exists(self, uri: str) -> bool:
        return self._path(uri).exists()

    def path_for(self, uri: str) -> Path:
        return self._path(uri)
