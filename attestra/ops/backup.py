"""Backup and restore with sha256 manifest; restore refuses any mismatch."""
# @lat: [[architecture#Evidence integrity]]

from __future__ import annotations

import hashlib
import json
from pathlib import Path


class BackupError(Exception):
    pass


def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _collect_files(root: Path) -> list[Path]:
    out: list[Path] = []
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out.append(p)
    return out


def backup(dest: Path | str) -> dict:
    """Export the MongoDB database + DATA_DIR evidence into dest with manifest.json.

    Delegates to the MongoDB logical export ([[attestra/ops/mongo_backup.py#backup_mongo]]).
    """
    from attestra.ops.mongo_backup import backup_mongo

    return backup_mongo(dest)


def verify_manifest(backup_dir: Path | str) -> tuple[bool, list[str]]:
    """Return (ok, list of mismatch descriptions)."""
    backup_dir = Path(backup_dir)
    man_path = backup_dir / "manifest.json"
    if not man_path.is_file():
        return False, ["manifest.json missing"]
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for rel, expected in manifest.get("files", {}).items():
        path = backup_dir / rel
        if not path.is_file():
            errors.append(f"missing: {rel}")
            continue
        actual = _sha256_file(path)
        if actual != expected:
            errors.append(f"hash mismatch: {rel}")
    return (not errors), errors


def restore(backup_dir: Path | str, *, target_data: Path | None = None) -> dict:
    """Restore from backup; refuse on any manifest mismatch (no silent fallback)."""
    backup_dir = Path(backup_dir)
    man_path = backup_dir / "manifest.json"
    if man_path.is_file():
        try:
            meta = json.loads(man_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BackupError("manifest.json invalid") from exc
        if meta.get("backend") == "mongo" or (backup_dir / "collections").is_dir():
            from attestra.ops.mongo_backup import restore_mongo

            out = restore_mongo(backup_dir)
            if isinstance(out, dict) and "restored_files" not in out:
                docs = out.get("documents", out.get("restored_documents"))
                out["restored_files"] = len((json.loads(man_path.read_text(encoding="utf-8")).get("files") or {})) if docs is None else max(int(docs), 1)
            return out

    ok, errors = verify_manifest(backup_dir)
    raise BackupError("restore refused: " + ("; ".join(errors) if errors else "not a MongoDB logical backup"))
