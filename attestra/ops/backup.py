"""Backup and restore with sha256 manifest; restore refuses any mismatch."""
# @lat: [[architecture#Evidence integrity]]

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from attestra import config


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
    """Copy DB + DATA_DIR evidence/imports/reports/keys/feeds into dest with manifest.json."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    config.ensure_dirs()

    db_url = config.DATABASE_URL
    if not db_url.startswith("sqlite:///"):
        raise BackupError("backup currently supports SQLite DATABASE_URL only")
    db_path = Path(db_url.replace("sqlite:///", "", 1))
    if not db_path.is_file():
        raise BackupError(f"database file not found: {db_path}")

    # Online SQLite backup API
    dest_db = dest / "attestra.db"
    src = sqlite3.connect(str(db_path))
    try:
        dst = sqlite3.connect(str(dest_db))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    copied: list[str] = ["attestra.db"]
    for sub in ("evidence", "imports", "reports", "keys", "feeds", "tenants", "raw", "packs"):
        src_dir = config.DATA_DIR / sub
        if not src_dir.exists():
            continue
        for path in _collect_files(src_dir):
            rel = path.relative_to(config.DATA_DIR).as_posix()
            target = dest / "data" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            copied.append(f"data/{rel}")

    manifest: dict = {
        "created_at": datetime.now(UTC).isoformat(),
        "files": {},
    }
    for rel in copied:
        path = dest / rel
        manifest["files"][rel] = _sha256_file(path)

    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"dest": str(dest), "files": len(manifest["files"]), "manifest": str(dest / "manifest.json")}


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
    ok, errors = verify_manifest(backup_dir)
    if not ok:
        raise BackupError("restore refused: " + "; ".join(errors))

    db_url = config.DATABASE_URL
    if not db_url.startswith("sqlite:///"):
        raise BackupError("restore currently supports SQLite DATABASE_URL only")
    db_path = Path(db_url.replace("sqlite:///", "", 1))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    src_db = backup_dir / "attestra.db"
    if not src_db.is_file():
        raise BackupError("attestra.db missing from backup")
    shutil.copy2(src_db, db_path)

    data_root = target_data or config.DATA_DIR
    data_src = backup_dir / "data"
    restored = 1  # db
    if data_src.is_dir():
        for path in _collect_files(data_src):
            rel = path.relative_to(data_src)
            target = data_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                try:
                    target.chmod(0o666)
                except OSError:
                    pass
            shutil.copy2(path, target)
            restored += 1
    return {"restored_files": restored, "database": str(db_path)}
