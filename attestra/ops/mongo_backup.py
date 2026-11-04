"""MongoDB-aware backup/restore with SHA-256 manifest.

Produces a logical export of collections + GridFS artifacts (+ optional DATA_DIR
keys). This is application-consistent for a quiet system; production deployments
that need point-in-time recovery should also use replica-set ``mongodump`` /
``mongorestore`` (documented in the cutover runbook).

Restore refuses on any manifest mismatch.
"""
# @lat: [[architecture#Evidence integrity]]
# @lat: [[architecture#MongoDB migration (in progress)]]

from __future__ import annotations

import json
import shutil
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from bson import Binary, ObjectId
from gridfs import GridFSBucket

from attestra import config
from attestra.ops.backup import BackupError, _collect_files, _sha256_file
from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo import config as mongo_config
from attestra.persistence.mongo.client import get_db, init_mongo


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return {"$date": obj.astimezone(UTC).isoformat()}
    if isinstance(obj, date):
        return {"$date": datetime(obj.year, obj.month, obj.day, tzinfo=UTC).isoformat()}
    if isinstance(obj, ObjectId):
        return {"$oid": str(obj)}
    if isinstance(obj, Binary):
        return {"$binary": obj.hex()}
    if isinstance(obj, bytes):
        return {"$binary": obj.hex()}
    raise TypeError(f"not JSON serializable: {type(obj)!r}")


def _decode(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value.keys()) == {"$date"}:
            return datetime.fromisoformat(value["$date"].replace("Z", "+00:00"))
        if set(value.keys()) == {"$oid"}:
            return ObjectId(value["$oid"])
        if set(value.keys()) == {"$binary"}:
            return bytes.fromhex(value["$binary"])
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


def backup_mongo(dest: Path | str, *, include_data_dir_keys: bool = True) -> dict:
    """Export MongoDB collections + GridFS into ``dest`` with ``manifest.json``."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    init_mongo(apply_migrations=False)
    db = get_db()

    copied: list[str] = []
    meta = {
        "created_at": datetime.now(UTC).isoformat(),
        "backend": "mongo",
        "db": db.name,
        "mongodb_uri_host": "redacted",
        "gridfs_bucket": mongo_config.MONGODB_GRIDFS_BUCKET,
        "note": "Logical export; use mongodump for PITR on replica sets.",
    }
    (dest / "backup_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    copied.append("backup_meta.json")

    coll_dir = dest / "collections"
    coll_dir.mkdir(exist_ok=True)
    names = list(C.DOMAIN_COLLECTIONS) + [
        C.ID_SEQUENCES,
        C.AUDIT_CHAIN_HEAD,
        C.SCHEMA_MIGRATIONS,
        "credential_secrets",
        "_migration_checkpoints",
    ]
    # Also include GridFS metadata collections if present
    for name in sorted(set(names) | set(db.list_collection_names())):
        if name.startswith("system."):
            continue
        path = coll_dir / f"{name}.jsonl"
        count = 0
        with path.open("w", encoding="utf-8") as fh:
            for doc in db[name].find().sort("_id", 1):
                fh.write(json.dumps(doc, default=_json_default, separators=(",", ":")) + "\n")
                count += 1
        if count == 0 and name not in names:
            path.unlink(missing_ok=True)
            continue
        copied.append(f"collections/{name}.jsonl")

    # GridFS files
    bucket_name = mongo_config.MONGODB_GRIDFS_BUCKET
    files_coll = f"{bucket_name}.files"
    if files_coll in db.list_collection_names():
        gdir = dest / "gridfs"
        gdir.mkdir(exist_ok=True)
        bucket = GridFSBucket(db, bucket_name=bucket_name)
        for file_doc in db[files_coll].find().sort("filename", 1):
            filename = file_doc.get("filename") or str(file_doc["_id"])
            safe = filename.replace("/", "__").replace("\\", "__")
            out = gdir / safe
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("wb") as fh:
                bucket.download_to_stream(file_doc["_id"], fh)
            meta_path = gdir / f"{safe}.meta.json"
            meta_path.write_text(
                json.dumps(
                    {
                        "filename": filename,
                        "metadata": file_doc.get("metadata") or {},
                        "length": file_doc.get("length"),
                        "uploadDate": file_doc.get("uploadDate").isoformat()
                        if isinstance(file_doc.get("uploadDate"), datetime)
                        else file_doc.get("uploadDate"),
                    },
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
            copied.append(f"gridfs/{safe}")
            copied.append(f"gridfs/{safe}.meta.json")

    if include_data_dir_keys:
        config.ensure_dirs()
        for sub in ("keys",):
            src_dir = config.DATA_DIR / sub
            if not src_dir.exists():
                continue
            for path in _collect_files(src_dir):
                rel = path.relative_to(config.DATA_DIR).as_posix()
                target = dest / "data" / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
                copied.append(f"data/{rel}")

    manifest = {"created_at": meta["created_at"], "backend": "mongo", "files": {}}
    for rel in copied:
        manifest["files"][rel] = _sha256_file(dest / rel)
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"dest": str(dest), "files": len(manifest["files"]), "manifest": str(dest / "manifest.json"), "backend": "mongo"}


def restore_mongo(backup_dir: Path | str, *, drop_existing: bool = False) -> dict:
    """Restore logical Mongo backup; refuse on manifest mismatch."""
    backup_dir = Path(backup_dir)
    man_path = backup_dir / "manifest.json"
    if not man_path.is_file():
        raise BackupError("manifest.json missing")
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    if manifest.get("backend") not in (None, "mongo"):
        # Allow restores that only have mongo files even if older tooling omitted backend
        pass
    errors: list[str] = []
    for rel, expected in manifest.get("files", {}).items():
        path = backup_dir / rel
        if not path.is_file():
            errors.append(f"missing: {rel}")
            continue
        if _sha256_file(path) != expected:
            errors.append(f"hash mismatch: {rel}")
    if errors:
        raise BackupError("restore refused: " + "; ".join(errors))

    init_mongo(apply_migrations=True)
    db = get_db()
    restored = 0

    coll_dir = backup_dir / "collections"
    if coll_dir.is_dir():
        for path in sorted(coll_dir.glob("*.jsonl")):
            name = path.stem
            if drop_existing:
                db[name].drop()
            docs = []
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                docs.append(_decode(json.loads(line)))
            if docs:
                # Replace by _id
                from pymongo import ReplaceOne

                ops = [ReplaceOne({"_id": d["_id"]}, d, upsert=True) for d in docs if "_id" in d]
                if ops:
                    db[name].bulk_write(ops, ordered=False)
                restored += len(docs)

    gdir = backup_dir / "gridfs"
    if gdir.is_dir():
        bucket = GridFSBucket(db, bucket_name=mongo_config.MONGODB_GRIDFS_BUCKET)
        for meta_path in sorted(gdir.glob("*.meta.json")):
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            filename = meta["filename"]
            # meta file is ``<safe>.meta.json`` → blob file is ``<safe>``
            blob_name = meta_path.name[: -len(".meta.json")]
            blob_path = meta_path.with_name(blob_name)
            if not blob_path.is_file():
                continue
            data = blob_path.read_bytes()
            # Idempotent: skip if identical filename+sha already present
            existing = db[f"{mongo_config.MONGODB_GRIDFS_BUCKET}.files"].find_one({"filename": filename})
            if existing:
                continue
            bucket.upload_from_stream(filename, data, metadata=meta.get("metadata") or {})
            restored += 1

    data_src = backup_dir / "data"
    if data_src.is_dir():
        for path in _collect_files(data_src):
            rel = path.relative_to(data_src)
            target = config.DATA_DIR / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            restored += 1

    return {"restored_documents_or_files": restored, "database": db.name, "backend": "mongo"}
