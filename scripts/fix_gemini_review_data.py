"""One-shot data fixes from Gemini report review (local eng tenant).

- Tenant contact_email typo ``gamil.com`` → ``gmail.com``
- Public https FQDN assets stored as ``internal`` → ``internet``

Safe to re-run. Does not commit git; writes Mongo (and SQLite tenants/assets when present).
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_dotenv() -> None:
    env_path = ROOT / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _fix_email(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return raw
    lower = raw.lower()
    if lower.endswith("@gamil.com"):
        return raw[: -len("@gamil.com")] + "@gmail.com"
    return raw


def _looks_public_https(identifier: str) -> bool:
    try:
        from attestra.reports.labels import looks_like_public_https_fqdn

        return looks_like_public_https_fqdn(identifier)
    except Exception:
        parts = urlsplit((identifier or "").strip())
        host = (parts.hostname or "").lower()
        return parts.scheme.lower() == "https" and "." in host and host not in ("localhost",)


def fix_sqlite(db_path: Path) -> dict:
    out = {"emails": 0, "assets": 0, "path": str(db_path)}
    if not db_path.is_file():
        return out
    con = sqlite3.connect(str(db_path))
    try:
        for tid, email in con.execute("SELECT id, contact_email FROM tenants").fetchall():
            fixed = _fix_email(email or "")
            if fixed != (email or ""):
                con.execute("UPDATE tenants SET contact_email = ? WHERE id = ?", (fixed, tid))
                out["emails"] += 1
                print(f"sqlite tenant {tid}: {(email or '')!r} -> {fixed!r}")
        for aid, ident, exposure in con.execute(
            "SELECT id, identifier, exposure FROM assets"
        ).fetchall():
            if (exposure or "").lower() == "internal" and _looks_public_https(ident or ""):
                con.execute("UPDATE assets SET exposure = 'internet' WHERE id = ?", (aid,))
                out["assets"] += 1
                print(f"sqlite asset {aid}: {ident!r} exposure internal -> internet")
        con.commit()
    finally:
        con.close()
    return out


def fix_mongo() -> dict:
    out = {"emails": 0, "assets": 0}
    from attestra.persistence.mongo.client import get_db, init_mongo

    uri = os.environ.get("ATTESTRA_MONGODB_URI") or "mongodb://localhost:27017/?replicaSet=rs0"
    db_name = os.environ.get("ATTESTRA_MONGODB_DB") or "attestra"
    init_mongo(uri, db_name=db_name, apply_migrations=False)
    db = get_db()
    for t in db.tenants.find({}, {"contact_email": 1, "name": 1}):
        email = t.get("contact_email") or ""
        fixed = _fix_email(email)
        if fixed != email:
            db.tenants.update_one({"_id": t["_id"]}, {"$set": {"contact_email": fixed}})
            out["emails"] += 1
            print(f"mongo tenant {t['_id']} ({t.get('name')}): {email!r} -> {fixed!r}")
    for a in db.assets.find({"exposure": "internal"}, {"identifier": 1, "exposure": 1}):
        ident = a.get("identifier") or ""
        if _looks_public_https(ident):
            db.assets.update_one({"_id": a["_id"]}, {"$set": {"exposure": "internet"}})
            out["assets"] += 1
            print(f"mongo asset {a['_id']}: {ident!r} exposure internal -> internet")
    return out


def main() -> int:
    _load_dotenv()
    sqlite_out = fix_sqlite(ROOT / "data" / "attestra.db")
    print("sqlite:", sqlite_out)
    try:
        mongo_out = fix_mongo()
        print("mongo:", mongo_out)
    except Exception as exc:  # noqa: BLE001
        print("mongo skipped:", exc)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
