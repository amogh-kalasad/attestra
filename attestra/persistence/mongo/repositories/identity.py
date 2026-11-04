"""Identity repositories: user administration, invites/resets, API key admin.

Extends the core ``UserRepository`` / ``ApiKeyRepository`` / ``MembershipRepository``
without changing their behaviour. Scope rule (same as ``users.service``): a scoped caller
sees a user when the user's home tenant OR any membership tenant is in scope.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pymongo import ReturnDocument

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.repositories.base import BaseRepository
from attestra.persistence.mongo.repositories.core import (
    ApiKeyRepository,
    MembershipRepository,
    UserRepository,
)
from attestra.persistence.mongo.serialization import ensure_utc, utcnow, with_id
from attestra.persistence.mongo.tenant import TenantAccessDenied, require_tenant_access, tenant_filter

USER_MUTABLE_FIELDS = frozenset({"password_hash", "role", "active", "display_name", "last_login_at", "tenant_id"})


class UserAdminRepository(UserRepository):
    """User lookups/updates honouring home-tenant OR membership scope."""

    def user_tenants(self, user: dict[str, Any]) -> set[int]:
        uid = int(user.get("_id", user.get("id")))
        ids = {int(m["tenant_id"]) for m in self.db[C.TENANT_MEMBERSHIPS].find({"user_id": uid}, {"tenant_id": 1})}
        if user.get("tenant_id") is not None:
            ids.add(int(user["tenant_id"]))
        return ids

    def visible(self, user: dict[str, Any]) -> bool:
        return self.tenant_ids is None or bool(self.user_tenants(user) & set(self.tenant_ids))

    def get_visible(self, user_id: int) -> dict[str, Any] | None:
        doc = self.col.find_one({"_id": int(user_id)})
        if not doc or not self.visible(doc):
            return None
        return with_id(doc)

    def find_by_username(self, username: str) -> dict[str, Any] | None:
        """Exact (normalised lower-case) match first, then case-insensitive. Unscoped lookup."""
        name = (username or "").strip()
        if not name:
            return None
        doc = self.col.find_one({"username": name.lower()}) or self.col.find_one({"username": name})
        if doc is None:
            doc = self.col.find_one({"username": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
        return with_id(doc) if doc else None

    def list_visible(self, tenant_id: int | None = None) -> list[dict[str, Any]]:
        if tenant_id is not None:
            if self.tenant_ids is not None and int(tenant_id) not in self.tenant_ids:
                return []
            tids = [int(tenant_id)]
        elif self.tenant_ids is not None:
            tids = sorted(self.tenant_ids)
        else:
            tids = None
        if tids is None:
            q: dict[str, Any] = {}
        else:
            members = [int(m["user_id"]) for m in self.db[C.TENANT_MEMBERSHIPS].find({"tenant_id": {"$in": tids}}, {"user_id": 1})]
            q = {"$or": [{"tenant_id": {"$in": tids}}, {"_id": {"$in": members}}]}
        return [with_id(d) for d in self.col.find(q).sort("username", 1)]

    def count_active_admins(self) -> int:
        return self.col.count_documents({"role": "admin", "active": True})

    def update_fields(self, user_id: int, **fields: Any) -> dict[str, Any] | None:
        bad = set(fields) - USER_MUTABLE_FIELDS
        if bad:
            raise ValueError(f"cannot update user fields: {sorted(bad)}")
        existing = self.col.find_one({"_id": int(user_id)})
        if not existing or not self.visible(existing):
            return None
        if "tenant_id" in fields and fields["tenant_id"] is not None:
            require_tenant_access(int(fields["tenant_id"]), self.tenant_ids)
        doc = self.col.find_one_and_update(
            {"_id": int(user_id)}, {"$set": fields}, return_document=ReturnDocument.AFTER
        )
        return with_id(doc) if doc else None

    def touch_login(self, user_id: int, when: datetime | None = None) -> None:
        self.col.update_one({"_id": int(user_id)}, {"$set": {"last_login_at": ensure_utc(when) or utcnow()}})


class InviteRepository(BaseRepository):
    """``user_invites``: invite and reset links (only the SHA-256 token hash is stored)."""

    collection_name = C.USER_INVITES

    def create(
        self,
        *,
        purpose: str,
        token_hash: str,
        role: str,
        expires_at: datetime,
        created_by: str,
        email: str = "",
        tenant_id: int | None = None,
        engagement_id: int | None = None,
        user_id: int | None = None,
        doc_id: int | None = None,
    ) -> dict[str, Any]:
        if purpose not in ("invite", "reset"):
            raise ValueError("purpose must be invite or reset")
        if tenant_id is not None:
            require_tenant_access(int(tenant_id), self.tenant_ids)
        elif self.tenant_ids is not None and user_id is None:
            raise TenantAccessDenied("scoped callers cannot create tenant-less invites")
        return self.insert_with_id(
            {
                "purpose": purpose,
                "email": email,
                "role": role,
                "tenant_id": tenant_id,
                "engagement_id": engagement_id,
                "user_id": user_id,
                "token_hash": token_hash,
                "created_by": created_by,
                "created_at": utcnow(),
                "expires_at": ensure_utc(expires_at),
                "used_at": None,
                "revoked_at": None,
            },
            doc_id=doc_id,
        )

    def get_by_token_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Unscoped by design: the token itself is the credential (public accept/reset pages)."""
        doc = self.col.find_one({"token_hash": token_hash})
        return with_id(doc) if doc else None

    def get_scoped(self, invite_id: int) -> dict[str, Any] | None:
        """Scoped lookup matching SQL semantics: invite.tenant_id must be in scope."""
        doc = self.col.find_one({"_id": int(invite_id)})
        if not doc:
            return None
        if self.tenant_ids is not None and (doc.get("tenant_id") is None or int(doc["tenant_id"]) not in self.tenant_ids):
            return None
        return with_id(doc)

    def list_open(self) -> list[dict[str, Any]]:
        q: dict[str, Any] = {"used_at": None, "revoked_at": None}
        q.update(tenant_filter("tenant_id", self.tenant_ids))
        return [with_id(d) for d in self.col.find(q).sort("_id", -1)]

    def revoke(self, invite_id: int) -> bool:
        res = self.col.update_one(
            {"_id": int(invite_id), "used_at": None, "revoked_at": None}, {"$set": {"revoked_at": utcnow()}}
        )
        return res.modified_count == 1

    def revoke_open_for_user(self, user_id: int, *, purpose: str | None = None) -> int:
        q: dict[str, Any] = {"user_id": int(user_id), "used_at": None, "revoked_at": None}
        if purpose:
            q["purpose"] = purpose
        return self.col.update_many(q, {"$set": {"revoked_at": utcnow()}}).modified_count

    def consume(self, invite_id: int, *, user_id: int | None = None) -> bool:
        """Atomically mark an open link used (single-use even under concurrent submits)."""
        sets: dict[str, Any] = {"used_at": utcnow()}
        if user_id is not None:
            sets["user_id"] = int(user_id)
        res = self.col.update_one({"_id": int(invite_id), "used_at": None, "revoked_at": None}, {"$set": sets})
        return res.modified_count == 1


class ApiKeyAdminRepository(ApiKeyRepository):
    """Listing / last-used bookkeeping for API keys. Never returns ``key_hash``."""

    def _public(self, key: dict[str, Any], user: dict[str, Any] | None) -> dict[str, Any]:
        def iso(v):
            return ensure_utc(v).isoformat() if v else None

        return {
            "id": int(key["_id"]),
            "user_id": int(key["user_id"]),
            "username": (user or {}).get("username", ""),
            "prefix": key.get("prefix", ""),
            "created_at": iso(key.get("created_at")),
            "revoked_at": iso(key.get("revoked_at")),
            "last_used_at": iso(key.get("last_used_at")),
            "status": "revoked" if key.get("revoked_at") is not None else "active",
        }

    def list_public(self, *, username: str | None = None) -> list[dict[str, Any]]:
        q: dict[str, Any] = {}
        if username:
            user = self.db[C.USERS].find_one({"username": username.strip().lower()})
            if not user:
                return []
            q["user_id"] = int(user["_id"])
        users: dict[int, dict] = {}
        out = []
        for key in self.col.find(q).sort("_id", 1):
            if not self.in_scope(key):
                continue
            uid = int(key["user_id"])
            if uid not in users:
                users[uid] = self.db[C.USERS].find_one({"_id": uid}) or {}
            out.append(self._public(key, users[uid]))
        return out

    def touch_last_used(self, key_id: int, when: datetime | None = None) -> None:
        self.col.update_one({"_id": int(key_id)}, {"$set": {"last_used_at": ensure_utc(when) or utcnow()}})


__all__ = [
    "ApiKeyAdminRepository",
    "InviteRepository",
    "MembershipRepository",
    "UserAdminRepository",
]
