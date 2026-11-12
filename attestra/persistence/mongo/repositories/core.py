"""Foundational domain repositories: tenants, users, engagements, assets, findings."""

from __future__ import annotations

from datetime import date
from typing import Any

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.repositories.base import BaseRepository
from attestra.persistence.mongo.serialization import date_to_datetime, datetime_to_date, ensure_utc, utcnow, with_id
from attestra.persistence.mongo.tenant import (
    TenantAccessDenied,
    require_tenant_access,
    tenant_filter,
    via_engagement_filter,
)


class TenantRepository(BaseRepository):
    collection_name = C.TENANTS

    def list(self) -> list[dict[str, Any]]:
        q = tenant_filter("_id", self.tenant_ids)
        return [with_id(d) for d in self.col.find(q).sort("_id", 1)]

    def get(self, tenant_id: int) -> dict[str, Any] | None:
        doc = self.get_raw(tenant_id)
        if not doc:
            return None
        require_tenant_access(doc["id"], self.tenant_ids)
        return doc

    def create(
        self,
        name: str,
        *,
        industry: str = "",
        country: str = "",
        regulatory_status: str = "",
        technical_scope: list | None = None,
        contact_name: str = "",
        contact_email: str = "",
        data_region: str = "default",
        plan: str = "standard",
        ownership_validity_days: int = 30,
        doc_id: int | None = None,
    ) -> dict[str, Any]:
        if self.tenant_ids is not None:
            # Only unscoped (admin/operator) callers may create tenants.
            raise TenantAccessDenied("tenant creation requires an unscoped caller")
        return self.insert_with_id(
            {
                "name": name,
                "industry": industry,
                "country": country,
                "regulatory_status": regulatory_status,
                "technical_scope": list(technical_scope or []),
                "contact_name": contact_name,
                "contact_email": contact_email,
                "data_region": data_region,
                "plan": plan,
                "ownership_validity_days": int(ownership_validity_days),
            },
            doc_id=doc_id,
        )


class UserRepository(BaseRepository):
    collection_name = C.USERS

    def get(self, user_id: int) -> dict[str, Any] | None:
        # users have no RLS historically; still filter home tenant when scoped
        doc = self.get_raw(user_id)
        if not doc:
            return None
        if self.tenant_ids is not None:
            home = doc.get("tenant_id")
            if home is not None and int(home) not in self.tenant_ids:
                # Memberships may still grant access — callers that need that
                # should use MembershipRepository; hide foreign home tenants.
                raise TenantAccessDenied("not found")
        return doc

    def get_by_username(self, username: str) -> dict[str, Any] | None:
        doc = self.col.find_one({"username": username})
        return with_id(doc) if doc else None

    def create(
        self,
        username: str,
        *,
        password_hash: str = "",
        role: str = "tester",
        display_name: str = "",
        tenant_id: int | None = None,
        active: bool = True,
        doc_id: int | None = None,
    ) -> dict[str, Any]:
        if tenant_id is not None:
            require_tenant_access(tenant_id, self.tenant_ids)
        elif self.tenant_ids is not None:
            # A tenant-scoped caller must not mint global (tenant-less) users.
            raise TenantAccessDenied("scoped callers cannot create users without a tenant")
        return self.insert_with_id(
            {
                "username": username,
                "display_name": display_name,
                "password_hash": password_hash,
                "role": role,
                "active": bool(active),
                "tenant_id": tenant_id,
                "created_at": utcnow(),
                "last_login_at": None,
            },
            doc_id=doc_id,
        )


class MembershipRepository(BaseRepository):
    collection_name = C.TENANT_MEMBERSHIPS

    def list_for_user(self, user_id: int) -> list[dict[str, Any]]:
        q: dict[str, Any] = {"user_id": int(user_id)}
        q.update(tenant_filter("tenant_id", self.tenant_ids))
        return [with_id(d) for d in self.col.find(q)]

    def ensure(self, user_id: int, tenant_id: int, role: str = "") -> dict[str, Any]:
        require_tenant_access(tenant_id, self.tenant_ids)
        existing = self.col.find_one({"user_id": int(user_id), "tenant_id": int(tenant_id)})
        if existing:
            return with_id(existing)
        return self.insert_with_id({"user_id": int(user_id), "tenant_id": int(tenant_id), "role": role})


class ApiKeyRepository(BaseRepository):
    collection_name = C.API_KEYS

    def get_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        doc = self.col.find_one({"key_hash": key_hash})
        return with_id(doc) if doc else None

    def create(self, user_id: int, key_hash: str, prefix: str, *, doc_id: int | None = None) -> dict[str, Any]:
        if self.tenant_ids is not None:
            user = self.db[C.USERS].find_one({"_id": int(user_id)}, {"tenant_id": 1})
            home = user.get("tenant_id") if user else None
            if home is None or int(home) not in self.tenant_ids:
                raise TenantAccessDenied("not found")
        return self.insert_with_id(
            {
                "user_id": int(user_id),
                "key_hash": key_hash,
                "prefix": prefix,
                "created_at": utcnow(),
                "revoked_at": None,
                "last_used_at": None,
            },
            doc_id=doc_id,
        )

    def revoke(self, key_id: int) -> dict[str, Any] | None:
        from pymongo import ReturnDocument

        existing = self.col.find_one({"_id": int(key_id)})
        if not existing or not self.in_scope(existing):
            return None
        doc = self.col.find_one_and_update(
            {"_id": int(key_id), "revoked_at": None},
            {"$set": {"revoked_at": utcnow()}},
            return_document=ReturnDocument.AFTER,
        )
        return with_id(doc) if doc else None


class EngagementRepository(BaseRepository):
    collection_name = C.ENGAGEMENTS

    def get(self, engagement_id: int) -> dict[str, Any] | None:
        doc = self.get_raw(engagement_id)
        if not doc:
            return None
        require_tenant_access(doc["tenant_id"], self.tenant_ids)
        return doc

    def list(self) -> list[dict[str, Any]]:
        q = tenant_filter("tenant_id", self.tenant_ids)
        return [with_id(d) for d in self.col.find(q).sort("_id", 1)]

    def create(
        self,
        tenant_id: int,
        name: str,
        type: str,
        *,
        frameworks: list | None = None,
        window_start: date | None = None,
        window_end: date | None = None,
        status: str = "active",
        doc_id: int | None = None,
    ) -> dict[str, Any]:
        require_tenant_access(tenant_id, self.tenant_ids)
        return self.insert_with_id(
            {
                "tenant_id": int(tenant_id),
                "name": name,
                "type": type,
                "frameworks": list(frameworks or []),
                "window_start": date_to_datetime(window_start),
                "window_end": date_to_datetime(window_end),
                "status": status,
                "created_at": utcnow(),
            },
            doc_id=doc_id,
        )

    def assert_access(self, engagement_id: int) -> dict[str, Any]:
        doc = self.get(engagement_id)
        if not doc:
            raise LookupError(f"engagement {engagement_id} not found")
        return doc


class AssetRepository(BaseRepository):
    collection_name = C.ASSETS

    def _guard_engagement(self, engagement_id: int) -> dict[str, Any]:
        return EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)

    def list_for_engagement(self, engagement_id: int) -> list[dict[str, Any]]:
        self._guard_engagement(engagement_id)
        return [with_id(d) for d in self.col.find({"engagement_id": int(engagement_id)}).sort("_id", 1)]

    def get(self, asset_id: int) -> dict[str, Any] | None:
        doc = self.get_raw(asset_id)
        if not doc:
            return None
        self._guard_engagement(doc["engagement_id"])
        return doc

    def create(self, engagement_id: int, kind: str, identifier: str, **fields: Any) -> dict[str, Any]:
        self._guard_engagement(engagement_id)
        payload = {
            "engagement_id": int(engagement_id),
            "kind": kind,
            "identifier": identifier,
            "name": fields.get("name", ""),
            "environment": fields.get("environment", "production"),
            "test_types": list(fields.get("test_types") or []),
            "intrusive_allowed": bool(fields.get("intrusive_allowed", False)),
            "notes": fields.get("notes", ""),
            "criticality": int(fields.get("criticality", 3)),
            "exposure": fields.get("exposure", "internal"),
            "in_cde": bool(fields.get("in_cde", False)),
            "owner": fields.get("owner", ""),
            "ownership_token": fields.get("ownership_token", ""),
            "ownership_verified_at": ensure_utc(fields.get("ownership_verified_at")),
            "crawl_seed_urls": fields.get("crawl_seed_urls", ""),
            "crawl_spider_minutes": fields.get("crawl_spider_minutes"),
            "crawl_ajax_minutes": fields.get("crawl_ajax_minutes"),
            "api_base_url": fields.get("api_base_url", "") or "",
        }
        return self.insert_with_id(payload, doc_id=fields.get("doc_id"))


class AuthorizationRepository(BaseRepository):
    collection_name = C.AUTHORIZATIONS

    def list_for_engagement(self, engagement_id: int) -> list[dict[str, Any]]:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        docs = []
        for d in self.col.find({"engagement_id": int(engagement_id)}).sort("_id", 1):
            out = with_id(d)
            out["signed_on"] = datetime_to_date(out.get("signed_on"))
            out["expires_on"] = datetime_to_date(out.get("expires_on"))
            docs.append(out)
        return docs

    def create(
        self,
        engagement_id: int,
        document_name: str,
        document_path: str,
        sha256: str,
        signer: str,
        signed_on: date,
        expires_on: date,
        *,
        rules_of_engagement: str = "",
        environments: list | None = None,
        doc_id: int | None = None,
    ) -> dict[str, Any]:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        return self.insert_with_id(
            {
                "engagement_id": int(engagement_id),
                "document_name": document_name,
                "document_path": document_path,
                "sha256": sha256,
                "signer": signer,
                "rules_of_engagement": rules_of_engagement,
                "signed_on": date_to_datetime(signed_on),
                "expires_on": date_to_datetime(expires_on),
                "environments": list(environments or []),
            },
            doc_id=doc_id,
        )


class ScopeRuleRepository(BaseRepository):
    collection_name = C.SCOPE_RULES

    def list_for_engagement(self, engagement_id: int) -> list[dict[str, Any]]:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        return [with_id(d) for d in self.col.find({"engagement_id": int(engagement_id)}).sort("_id", 1)]

    def create(
        self,
        engagement_id: int,
        action: str,
        kind: str,
        pattern: str,
        *,
        note: str = "",
        created_by: str = "",
        doc_id: int | None = None,
    ) -> dict[str, Any]:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        return self.insert_with_id(
            {
                "engagement_id": int(engagement_id),
                "action": action,
                "kind": kind,
                "pattern": pattern,
                "note": note,
                "created_by": created_by,
                "created_at": utcnow(),
            },
            doc_id=doc_id,
        )


class FindingRepository(BaseRepository):
    collection_name = C.FINDINGS

    def get(self, finding_id: int) -> dict[str, Any] | None:
        doc = self.get_raw(finding_id)
        if not doc:
            return None
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(doc["engagement_id"])
        return doc

    def list_for_engagement(self, engagement_id: int) -> list[dict[str, Any]]:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        return [with_id(d) for d in self.col.find({"engagement_id": int(engagement_id)}).sort("_id", 1)]

    def get_by_fingerprint(self, engagement_id: int, fingerprint: str) -> dict[str, Any] | None:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        doc = self.col.find_one({"engagement_id": int(engagement_id), "fingerprint": fingerprint})
        return with_id(doc) if doc else None

    def create(self, engagement_id: int, fingerprint: str, title: str, **fields: Any) -> dict[str, Any]:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        payload = {
            "engagement_id": int(engagement_id),
            "asset_id": fields.get("asset_id"),
            "fingerprint": fingerprint,
            "title": title,
            "description": fields.get("description", ""),
            "recommendation": fields.get("recommendation", ""),
            "impact": fields.get("impact", ""),
            "affected_urls": list(fields.get("affected_urls") or []),
            "references": list(fields.get("references") or []),
            "severity": fields.get("severity", "info"),
            "status": fields.get("status", "new"),
            "cwe": fields.get("cwe", ""),
            "cves": list(fields.get("cves") or []),
            "location": fields.get("location", ""),
            "tools": list(fields.get("tools") or []),
            "rule_ids": list(fields.get("rule_ids") or []),
            "cvss_score": fields.get("cvss_score"),
            "cvss_vector": fields.get("cvss_vector", ""),
            "cvss_version": fields.get("cvss_version", ""),
            "risk_score": fields.get("risk_score"),
            "business_risk": fields.get("business_risk", ""),
            "created_at": utcnow(),
            "updated_at": utcnow(),
        }
        return self.insert_with_id(payload, doc_id=fields.get("doc_id"))

    def list_scoped(self) -> list[dict[str, Any]]:
        """List findings visible under current tenant scope (via engagement)."""
        q = via_engagement_filter(self.db, self.tenant_ids)
        return [with_id(d) for d in self.col.find(q).sort("_id", 1)]
