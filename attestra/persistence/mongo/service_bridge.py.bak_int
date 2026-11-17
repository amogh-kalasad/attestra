"""Helpers to use Mongo repositories from service-layer call sites.

Call sites can obtain scoped repositories without holding an ORM session.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from attestra.persistence.mongo.client import get_db, init_mongo
from attestra.persistence.mongo.repositories.core import (
    ApiKeyRepository,
    AssetRepository,
    AuthorizationRepository,
    EngagementRepository,
    FindingRepository,
    MembershipRepository,
    ScopeRuleRepository,
    TenantRepository,
    UserRepository,
)
from attestra.persistence.mongo.repositories.ops import (
    ArtifactRepository,
    AuditRepository,
    CreditRepository,
    JobRepository,
)
from attestra.persistence.mongo.tenant import TenantIds, normalize_tenant_ids


@dataclass
class MongoUnitOfWork:
    """Scoped repository bundle for one request/CLI operation."""

    tenant_ids: TenantIds

    def __post_init__(self) -> None:
        self.db = get_db()

    @property
    def tenants(self) -> TenantRepository:
        return TenantRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def users(self) -> UserRepository:
        return UserRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def memberships(self) -> MembershipRepository:
        return MembershipRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def api_keys(self) -> ApiKeyRepository:
        return ApiKeyRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def engagements(self) -> EngagementRepository:
        return EngagementRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def assets(self) -> AssetRepository:
        return AssetRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def authorizations(self) -> AuthorizationRepository:
        return AuthorizationRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def scope_rules(self) -> ScopeRuleRepository:
        return ScopeRuleRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def findings(self) -> FindingRepository:
        return FindingRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def audit(self) -> AuditRepository:
        return AuditRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def jobs(self) -> JobRepository:
        return JobRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def credits(self) -> CreditRepository:
        return CreditRepository(self.db, tenant_ids=self.tenant_ids)

    @property
    def artifacts(self) -> ArtifactRepository:
        return ArtifactRepository(self.db, tenant_ids=self.tenant_ids)


def ensure_mongo_ready() -> None:
    init_mongo()


def tenant_ids_for_principal(uow: MongoUnitOfWork, principal: Any) -> TenantIds:
    """Mirror ``services.tenant_ids_for`` using Mongo memberships."""
    if principal is None:
        return None
    role = getattr(principal, "role", None)
    if role == "admin":
        return None
    ids: set[int] = set()
    home = getattr(principal, "tenant_id", None)
    if home is not None:
        ids.add(int(home))
    user_id = getattr(principal, "user_id", None)
    if user_id is not None:
        for m in MembershipRepository(uow.db, tenant_ids=None).list_for_user(int(user_id)):
            ids.add(int(m["tenant_id"]))
    if not ids:
        if role == "client_viewer":
            return frozenset()
        return None
    return frozenset(ids)


def uow_for_principal(principal: Any = None, *, tenant_ids: TenantIds | object = ...) -> MongoUnitOfWork:
    ensure_mongo_ready()
    if tenant_ids is not ...:
        return MongoUnitOfWork(tenant_ids=normalize_tenant_ids(tenant_ids))  # type: ignore[arg-type]
    bootstrap = MongoUnitOfWork(tenant_ids=None)
    return MongoUnitOfWork(tenant_ids=tenant_ids_for_principal(bootstrap, principal))
