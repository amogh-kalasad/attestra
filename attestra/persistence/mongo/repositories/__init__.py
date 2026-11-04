"""MongoDB repositories for Attestra domain entities."""

from __future__ import annotations

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
from attestra.persistence.mongo.repositories.identity import (
    ApiKeyAdminRepository,
    InviteRepository,
    UserAdminRepository,
)
from attestra.persistence.mongo.repositories.ops import (
    ArtifactRepository,
    AuditRepository,
    CreditRepository,
    JobRepository,
)
from attestra.persistence.mongo.repositories.reports import ReportRepository
from attestra.persistence.mongo.repositories.settings import (
    CertificationAuthorityRepository,
    EmailAlertSentRepository,
    EmailAlertSettingsRepository,
)
from attestra.persistence.mongo.repositories.webhooks import (
    FindingAssignmentRepository,
    WebhookDeliveryRepository,
    WebhookEndpointRepository,
    WorkflowRuleRepository,
)

__all__ = [
    "ApiKeyAdminRepository",
    "CertificationAuthorityRepository",
    "EmailAlertSentRepository",
    "EmailAlertSettingsRepository",
    "FindingAssignmentRepository",
    "InviteRepository",
    "UserAdminRepository",
    "WebhookDeliveryRepository",
    "WebhookEndpointRepository",
    "WorkflowRuleRepository",
    "ApiKeyRepository",
    "ArtifactRepository",
    "AssetRepository",
    "AuditRepository",
    "AuthorizationRepository",
    "CreditRepository",
    "EngagementRepository",
    "FindingRepository",
    "JobRepository",
    "MembershipRepository",
    "ReportRepository",
    "ScopeRuleRepository",
    "TenantRepository",
    "UserRepository",
]
