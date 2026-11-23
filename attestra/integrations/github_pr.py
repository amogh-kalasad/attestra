"""GitHub remediation **pull-request proposals** (separate from Issues).

Draft-only by default. Customer approval is required before a draft PR is
opened on GitHub. This module never pushes commits or merges PRs. Closure is
conceptually tied to the finding ``retest_passed`` workflow via proposal
``status`` (``awaiting_retest`` → ``closed_retest_passed``).

Existing Issues sync remains in ``attestra.integrations.github.GitHubIssuesClient``.
"""
# @lat: [[aasi#Phase 6 GitHub remediation PR proposals]]

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from attestra.integrations.tickets import HttpCall, TicketError, http_json
from attestra.models import Finding

PROPOSAL_STATUSES = frozenset(
    {
        "draft",  # local proposal; not sent to GitHub
        "pending_approval",  # awaiting customer / tenant authorization
        "approved",  # approved; draft PR may be created
        "draft_pr_open",  # GitHub draft PR created (draft=true)
        "awaiting_retest",  # fix claimed; retest required before closure
        "closed_retest_passed",  # closed only after retest_passed semantics
        "rejected",
        "cancelled",
    }
)

# Statuses that allow opening a GitHub draft PR.
_CAN_OPEN_DRAFT_PR = frozenset({"approved"})

# Statuses from which we may mark awaiting retest.
_CAN_AWAIT_RETEST = frozenset({"draft_pr_open", "approved"})


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ProposalError(RuntimeError):
    """Remediation PR proposal workflow error."""


class TenantAuthorizer(Protocol):
    """Callable/protocol: return True when ``tenant_id`` may use GitHub PR proposals."""

    def __call__(self, tenant_id: int) -> bool: ...


def default_authorizer(tenant_id: int, *, allowed: frozenset[int] | None = None) -> bool:
    """Authorize when ``allowed`` is None (open) or contains ``tenant_id``."""
    if allowed is None:
        return True
    return int(tenant_id) in allowed


@dataclass
class RemediationPRProposal:
    """In-process remediation PR proposal linked to one finding."""

    id: str
    tenant_id: int
    engagement_id: int
    finding_id: int
    repo: str
    title: str
    body: str
    head_branch: str
    base_branch: str
    status: str = "draft"
    draft: bool = True
    github_pr_number: int | None = None
    github_pr_url: str = ""
    retest_required: bool = True
    audit: list[dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)
    approved_by: str = ""
    approved_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "finding_id": self.finding_id,
            "repo": self.repo,
            "title": self.title,
            "body": self.body,
            "head_branch": self.head_branch,
            "base_branch": self.base_branch,
            "status": self.status,
            "draft": self.draft,
            "github_pr_number": self.github_pr_number,
            "github_pr_url": self.github_pr_url,
            "retest_required": self.retest_required,
            "audit": list(self.audit),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
        }


def proposal_body_for_finding(f: Finding, *, extra: str = "") -> str:
    """Build a remediation PR body that cites the Attestra finding."""
    lines = [
        f"## Attestra remediation proposal",
        "",
        f"Finding **#{f.id}** (engagement {f.engagement_id})",
        f"Severity: `{f.severity}`  Risk score: `{f.risk_score}`",
        f"Location: `{f.location or ''}`",
        "",
        "### Description",
        f.description or "(none)",
        "",
        "### Recommendation",
        f.recommendation or "(none)",
        "",
        "### Closure policy",
        "This draft PR must **not** be merged automatically.",
        "Finding closure requires a successful retest (`retest_passed`).",
        "Proposal status moves to `awaiting_retest` then `closed_retest_passed`.",
    ]
    if extra:
        lines += ["", extra]
    return "\n".join(lines).strip()


@dataclass
class GitHubPRProposalClient:
    """Draft remediation PR proposals; Issues stay on ``GitHubIssuesClient``.

    Flow: ``propose`` → ``request_approval`` → ``approve`` → ``create_draft_pr``
    → ``mark_awaiting_retest`` → ``close_on_retest_passed``.
    Never pushes branches or merges PRs.
    """

    repo: str  # owner/name
    token: str
    api_url: str = "https://api.github.com"
    http: HttpCall = field(default=http_json)
    name: str = "github_pr"
    base_branch: str = "main"
    # When False, create_draft_pr refuses even after approval (safety latch).
    allow_remote_create: bool = True
    authorizer: TenantAuthorizer | None = None
    _proposals: dict[str, RemediationPRProposal] = field(default_factory=dict, repr=False)

    @classmethod
    def from_env(
        cls,
        env: dict[str, str],
        *,
        http: HttpCall | None = None,
        authorizer: TenantAuthorizer | None = None,
    ) -> GitHubPRProposalClient:
        from attestra.secret_store import get_secret

        repo = env.get("ATTESTRA_GITHUB_REPO", "")
        token = env.get("ATTESTRA_GITHUB_TOKEN") or get_secret("ATTESTRA_GITHUB_TOKEN")
        if not (repo and "/" in repo and token):
            raise TicketError(
                "GitHub PR proposals need ATTESTRA_GITHUB_REPO (owner/name) and ATTESTRA_GITHUB_TOKEN"
            )
        api = env.get("ATTESTRA_GITHUB_API_URL", "https://api.github.com").rstrip("/")
        base = env.get("ATTESTRA_GITHUB_PR_BASE", "main").strip() or "main"
        return cls(
            repo,
            token,
            api,
            http or http_json,
            base_branch=base,
            authorizer=authorizer,
        )

    def _authorize(self, tenant_id: int) -> None:
        check = self.authorizer or (lambda _tid: True)
        if not check(int(tenant_id)):
            raise ProposalError(f"tenant {tenant_id} is not authorized for GitHub PR proposals")

    def _audit(self, proposal: RemediationPRProposal, action: str, actor: str, **extra: Any) -> None:
        entry = {
            "ts": _utcnow().isoformat(),
            "action": action,
            "actor": actor,
            **{k: v for k, v in extra.items() if v is not None},
        }
        proposal.audit.append(entry)
        proposal.updated_at = _utcnow()

    def get(self, proposal_id: str) -> RemediationPRProposal | None:
        return self._proposals.get(proposal_id)

    def list_for_finding(self, finding_id: int, tenant_id: int) -> list[RemediationPRProposal]:
        self._authorize(tenant_id)
        return [
            p
            for p in self._proposals.values()
            if p.finding_id == int(finding_id) and p.tenant_id == int(tenant_id)
        ]

    def propose(
        self,
        f: Finding,
        *,
        tenant_id: int,
        actor: str,
        head_branch: str,
        title: str | None = None,
        body: str | None = None,
        base_branch: str | None = None,
        retest_required: bool = True,
    ) -> RemediationPRProposal:
        """Create a local draft proposal linked to the finding (no GitHub call)."""
        self._authorize(tenant_id)
        if getattr(f, "engagement_id", None) is None:
            raise ProposalError("finding must have engagement_id")
        head = (head_branch or "").strip()
        if not head:
            raise ProposalError("head_branch is required")
        pid = str(uuid.uuid4())
        proposal = RemediationPRProposal(
            id=pid,
            tenant_id=int(tenant_id),
            engagement_id=int(f.engagement_id),
            finding_id=int(f.id),
            repo=self.repo,
            title=(title or f"[Attestra] Remediate finding #{f.id}: {f.title}")[:250],
            body=body if body is not None else proposal_body_for_finding(f),
            head_branch=head,
            base_branch=(base_branch or self.base_branch).strip() or self.base_branch,
            status="draft",
            draft=True,
            retest_required=bool(retest_required),
        )
        self._audit(proposal, "propose", actor, finding_id=f.id)
        proposal.status = "pending_approval"
        self._audit(proposal, "request_approval", actor)
        self._proposals[pid] = proposal
        return proposal

    def approve(self, proposal_id: str, *, tenant_id: int, actor: str) -> RemediationPRProposal:
        """Customer / tenant approval required before any GitHub draft PR is opened."""
        self._authorize(tenant_id)
        proposal = self._require_proposal(proposal_id, tenant_id)
        if proposal.status not in {"pending_approval", "draft"}:
            raise ProposalError(f"cannot approve proposal in status {proposal.status!r}")
        proposal.status = "approved"
        proposal.approved_by = actor
        proposal.approved_at = _utcnow()
        self._audit(proposal, "approve", actor)
        return proposal

    def reject(self, proposal_id: str, *, tenant_id: int, actor: str, reason: str = "") -> RemediationPRProposal:
        self._authorize(tenant_id)
        proposal = self._require_proposal(proposal_id, tenant_id)
        if proposal.status in {"closed_retest_passed", "cancelled"}:
            raise ProposalError(f"cannot reject proposal in status {proposal.status!r}")
        proposal.status = "rejected"
        self._audit(proposal, "reject", actor, reason=reason or None)
        return proposal

    def create_draft_pr(self, proposal_id: str, *, tenant_id: int, actor: str) -> RemediationPRProposal:
        """Open a **draft** pull request on GitHub after approval. Never merges."""
        self._authorize(tenant_id)
        proposal = self._require_proposal(proposal_id, tenant_id)
        if proposal.status not in _CAN_OPEN_DRAFT_PR:
            raise ProposalError(
                f"create_draft_pr requires status in {sorted(_CAN_OPEN_DRAFT_PR)}; got {proposal.status!r}"
            )
        if not proposal.draft:
            raise ProposalError("only draft PRs are allowed; refuse non-draft create")
        if not self.allow_remote_create:
            raise ProposalError("remote PR create is disabled (allow_remote_create=False)")

        payload = {
            "title": proposal.title,
            "head": proposal.head_branch,
            "base": proposal.base_branch,
            "body": proposal.body,
            "draft": True,
        }
        resp = self.http(
            "POST",
            f"{self.api_url}/repos/{self.repo}/pulls",
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
            },
            payload,
        )
        number = resp.get("number")
        if not number:
            raise ProposalError("GitHub did not return a pull request number")
        # Refuse if API somehow returned a non-draft PR.
        if resp.get("draft") is False:
            raise ProposalError("GitHub returned a non-draft PR; refusing to track as remediation proposal")

        proposal.github_pr_number = int(number)
        proposal.github_pr_url = str(resp.get("html_url") or "")
        proposal.status = "draft_pr_open"
        self._audit(
            proposal,
            "create_draft_pr",
            actor,
            github_pr_number=proposal.github_pr_number,
            github_pr_url=proposal.github_pr_url,
            draft=True,
        )
        return proposal

    def mark_awaiting_retest(
        self, proposal_id: str, *, tenant_id: int, actor: str
    ) -> RemediationPRProposal:
        """After a fix is claimed, require retest before conceptual closure."""
        self._authorize(tenant_id)
        proposal = self._require_proposal(proposal_id, tenant_id)
        if not proposal.retest_required:
            raise ProposalError("proposal has retest_required=False")
        if proposal.status not in _CAN_AWAIT_RETEST:
            raise ProposalError(f"cannot await retest from status {proposal.status!r}")
        proposal.status = "awaiting_retest"
        self._audit(proposal, "mark_awaiting_retest", actor)
        return proposal

    def close_on_retest_passed(
        self,
        proposal_id: str,
        *,
        tenant_id: int,
        actor: str,
        finding_status: str,
    ) -> RemediationPRProposal:
        """Close the proposal only when finding workflow reports ``retest_passed``.

        Does not call GitHub merge APIs. Callers remain responsible for transitioning
        the Finding via Attestra services.
        """
        self._authorize(tenant_id)
        proposal = self._require_proposal(proposal_id, tenant_id)
        if finding_status != "retest_passed":
            raise ProposalError(
                f"closure requires finding_status='retest_passed'; got {finding_status!r}"
            )
        if proposal.retest_required and proposal.status not in {
            "awaiting_retest",
            "draft_pr_open",
            "approved",
        }:
            raise ProposalError(
                f"cannot close proposal in status {proposal.status!r} without retest workflow"
            )
        proposal.status = "closed_retest_passed"
        self._audit(proposal, "close_on_retest_passed", actor, finding_status=finding_status)
        return proposal

    def _require_proposal(self, proposal_id: str, tenant_id: int) -> RemediationPRProposal:
        proposal = self._proposals.get(proposal_id)
        if proposal is None or proposal.tenant_id != int(tenant_id):
            raise ProposalError("proposal not found")
        return proposal


__all__ = [
    "PROPOSAL_STATUSES",
    "ProposalError",
    "RemediationPRProposal",
    "GitHubPRProposalClient",
    "proposal_body_for_finding",
    "default_authorizer",
]
