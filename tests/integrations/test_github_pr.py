"""Unit tests for GitHub remediation PR proposals (draft-only, approval-gated)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

# @lat: [[aasi#Phase 6 GitHub remediation PR proposals]]


class _FakeHttp:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        if callable(self.response):
            return self.response(method, url, headers, body)
        return self.response


def _finding(**kwargs):
    defaults = dict(
        id=7,
        engagement_id=3,
        title="Prompt injection",
        description="Model accepts injected instructions",
        recommendation="Harden system prompt and add input filters",
        severity="high",
        risk_score=8.5,
        location="https://chat.example/api",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


@pytest.fixture
def client():
    from attestra.integrations.github_pr import GitHubPRProposalClient, default_authorizer

    http = _FakeHttp({"number": 101, "draft": True, "html_url": "https://github.com/acme/app/pull/101"})
    return GitHubPRProposalClient(
        repo="acme/app",
        token="t",
        http=http,
        authorizer=lambda tid: default_authorizer(tid, allowed=frozenset({1, 2})),
    )


# @lat: [[tests#AASI Phase 6 GitHub PR proposals#Propose requires approval before draft PR]]
def test_propose_requires_approval_before_draft_pr(client):
    from attestra.integrations.github_pr import ProposalError

    f = _finding()
    proposal = client.propose(f, tenant_id=1, actor="analyst", head_branch="fix/attestra-7")
    assert proposal.status == "pending_approval"
    assert proposal.draft is True
    assert proposal.finding_id == 7
    assert "retest_passed" in proposal.body
    assert client.http.calls == []  # no GitHub call yet

    with pytest.raises(ProposalError, match="approved"):
        client.create_draft_pr(proposal.id, tenant_id=1, actor="analyst")

    client.approve(proposal.id, tenant_id=1, actor="customer")
    assert proposal.status == "approved"
    assert proposal.approved_by == "customer"

    opened = client.create_draft_pr(proposal.id, tenant_id=1, actor="analyst")
    assert opened.status == "draft_pr_open"
    assert opened.github_pr_number == 101
    assert len(client.http.calls) == 1
    method, url, headers, body = client.http.calls[0]
    assert method == "POST"
    assert url.endswith("/repos/acme/app/pulls")
    assert body["draft"] is True
    assert body["head"] == "fix/attestra-7"
    assert "Authorization" in headers


# @lat: [[tests#AASI Phase 6 GitHub PR proposals#Tenant authorization enforced]]
def test_tenant_authorization_enforced(client):
    from attestra.integrations.github_pr import ProposalError

    with pytest.raises(ProposalError, match="not authorized"):
        client.propose(_finding(), tenant_id=99, actor="x", head_branch="b")


# @lat: [[tests#AASI Phase 6 GitHub PR proposals#Never merge; closure needs retest_passed]]
def test_closure_tied_to_retest_passed(client):
    from attestra.integrations.github_pr import ProposalError

    f = _finding()
    p = client.propose(f, tenant_id=1, actor="a", head_branch="fix/x")
    client.approve(p.id, tenant_id=1, actor="customer")
    client.create_draft_pr(p.id, tenant_id=1, actor="a")
    client.mark_awaiting_retest(p.id, tenant_id=1, actor="a")
    assert p.status == "awaiting_retest"

    with pytest.raises(ProposalError, match="retest_passed"):
        client.close_on_retest_passed(p.id, tenant_id=1, actor="qa", finding_status="fixed")

    closed = client.close_on_retest_passed(
        p.id, tenant_id=1, actor="qa", finding_status="retest_passed"
    )
    assert closed.status == "closed_retest_passed"
    actions = [e["action"] for e in closed.audit]
    assert "propose" in actions
    assert "approve" in actions
    assert "create_draft_pr" in actions
    assert "close_on_retest_passed" in actions
    # No merge endpoint was called — only the draft create POST.
    assert all("/merge" not in c[1] for c in client.http.calls)
    assert all(c[3].get("draft") is True for c in client.http.calls if isinstance(c[3], dict))


# @lat: [[tests#AASI Phase 6 GitHub PR proposals#Separate from Issues client]]
def test_separate_from_issues_module():
    from attestra.integrations import github, github_pr

    assert hasattr(github, "GitHubIssuesClient")
    assert hasattr(github_pr, "GitHubPRProposalClient")
    assert github.GitHubIssuesClient is not github_pr.GitHubPRProposalClient
    assert github_pr.GitHubPRProposalClient.name == "github_pr"


# @lat: [[tests#AASI Phase 6 GitHub PR proposals#Refuse non-draft remote response]]
def test_refuse_non_draft_remote_response():
    from attestra.integrations.github_pr import GitHubPRProposalClient, ProposalError

    http = _FakeHttp({"number": 5, "draft": False, "html_url": "https://github.com/acme/app/pull/5"})
    client = GitHubPRProposalClient(repo="acme/app", token="t", http=http)
    p = client.propose(_finding(), tenant_id=1, actor="a", head_branch="fix/y")
    client.approve(p.id, tenant_id=1, actor="customer")
    with pytest.raises(ProposalError, match="non-draft"):
        client.create_draft_pr(p.id, tenant_id=1, actor="a")
