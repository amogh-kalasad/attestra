"""GitHub Issues creation (REST)."""

from __future__ import annotations

from dataclasses import dataclass, field

from attestra.integrations.tickets import HttpCall, TicketError, body_text, http_json, summary
from attestra.models import Finding


@dataclass
class GitHubIssuesClient:
    repo: str  # owner/name
    token: str
    api_url: str = "https://api.github.com"
    http: HttpCall = field(default=http_json)
    name: str = "github"

    @classmethod
    def from_env(cls, env: dict[str, str], *, http: HttpCall | None = None) -> GitHubIssuesClient:
        from attestra.secret_store import get_secret

        repo = env.get("ATTESTRA_GITHUB_REPO", "")
        token = env.get("ATTESTRA_GITHUB_TOKEN") or get_secret("ATTESTRA_GITHUB_TOKEN")
        if not (repo and "/" in repo and token):
            raise TicketError("GitHub sync needs ATTESTRA_GITHUB_REPO (owner/name) and ATTESTRA_GITHUB_TOKEN")
        api = env.get("ATTESTRA_GITHUB_API_URL", "https://api.github.com").rstrip("/")
        return cls(repo, token, api, http or http_json)

    def payload(self, f: Finding) -> dict:
        return {"title": summary(f), "body": body_text(f), "labels": ["attestra", f"severity:{f.severity}"]}

    def create(self, f: Finding) -> str:
        resp = self.http(
            "POST",
            f"{self.api_url}/repos/{self.repo}/issues",
            {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"},
            self.payload(f),
        )
        number = resp.get("number")
        if not number:
            raise TicketError("GitHub did not return an issue number")
        return f"{self.repo}#{number}"
