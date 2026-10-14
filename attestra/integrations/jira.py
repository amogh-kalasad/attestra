"""Jira Cloud/Server issue creation (REST v2)."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from attestra.integrations.tickets import HttpCall, TicketError, body_text, http_json, summary
from attestra.models import Finding

PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}


@dataclass
class JiraClient:
    base_url: str
    project: str
    user: str
    token: str
    issue_type: str = "Bug"
    http: HttpCall = field(default=http_json)
    name: str = "jira"

    @classmethod
    def from_env(cls, env: dict[str, str], *, http: HttpCall | None = None) -> JiraClient:
        from attestra.secret_store import get_secret

        url = env.get("ATTESTRA_JIRA_URL", "").rstrip("/")
        project = env.get("ATTESTRA_JIRA_PROJECT", "")
        user = env.get("ATTESTRA_JIRA_USER", "")
        token = env.get("ATTESTRA_JIRA_TOKEN") or get_secret("ATTESTRA_JIRA_TOKEN")
        if not (url and project and user and token):
            raise TicketError("Jira sync needs ATTESTRA_JIRA_URL, _PROJECT, _USER and _TOKEN")
        return cls(url, project, user, token, env.get("ATTESTRA_JIRA_ISSUE_TYPE", "Bug"), http or http_json)

    def payload(self, f: Finding) -> dict:
        return {
            "fields": {
                "project": {"key": self.project},
                "issuetype": {"name": self.issue_type},
                "summary": summary(f),
                "description": body_text(f),
                "priority": {"name": PRIORITY.get(f.severity, "Medium")},
                "labels": ["attestra", f"severity-{f.severity}"],
            }
        }

    def create(self, f: Finding) -> str:
        auth = base64.b64encode(f"{self.user}:{self.token}".encode()).decode()
        resp = self.http("POST", f"{self.base_url}/rest/api/2/issue", {"Authorization": f"Basic {auth}"}, self.payload(f))
        key = resp.get("key")
        if not key:
            raise TicketError("Jira did not return an issue key")
        return str(key)
