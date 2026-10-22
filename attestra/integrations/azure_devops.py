"""Azure DevOps work item creation (REST).

Off by default. Set ``ATTESTRA_TICKETS_BACKEND=azure_devops`` and:

- ``ATTESTRA_AZDO_ORG`` — organization name or full ``https://dev.azure.com/<org>`` URL
- ``ATTESTRA_AZDO_PROJECT`` — project name
- ``ATTESTRA_AZDO_PAT`` — personal access token (prefer secret store)

Optional: ``ATTESTRA_AZDO_WORK_ITEM_TYPE`` (default ``Issue``),
``ATTESTRA_AZDO_API_URL`` (default ``https://dev.azure.com``).

Secrets are never logged; only the work item id is stored in ``ticket_ref`` as
``azure_devops:<project>#<id>``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from attestra.integrations.tickets import HttpCall, TicketError, body_text, http_json, summary
from attestra.models import Finding

SEVERITY = {"critical": "1 - Critical", "high": "2 - High", "medium": "3 - Medium", "low": "4 - Low", "info": "4 - Low"}


@dataclass
class AzureDevOpsClient:
    org: str
    project: str
    pat: str
    work_item_type: str = "Issue"
    api_url: str = "https://dev.azure.com"
    http: HttpCall = field(default=http_json)
    name: str = "azure_devops"

    @classmethod
    def from_env(cls, env: dict[str, str], *, http: HttpCall | None = None) -> AzureDevOpsClient:
        from attestra.secret_store import get_secret

        org = env.get("ATTESTRA_AZDO_ORG", "").strip().rstrip("/")
        project = env.get("ATTESTRA_AZDO_PROJECT", "").strip()
        pat = env.get("ATTESTRA_AZDO_PAT") or get_secret("ATTESTRA_AZDO_PAT")
        if not (org and project and pat):
            raise TicketError(
                "Azure DevOps not configured; set ATTESTRA_AZDO_ORG, "
                "ATTESTRA_AZDO_PROJECT and ATTESTRA_AZDO_PAT"
            )
        api = env.get("ATTESTRA_AZDO_API_URL", "https://dev.azure.com").rstrip("/")
        if org.startswith("https://"):
            # Full org URL: https://dev.azure.com/myorg
            parts = org.rstrip("/").rsplit("/", 1)
            api, org = parts[0], parts[1] if len(parts) == 2 else org
        wit = env.get("ATTESTRA_AZDO_WORK_ITEM_TYPE", "Issue").strip() or "Issue"
        return cls(org, project, pat, wit, api, http or http_json)

    def payload(self, f: Finding) -> list[dict]:
        return [
            {"op": "add", "path": "/fields/System.Title", "value": summary(f)},
            {"op": "add", "path": "/fields/System.Description", "value": body_text(f)},
            {
                "op": "add",
                "path": "/fields/Microsoft.VSTS.Common.Severity",
                "value": SEVERITY.get(f.severity, "3 - Medium"),
            },
            {"op": "add", "path": "/fields/System.Tags", "value": f"attestra; severity:{f.severity}"},
        ]

    def create(self, f: Finding) -> str:
        auth = base64.b64encode(f":{self.pat}".encode()).decode()
        # Azure DevOps expects application/json-patch+json for work item create.
        resp = self.http(
            "POST",
            f"{self.api_url}/{self.org}/{self.project}/_apis/wit/workitems/"
            f"${self.work_item_type}?api-version=7.0",
            {
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json-patch+json",
                "Accept": "application/json",
            },
            self.payload(f),
        )
        wid = resp.get("id")
        if not wid:
            raise TicketError("Azure DevOps did not return a work item id")
        return f"{self.project}#{wid}"
