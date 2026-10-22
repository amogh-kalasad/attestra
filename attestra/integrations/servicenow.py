"""ServiceNow incident creation (Table API).

Off by default. Set ``ATTESTRA_TICKETS_BACKEND=servicenow`` and:

- ``ATTESTRA_SERVICENOW_INSTANCE`` — instance host (``example.service-now.com``)
  or full HTTPS base URL
- ``ATTESTRA_SERVICENOW_USER`` — basic-auth user
- ``ATTESTRA_SERVICENOW_TOKEN`` — password or API token (prefer secret store)

Optional: ``ATTESTRA_SERVICENOW_TABLE`` (default ``incident``).

Secrets are never logged; only the returned ``sys_id`` / number is stored in
``ticket_ref`` as ``servicenow:<number-or-sys_id>``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from attestra.integrations.tickets import HttpCall, TicketError, body_text, http_json, summary
from attestra.models import Finding

PRIORITY = {"critical": "1", "high": "2", "medium": "3", "low": "4", "info": "5"}


@dataclass
class ServiceNowClient:
    base_url: str
    user: str
    token: str
    table: str = "incident"
    http: HttpCall = field(default=http_json)
    name: str = "servicenow"

    @classmethod
    def from_env(cls, env: dict[str, str], *, http: HttpCall | None = None) -> ServiceNowClient:
        from attestra.secret_store import get_secret

        instance = env.get("ATTESTRA_SERVICENOW_INSTANCE", "").strip().rstrip("/")
        user = env.get("ATTESTRA_SERVICENOW_USER", "").strip()
        token = env.get("ATTESTRA_SERVICENOW_TOKEN") or get_secret("ATTESTRA_SERVICENOW_TOKEN")
        if not (instance and user and token):
            raise TicketError(
                "ServiceNow not configured; set ATTESTRA_SERVICENOW_INSTANCE, "
                "ATTESTRA_SERVICENOW_USER and ATTESTRA_SERVICENOW_TOKEN"
            )
        if instance.startswith("https://"):
            base = instance
        else:
            base = f"https://{instance}"
        table = env.get("ATTESTRA_SERVICENOW_TABLE", "incident").strip() or "incident"
        return cls(base, user, token, table, http or http_json)

    def payload(self, f: Finding) -> dict:
        return {
            "short_description": summary(f),
            "description": body_text(f),
            "urgency": PRIORITY.get(f.severity, "3"),
            "impact": PRIORITY.get(f.severity, "3"),
            "category": "software",
        }

    def create(self, f: Finding) -> str:
        auth = base64.b64encode(f"{self.user}:{self.token}".encode()).decode()
        resp = self.http(
            "POST",
            f"{self.base_url}/api/now/table/{self.table}",
            {"Authorization": f"Basic {auth}", "Accept": "application/json"},
            self.payload(f),
        )
        result = resp.get("result") or resp
        key = result.get("number") or result.get("sys_id")
        if not key:
            raise TicketError("ServiceNow did not return an incident number or sys_id")
        return str(key)
