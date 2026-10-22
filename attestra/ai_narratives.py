"""Optional AI-drafted narratives (Step 8.5). OFF by default.

    ATTESTRA_AI_NARRATIVES=off | on          (default off: no provider is built, no network calls)
    ATTESTRA_AI_PROVIDER=ollama | openai     (openai = any OpenAI-compatible /v1/chat/completions)
    ATTESTRA_AI_BASE_URL=http://localhost:11434   (ollama default) or https://host/v1
    ATTESTRA_AI_MODEL=llama3.1
    ATTESTRA_AI_TENANTS_OFF=3,7              (per-tenant off switch)

The API key for the openai provider is read from the secret store (key ``ai_api_key``),
falling back to ``ATTESTRA_AI_API_KEY``. Only redacted finding metadata is sent: never
evidence, descriptions, locations, hostnames, URLs, IPs, emails or secrets.

Every output is stored as an ``AI draft``. It cannot reach a report until a tester
approves it (:func:`approved_text` is the only report-facing accessor).
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

AI_DRAFT_LABEL = "AI draft"
APPROVER_ROLES = frozenset({"tester", "lead", "admin"})

# Only these Finding attributes may leave the process (after redaction).
_ALLOWED_FIELDS = ("severity", "cwe", "cves", "owasp_top10", "asvs_ref", "kev", "epss", "cvss_score", "status")

_REDACTIONS = [
    (re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+"), "[url]"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b"), "[email]"),
    (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?\b"), "[ip]"),
    (re.compile(r"\b[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}\b"), "[ip]"),
    (re.compile(r"(?i)\b(bearer|token|password|passwd|secret|api[_-]?key|authorization)\b\s*[:=]?\s*\S+"), "[secret]"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "[secret]"),
    (re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]*"), "[secret]"),
    (re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"), "[secret]"),
    (re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I), "[host]"),
    (re.compile(r"(?:[A-Za-z]:)?[\\/][\w.\-\\/]+"), "[path]"),
]


class AINarrativesError(Exception):
    pass


def redact(text: str) -> str:
    out = str(text or "")
    for pattern, repl in _REDACTIONS:
        out = pattern.sub(repl, out)
    return out[:300]


def finding_metadata(finding: Any) -> dict[str, Any]:
    """Redacted, evidence-free view of a finding. Title is redacted; nothing else free-text is sent."""
    meta: dict[str, Any] = {"title": redact(getattr(finding, "title", ""))}
    for name in _ALLOWED_FIELDS:
        value = getattr(finding, name, None)
        if value in (None, "", []):
            continue
        if name == "cves":
            value = [c for c in value if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(c))]
        meta[name] = value
    return meta


# ---------------------------------------------------------------- providers
class Provider(Protocol):
    name: str

    def complete(self, system: str, prompt: str) -> str: ...


HttpPost = Callable[[str, dict[str, str], dict[str, Any]], dict[str, Any]]


def _http_post(url: str, headers: dict[str, str], body: dict[str, Any], *, timeout: float = 60.0) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked in __init__
        return json.loads(resp.read(2_000_000).decode("utf-8"))


def _check_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        raise AINarrativesError("ATTESTRA_AI_BASE_URL must be an http(s) URL")
    return url.rstrip("/")


class OllamaProvider:
    name = "ollama"

    def __init__(
        self, base_url: str = "http://localhost:11434", model: str = "llama3.1", *, http_post: HttpPost | None = None
    ):
        self.url = _check_url(base_url) + "/api/chat"
        self.model = model
        self._post = http_post or _http_post

    def complete(self, system: str, prompt: str) -> str:
        body = {
            "model": self.model,
            "stream": False,
            "options": {"temperature": 0.2},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        doc = self._post(self.url, {"Content-Type": "application/json"}, body)
        return str(((doc or {}).get("message") or {}).get("content", "")).strip()


class OpenAICompatProvider:
    name = "openai"

    def __init__(self, base_url: str, model: str, api_key: str, *, http_post: HttpPost | None = None):
        if not api_key:
            raise AINarrativesError("AI API key missing (secret 'ai_api_key' or ATTESTRA_AI_API_KEY)")
        self.url = _check_url(base_url) + "/chat/completions"
        self.model = model
        self._api_key = api_key
        self._headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        self._post = http_post or _http_post

    def __repr__(self) -> str:  # never show the key
        return f"OpenAICompatProvider(url={self.url!r}, model={self.model!r})"

    def _scrub(self, text: str) -> str:
        key = self._api_key
        out = str(text or "")
        if key:
            out = out.replace(key, "[redacted]")
            out = out.replace(f"Bearer {key}", "Bearer [redacted]")
        return out

    def complete(self, system: str, prompt: str) -> str:
        body = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        try:
            doc = self._post(self.url, dict(self._headers), body)
        except Exception as exc:  # noqa: BLE001 - scrub key from any transport error text
            raise AINarrativesError(self._scrub(str(exc)) or "AI provider request failed") from None
        choices = (doc or {}).get("choices") or [{}]
        return str((choices[0].get("message") or {}).get("content", "")).strip()


def is_enabled(env: dict[str, str] | None = None, tenant_id: int | None = None) -> bool:
    env = os.environ if env is None else env
    if env.get("ATTESTRA_AI_NARRATIVES", "off").strip().lower() not in ("on", "1", "true", "yes"):
        return False
    off = {t.strip() for t in env.get("ATTESTRA_AI_TENANTS_OFF", "").split(",") if t.strip()}
    return tenant_id is None or str(tenant_id) not in off


def provider_from_env(env: dict[str, str] | None = None, *, http_post: HttpPost | None = None) -> Provider | None:
    """Returns ``None`` when the feature is off (nothing is constructed, nothing is contacted)."""
    env = os.environ if env is None else env
    if not is_enabled(env):
        return None
    kind = env.get("ATTESTRA_AI_PROVIDER", "ollama").strip().lower()
    model = env.get("ATTESTRA_AI_MODEL", "llama3.1")
    if kind == "ollama":
        return OllamaProvider(env.get("ATTESTRA_AI_BASE_URL", "http://localhost:11434"), model, http_post=http_post)
    if kind in ("openai", "openai-compatible"):
        from attestra.secret_store import get_secret

        key = get_secret("ai_api_key", env.get("ATTESTRA_AI_API_KEY", ""))
        return OpenAICompatProvider(env.get("ATTESTRA_AI_BASE_URL", ""), model, key, http_post=http_post)
    raise AINarrativesError(f"unknown ATTESTRA_AI_PROVIDER {kind!r}")


# ---------------------------------------------------------------- drafts
@dataclass
class Draft:
    id: str
    kind: str  # executive_summary | finding
    engagement_id: int
    finding_id: int | None
    text: str
    label: str = AI_DRAFT_LABEL
    status: str = "draft"  # draft | approved | rejected
    provider: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    approved_by: str = ""
    approved_at: str = ""


class DraftStore:
    """JSON file per engagement under ``<data>/ai_drafts`` (no schema migration needed)."""

    def __init__(self, root: Path | None = None):
        if root is None:
            from attestra.config import DATA_DIR

            root = DATA_DIR / "ai_drafts"
        self.root = Path(root)
        self._lock = threading.Lock()

    def _file(self, engagement_id: int) -> Path:
        return self.root / f"engagement_{int(engagement_id)}.json"

    def list(self, engagement_id: int) -> list[Draft]:
        f = self._file(engagement_id)
        if not f.exists():
            return []
        return [Draft(**d) for d in json.loads(f.read_text(encoding="utf-8"))]

    def _save(self, engagement_id: int, drafts: list[Draft]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._file(engagement_id).write_text(json.dumps([asdict(d) for d in drafts], indent=2), encoding="utf-8")

    def add(self, draft: Draft) -> Draft:
        with self._lock:
            drafts = self.list(draft.engagement_id)
            drafts.append(draft)
            self._save(draft.engagement_id, drafts)
        return draft

    def _update(self, engagement_id: int, draft_id: str, **changes: Any) -> Draft:
        with self._lock:
            drafts = self.list(engagement_id)
            for d in drafts:
                if d.id == draft_id:
                    for k, v in changes.items():
                        setattr(d, k, v)
                    self._save(engagement_id, drafts)
                    return d
        raise AINarrativesError(f"draft {draft_id} not found")

    def approve(
        self, engagement_id: int, draft_id: str, *, user: str, role: str, edited_text: str | None = None
    ) -> Draft:
        if role not in APPROVER_ROLES:
            raise PermissionError("only a tester (or lead/admin) can approve AI drafts")
        changes: dict[str, Any] = {
            "status": "approved",
            "approved_by": user,
            "approved_at": datetime.now(UTC).isoformat(),
        }
        if edited_text is not None:
            changes["text"] = edited_text
        return self._update(engagement_id, draft_id, **changes)

    def reject(self, engagement_id: int, draft_id: str, *, user: str) -> Draft:
        return self._update(engagement_id, draft_id, status="rejected", approved_by=user)


def approved_draft(store: DraftStore, engagement_id: int, kind: str, finding_id: int | None = None) -> Draft | None:
    for d in reversed(store.list(engagement_id)):
        if d.kind == kind and d.finding_id == finding_id and d.status == "approved" and d.approved_by:
            return d
    return None


def approved_for_report(engagement_id: int, tenant_id: int | None = None) -> dict[str, Any]:
    """Context for report templates. Empty when the feature is off (reports unchanged)."""
    if not is_enabled(tenant_id=tenant_id):
        return {"ai_summary": None, "ai_narratives": {}}
    store = DraftStore()
    summary = approved_draft(store, engagement_id, "executive_summary")
    narratives: dict[int, Draft] = {}
    for d in store.list(engagement_id):
        if d.kind == "finding" and d.finding_id is not None:
            ok = approved_draft(store, engagement_id, "finding", d.finding_id)
            if ok:
                narratives[d.finding_id] = ok
    return {"ai_summary": summary, "ai_narratives": narratives}


_provider_override: Provider | None = None


def set_provider(provider: Provider | None) -> None:
    """Override the provider (tests). ``None`` goes back to reading the environment."""
    global _provider_override
    _provider_override = provider


def get_provider(tenant_id: int | None = None) -> Provider | None:
    if not is_enabled(tenant_id=tenant_id):
        return None
    return _provider_override or provider_from_env()


def approved_text(store: DraftStore, engagement_id: int, kind: str, finding_id: int | None = None) -> str | None:
    """Report-facing accessor: returns text only for tester-approved drafts, else ``None``
    (the report then falls back to its template narrative)."""
    for d in reversed(store.list(engagement_id)):
        if d.kind == kind and d.finding_id == finding_id and d.status == "approved" and d.approved_by:
            return d.text
    return None


# ---------------------------------------------------------------- generation
SYSTEM_PROMPT = (
    "You are drafting text for a security assessment report. Use only the metadata given. "
    "Do not invent hosts, evidence or numbers. Be concise and factual."
)


def _new_id() -> str:
    return os.urandom(8).hex()


def draft_finding_narrative(
    provider: Provider | None, store: DraftStore, engagement_id: int, finding: Any, *, tenant_id: int | None = None
) -> Draft | None:
    if provider is None or (tenant_id is not None and not is_enabled(tenant_id=tenant_id)):
        return None
    meta = finding_metadata(finding)
    prompt = "Write a 3-4 sentence narrative (impact and fix direction) for this finding:\n" + json.dumps(
        meta, sort_keys=True
    )
    text = provider.complete(SYSTEM_PROMPT, prompt)
    return store.add(
        Draft(_new_id(), "finding", engagement_id, getattr(finding, "id", None), text, provider=provider.name)
    )


def draft_executive_summary(
    provider: Provider | None,
    store: DraftStore,
    engagement_id: int,
    findings: Iterable[Any],
    *,
    tenant_id: int | None = None,
) -> Draft | None:
    if provider is None or (tenant_id is not None and not is_enabled(tenant_id=tenant_id)):
        return None
    metas = [finding_metadata(f) for f in findings]
    counts: dict[str, int] = {}
    for m in metas:
        counts[str(m.get("severity", "info"))] = counts.get(str(m.get("severity", "info")), 0) + 1
    payload = {"severity_counts": counts, "kev_count": sum(1 for m in metas if m.get("kev")), "top": metas[:15]}
    prompt = "Write a short executive summary (one paragraph) for this assessment:\n" + json.dumps(
        payload, sort_keys=True
    )
    text = provider.complete(SYSTEM_PROMPT, prompt)
    return store.add(Draft(_new_id(), "executive_summary", engagement_id, None, text, provider=provider.name))
