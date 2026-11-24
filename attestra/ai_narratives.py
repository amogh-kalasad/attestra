"""Optional AI-drafted narratives (Step 8.5). OFF by default.

    ATTESTRA_AI_NARRATIVES=off | on          (bootstrap when no per-tenant Mongo UI settings)
    ATTESTRA_AI_PROVIDER=ollama | openai | anthropic | xai | openrouter | openai-compatible
    ATTESTRA_AI_BASE_URL=…                  (optional; catalog defaults apply when blank)
    ATTESTRA_AI_MODEL=…
    ATTESTRA_AI_TENANTS_OFF=3,7              (per-tenant off switch; still honored with UI settings)

Prefer Settings → AI provider (admin/lead) for per-tenant Mongo config and pasted API keys
(Fernet ``api_key_enc``). Env remains bootstrap for local/CI. Compose api/worker share Mongo +
``ATTESTRA_CREDENTIAL_FERNET_KEY``, so UI saves apply without rewriting container env.

Only redacted finding metadata is sent: never evidence, descriptions, locations, hostnames,
URLs, IPs, emails or secrets. Every output is an ``AI draft`` until a tester approves it.
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.request  # noqa: F401 - tests patch ai.urllib.request; keep attribute
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from attestra.ai_providers import (
    AIProviderError,
    AnthropicProvider,
    HttpPost,
    OllamaProvider,
    OpenAICompatProvider,
    build_provider,
)

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

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> str: ...


# Output token / HTTP timeout budgets (combined drafts grow with finding count).
MAX_OUTPUT_TOKENS = 16384
MAX_HTTP_TIMEOUT_S = 600.0


def draft_generation_budget(finding_count: int, *, mode: str = "finding") -> tuple[int, float]:
    """Return ``(max_tokens, timeout_seconds)`` scaled by finding count and draft mode.

    Combined writeups need more output room and a longer HTTP read timeout; Select-all
    on a large engagement otherwise hits the default provider read timeout.
    """
    n = max(1, int(finding_count or 1))
    if mode == "combined":
        tokens = min(MAX_OUTPUT_TOKENS, 2048 + 450 * n)
        timeout = min(MAX_HTTP_TIMEOUT_S, 120.0 + 18.0 * n)
    elif mode == "executive_summary":
        tokens = 2048
        timeout = min(240.0, 90.0 + 1.5 * min(n, 50))
    else:
        tokens = 2048
        timeout = 120.0
    return int(tokens), float(timeout)


def _tenant_settings_row(tenant_id: int) -> dict[str, Any] | None:
    """Best-effort live Mongo read; ``None`` when unavailable or no document."""
    try:
        from attestra.ai_settings import service as ai_settings

        return ai_settings.get_raw(int(tenant_id))
    except Exception:
        return None


def _env_narratives_on(env: dict[str, str]) -> bool:
    return env.get("ATTESTRA_AI_NARRATIVES", "off").strip().lower() in ("on", "1", "true", "yes")


def is_enabled(env: dict[str, str] | None = None, tenant_id: int | None = None) -> bool:
    """True when AI may run for ``tenant_id``.

    Per-tenant Mongo UI settings win when a document exists. Otherwise the env
    bootstrap switch applies. ``ATTESTRA_AI_TENANTS_OFF`` always kills a tenant.
    """
    env = os.environ if env is None else env
    off = {t.strip() for t in env.get("ATTESTRA_AI_TENANTS_OFF", "").split(",") if t.strip()}
    if tenant_id is not None and str(tenant_id) in off:
        return False
    if tenant_id is not None:
        row = _tenant_settings_row(int(tenant_id))
        if row is not None:
            return bool(row.get("enabled"))
    return _env_narratives_on(env)


def _api_key_from_env(env: dict[str, str]) -> str:
    from attestra.secret_store import get_secret

    return get_secret("ai_api_key", env.get("ATTESTRA_AI_API_KEY", ""))


def provider_from_env(env: dict[str, str] | None = None, *, http_post: HttpPost | None = None) -> Provider | None:
    """Build from env bootstrap. Returns ``None`` when env narratives are off."""
    env = os.environ if env is None else env
    if not _env_narratives_on(env):
        return None
    kind = env.get("ATTESTRA_AI_PROVIDER", "ollama").strip().lower() or "ollama"
    model = env.get("ATTESTRA_AI_MODEL", "")
    base = env.get("ATTESTRA_AI_BASE_URL", "")
    try:
        return build_provider(
            provider=kind,
            model=model,
            base_url=base,
            api_key=_api_key_from_env(env) if kind != "ollama" else "",
            http_post=http_post,
        )
    except AIProviderError as exc:
        raise AINarrativesError(str(exc)) from None


def provider_from_tenant(
    tenant_id: int, *, env: dict[str, str] | None = None, http_post: HttpPost | None = None
) -> Provider | None:
    """Live resolve: Mongo UI settings for the tenant, else env bootstrap."""
    env = os.environ if env is None else env
    if not is_enabled(env, tenant_id=tenant_id):
        return None
    row = _tenant_settings_row(int(tenant_id))
    if row is not None:
        try:
            from attestra.ai_settings import service as ai_settings

            key = ai_settings.decrypt_api_key(row) if row.get("api_key_enc") else ""
            return build_provider(
                provider=str(row.get("provider") or "ollama"),
                model=str(row.get("model") or ""),
                base_url=str(row.get("base_url") or ""),
                api_key=key,
                http_post=http_post,
            )
        except AIProviderError as exc:
            raise AINarrativesError(str(exc)) from None
    return provider_from_env(env, http_post=http_post)


# ---------------------------------------------------------------- drafts
@dataclass
class Draft:
    id: str
    kind: str  # executive_summary | finding | finding_combined
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
        return {"ai_summary": None, "ai_narratives": {}, "ai_combined": None}
    store = DraftStore()
    summary = approved_draft(store, engagement_id, "executive_summary")
    narratives: dict[int, Draft] = {}
    for d in store.list(engagement_id):
        if d.kind == "finding" and d.finding_id is not None:
            ok = approved_draft(store, engagement_id, "finding", d.finding_id)
            if ok:
                narratives[d.finding_id] = ok
    combined = approved_draft(store, engagement_id, "finding_combined")
    return {"ai_summary": summary, "ai_narratives": narratives, "ai_combined": combined}


_provider_override: Provider | None = None


def set_provider(provider: Provider | None) -> None:
    """Override the provider (tests). ``None`` goes back to reading the environment."""
    global _provider_override
    _provider_override = provider


def get_provider(tenant_id: int | None = None) -> Provider | None:
    """Resolve provider for a tenant. Prefers live Mongo UI settings; no process-wide settings cache."""
    if _provider_override is not None:
        return _provider_override if is_enabled(tenant_id=tenant_id) else None
    if tenant_id is not None:
        return provider_from_tenant(int(tenant_id))
    if not is_enabled():
        return None
    return provider_from_env()


def approved_text(store: DraftStore, engagement_id: int, kind: str, finding_id: int | None = None) -> str | None:
    """Report-facing accessor: returns text only for tester-approved drafts, else ``None``
    (the report then falls back to its template narrative)."""
    for d in reversed(store.list(engagement_id)):
        if d.kind == kind and d.finding_id == finding_id and d.status == "approved" and d.approved_by:
            return d.text
    return None


# ---------------------------------------------------------------- generation
SYSTEM_PROMPT = (
    "You are drafting text for a professional VAPT / penetration-test report. "
    "Use only the metadata given. Do not invent hosts, evidence, CVEs, or numbers. "
    "Be concise, factual, and suitable for a client deliverable."
)

# VAPT finding-card writeup headings (must match prompt + report rendering).
FINDING_WRITEUP_SECTIONS = ("Description", "Impact", "Likelihood", "Recommendation")
_SECTION_RE = re.compile(
    r"^##\s+(Description|Impact|Likelihood|Recommendation)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _new_id() -> str:
    return os.urandom(8).hex()


def _finding_writeup_prompt(meta: dict[str, Any]) -> str:
    headings = "\n".join(f"## {h}" for h in FINDING_WRITEUP_SECTIONS)
    return (
        "Write a VAPT finding writeup for this finding using EXACTLY these Markdown headings "
        f"in this order (one short paragraph under each):\n{headings}\n\n"
        "Do not add other headings. Do not wrap the whole answer in a code fence.\n"
        f"Finding metadata:\n{json.dumps(meta, sort_keys=True)}"
    )


def normalize_finding_writeup(text: str) -> str:
    """Ensure Description / Impact / Likelihood / Recommendation headings exist for reports."""
    raw = (text or "").strip()
    if not raw:
        return raw
    found = {m.group(1).title(): True for m in _SECTION_RE.finditer(raw)}
    if all(h in found for h in FINDING_WRITEUP_SECTIONS):
        # Canonicalize heading casing.
        return _SECTION_RE.sub(lambda m: f"## {m.group(1).title()}", raw).strip()
    # Model ignored structure — wrap as Description so report still has a labeled block.
    return f"## Description\n{raw}\n\n## Impact\nNot stated by the model.\n\n## Likelihood\nNot stated by the model.\n\n## Recommendation\nNot stated by the model."


def writeup_sections(text: str) -> list[tuple[str, str]]:
    """Split a structured writeup into ``(heading, body)`` pairs for report HTML."""
    raw = (text or "").strip()
    if not raw:
        return []
    matches = list(_SECTION_RE.finditer(raw))
    if not matches:
        return [("Narrative", raw)]
    out: list[tuple[str, str]] = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        body = raw[start:end].strip()
        out.append((m.group(1).title(), body))
    return out


_COMBINED_FINDING_RE = re.compile(r"^#\s+(F-\S+.*?)\s*$", re.MULTILINE)


def combined_writeup_blocks(text: str) -> list[tuple[str, list[tuple[str, str]]]]:
    """Split a combined finding writeup into ``(finding_heading, sections)`` for reports."""
    raw = (text or "").strip()
    if not raw:
        return []
    matches = list(_COMBINED_FINDING_RE.finditer(raw))
    if not matches:
        return [("", writeup_sections(raw))]
    out: list[tuple[str, list[tuple[str, str]]]] = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        body = raw[start:end].strip()
        out.append((m.group(1).strip(), writeup_sections(body)))
    return out


def draft_finding_narrative(
    provider: Provider | None, store: DraftStore, engagement_id: int, finding: Any, *, tenant_id: int | None = None
) -> Draft | None:
    if provider is None or (tenant_id is not None and not is_enabled(tenant_id=tenant_id)):
        return None
    meta = finding_metadata(finding)
    tokens, wait = draft_generation_budget(1, mode="finding")
    text = normalize_finding_writeup(
        provider.complete(SYSTEM_PROMPT, _finding_writeup_prompt(meta), max_tokens=tokens, timeout=wait)
    )
    return store.add(
        Draft(_new_id(), "finding", engagement_id, getattr(finding, "id", None), text, provider=provider.name)
    )


def draft_finding_narratives(
    provider: Provider | None,
    store: DraftStore,
    engagement_id: int,
    findings: Iterable[Any],
    *,
    tenant_id: int | None = None,
) -> list[Draft]:
    """Create one structured finding writeup draft per finding (per-finding batch mode)."""
    out: list[Draft] = []
    for f in findings:
        d = draft_finding_narrative(provider, store, engagement_id, f, tenant_id=tenant_id)
        if d is not None:
            out.append(d)
    return out


def draft_combined_finding_writeup(
    provider: Provider | None,
    store: DraftStore,
    engagement_id: int,
    findings: Iterable[Any],
    *,
    tenant_id: int | None = None,
) -> Draft | None:
    """One combined VAPT writeup covering every selected finding (shared approval)."""
    if provider is None or (tenant_id is not None and not is_enabled(tenant_id=tenant_id)):
        return None
    items = list(findings)
    if not items:
        return None
    payload = [
        {"id": getattr(f, "id", None), **finding_metadata(f)}
        for f in items
    ]
    ids = ", ".join(f"F-{getattr(f, 'id', '?')}" for f in items)
    headings = "\n".join(f"## {h}" for h in FINDING_WRITEUP_SECTIONS)
    prompt = (
        f"Write a combined VAPT findings writeup for these {len(items)} findings ({ids}). "
        "For EACH finding, emit a level-1 heading like `# F-<id> · <short title>` then EXACTLY these "
        f"level-2 headings in order:\n{headings}\n\n"
        "Keep each section to one short paragraph. Do not invent hosts or evidence.\n"
        f"Findings metadata:\n{json.dumps(payload, sort_keys=True)}"
    )
    tokens, wait = draft_generation_budget(len(items), mode="combined")
    text = provider.complete(SYSTEM_PROMPT, prompt, max_tokens=tokens, timeout=wait).strip()
    if text and not text.startswith("#"):
        text = f"# Combined finding writeup ({ids})\n\n{text}"
    return store.add(
        Draft(_new_id(), "finding_combined", engagement_id, None, text, provider=provider.name)
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
    prompt = (
        "Write a short executive summary for this assessment using these Markdown headings:\n"
        "## Overview\n## Key risks\n## Recommended priorities\n\n"
        "One short paragraph under each. Do not invent hosts or numbers beyond the counts given.\n"
        f"Assessment metadata:\n{json.dumps(payload, sort_keys=True)}"
    )
    tokens, wait = draft_generation_budget(len(metas), mode="executive_summary")
    text = provider.complete(SYSTEM_PROMPT, prompt, max_tokens=tokens, timeout=wait)
    return store.add(Draft(_new_id(), "executive_summary", engagement_id, None, text, provider=provider.name))
