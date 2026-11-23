"""Thin AASI wrapper over ``ai_narratives.Provider`` — JSON out, redaction, retries.

Reuses the existing narratives provider construction (``provider_from_env`` /
``get_provider``, ``ATTESTRA_AI_NARRATIVES``, ``ATTESTRA_AI_TENANTS_OFF``). Does
not introduce a second AI framework.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import asdict, dataclass, field
from typing import Any

from attestra import ai_narratives, config

__all__ = [
    "AasiProvider",
    "AasiProviderDisabled",
    "AasiProviderError",
    "ProviderUsage",
    "build_provider",
]

_JSON_FENCE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)


class AasiProviderDisabled(Exception):
    """AI / AASI is off for this process or tenant; no network call is made."""


class AasiProviderError(Exception):
    """Provider transport, timeout, or structured-output validation failed."""


@dataclass
class ProviderUsage:
    """Accumulated call accounting for one ``AasiProvider`` instance."""

    calls: int = 0
    retries: int = 0
    tokens_in: int | None = None
    tokens_out: int | None = None
    provider: str = ""
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


UsageCallback = Callable[[ProviderUsage], None]


def _estimate_tokens(text: str) -> int:
    return max(0, (len(text) + 3) // 4) if text else 0


def redact_prompt(text: str) -> str:
    """Apply ``ai_narratives`` redaction patterns without the 300-char title cap."""
    out = str(text or "")
    for pattern, repl in ai_narratives._REDACTIONS:
        out = pattern.sub(repl, out)
    return out


def _required_keys(schema_hint: dict[str, Any] | list[str] | None) -> list[str]:
    if schema_hint is None:
        return []
    if isinstance(schema_hint, (list, tuple)):
        return [str(k) for k in schema_hint]
    if not isinstance(schema_hint, dict):
        return []
    req = schema_hint.get("required")
    if isinstance(req, (list, tuple)):
        return [str(k) for k in req]
    return []


def _parse_json_object(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        raise AasiProviderError("empty provider response")
    fence = _JSON_FENCE.search(text)
    if fence:
        text = fence.group(1).strip()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise AasiProviderError("provider response is not JSON") from None
        try:
            doc = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise AasiProviderError(f"provider JSON parse failed: {exc}") from None
    if not isinstance(doc, dict):
        raise AasiProviderError("provider JSON must be an object")
    return doc


def _assert_ai_allowed(tenant_id: int | None, *, env: dict[str, str] | None = None) -> None:
    if not getattr(config, "AASI_ENABLED", False):
        raise AasiProviderDisabled("AASI is disabled (ATTESTRA_AASI=off)")
    if not ai_narratives.is_enabled(env, tenant_id=tenant_id):
        raise AasiProviderDisabled(
            "AI provider disabled (ATTESTRA_AI_NARRATIVES off or tenant on ATTESTRA_AI_TENANTS_OFF)"
        )


def build_provider(
    *,
    tenant_id: int | None = None,
    env: dict[str, str] | None = None,
    http_post: ai_narratives.HttpPost | None = None,
    provider: ai_narratives.Provider | None = None,
    retry_limit: int | None = None,
    timeout_s: float = 60.0,
    on_usage: UsageCallback | None = None,
) -> AasiProvider:
    """Build an ``AasiProvider`` using narratives env rules; raise when AI is off."""
    _assert_ai_allowed(tenant_id, env=env)
    inner = provider
    if inner is None:
        if http_post is not None or env is not None:
            inner = ai_narratives.provider_from_env(env, http_post=http_post)
        else:
            inner = ai_narratives.get_provider(tenant_id=tenant_id)
    if inner is None:
        raise AasiProviderDisabled("AI provider not configured")
    kwargs: dict[str, Any] = {
        "timeout_s": timeout_s,
        "on_usage": on_usage,
        "tenant_id": tenant_id,
    }
    if retry_limit is not None:
        kwargs["retry_limit"] = retry_limit
    return AasiProvider(inner, **kwargs)


@dataclass
class AasiProvider:
    """Structured-JSON façade over a narratives ``Provider``."""

    _inner: ai_narratives.Provider
    retry_limit: int = field(default_factory=lambda: int(getattr(config, "AASI_RETRY_LIMIT", 2)))
    timeout_s: float = 60.0
    on_usage: UsageCallback | None = None
    tenant_id: int | None = None
    _usage: ProviderUsage = field(default_factory=ProviderUsage)

    def __post_init__(self) -> None:
        if self.retry_limit is None:
            self.retry_limit = int(getattr(config, "AASI_RETRY_LIMIT", 2))
        self.retry_limit = max(0, int(self.retry_limit))
        name = getattr(self._inner, "name", "") or ""
        self._usage.provider = name

    @property
    def name(self) -> str:
        return getattr(self._inner, "name", "") or "aasi"

    @property
    def usage(self) -> ProviderUsage:
        return self._usage

    def _emit_usage(self) -> None:
        if self.on_usage is not None:
            self.on_usage(self._usage)

    def _complete_once(self, system: str, prompt: str) -> str:
        if self.timeout_s and self.timeout_s > 0:
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(self._inner.complete, system, prompt)
                try:
                    return fut.result(timeout=self.timeout_s)
                except FuturesTimeout as exc:
                    raise AasiProviderError(f"AI provider timed out after {self.timeout_s}s") from exc
        return self._inner.complete(system, prompt)

    def complete_json(
        self,
        system: str,
        prompt: str,
        schema_hint: dict[str, Any] | list[str] | None = None,
        *,
        schema: dict[str, Any] | list[str] | None = None,
    ) -> dict[str, Any]:
        """Redact outbound text, call the inner provider, parse and validate JSON.

        Returns the parsed object. Updates ``usage`` and invokes ``on_usage`` when set.
        Raises ``AasiProviderDisabled`` without contacting the network when AI is off.
        ``schema`` is accepted as an alias of ``schema_hint`` for role callers.
        """
        _assert_ai_allowed(self.tenant_id)
        hint = schema_hint if schema_hint is not None else schema

        safe_system = redact_prompt(system)
        safe_prompt = redact_prompt(prompt)
        required = _required_keys(hint)
        if hint is not None:
            if required:
                tip = "\nRespond with a single JSON object. Required keys: " + ", ".join(required)
            else:
                tip = "\nRespond with a single JSON object matching the requested schema."
            safe_prompt = redact_prompt(safe_prompt + tip)

        attempts = self.retry_limit + 1
        last_err: Exception | None = None
        for attempt in range(attempts):
            if attempt:
                self._usage.retries += 1
            try:
                raw = self._complete_once(safe_system, safe_prompt)
                self._usage.calls += 1
                tin = _estimate_tokens(safe_system) + _estimate_tokens(safe_prompt)
                tout = _estimate_tokens(raw)
                self._usage.tokens_in = (self._usage.tokens_in or 0) + tin
                self._usage.tokens_out = (self._usage.tokens_out or 0) + tout
                doc = _parse_json_object(raw)
                missing = [k for k in required if k not in doc]
                if missing:
                    raise AasiProviderError(f"JSON missing required keys: {missing}")
                self._usage.last_error = ""
                self._emit_usage()
                return doc
            except AasiProviderDisabled:
                raise
            except Exception as exc:  # noqa: BLE001 — retry then surface
                last_err = exc
                self._usage.last_error = str(exc)[:300]
                if attempt + 1 >= attempts:
                    break

        self._emit_usage()
        if isinstance(last_err, AasiProviderError):
            raise last_err
        raise AasiProviderError(str(last_err) if last_err else "provider call failed") from last_err
