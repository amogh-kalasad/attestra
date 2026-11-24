"""Multi-provider LLM catalog and HTTP adapters for AI narratives / AASI.

Known providers ship default base URLs and endpoint/auth rules. Construction stays
behind :func:`build_provider` so AASI can keep using ``Provider.complete``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


class AIProviderError(Exception):
    """Raised for unknown providers, bad URLs, or missing keys."""


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


HttpPost = Callable[..., dict[str, Any]]

ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_HTTP_TIMEOUT_S = 120.0


def _http_post(
    url: str, headers: dict[str, str], body: dict[str, Any], *, timeout: float = DEFAULT_HTTP_TIMEOUT_S
) -> dict[str, Any]:
    """POST JSON; on HTTP errors include a short response body so callers can surface the real reason."""
    wait = float(timeout) if timeout is not None else DEFAULT_HTTP_TIMEOUT_S
    payload = json.dumps(body).encode()
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=wait) as resp:  # noqa: S310 - scheme checked in __init__
            return json.loads(resp.read(2_000_000).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read(4_000).decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001 - best-effort body for the raised message
            raw = ""
        detail = raw.replace("\n", " ")[:500] if raw else (exc.reason or "Bad Request")
        raise AIProviderError(f"HTTP Error {exc.code}: {detail}") from None
    except TimeoutError:
        raise AIProviderError(
            f"AI provider timed out after {wait:.0f}s (try fewer findings, or use one draft per finding)"
        ) from None
    except urllib.error.URLError as exc:
        reason = exc.reason
        msg = str(reason) if reason is not None else str(exc)
        if isinstance(reason, TimeoutError) or "timed out" in msg.lower():
            raise AIProviderError(
                f"AI provider timed out after {wait:.0f}s (try fewer findings, or use one draft per finding)"
            ) from None
        raise AIProviderError(f"AI provider network error: {msg}") from None


def _call_http_post(
    post: HttpPost,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    """Call a transport with timeout when supported (injected test posts may omit it)."""
    try:
        return post(url, headers, body, timeout=timeout)
    except TypeError:
        return post(url, headers, body)


def _check_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        raise AIProviderError("ATTESTRA_AI_BASE_URL must be an http(s) URL")
    return url.rstrip("/")


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    label: str
    default_base_url: str
    default_model: str
    needs_api_key: bool
    wire: str  # "ollama" | "openai_compat" | "anthropic"


PROVIDERS: dict[str, ProviderSpec] = {
    "ollama": ProviderSpec(
        id="ollama",
        label="Ollama (local)",
        default_base_url="http://localhost:11434",
        default_model="llama3.1",
        needs_api_key=False,
        wire="ollama",
    ),
    "openai": ProviderSpec(
        id="openai",
        label="OpenAI",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        needs_api_key=True,
        wire="openai_compat",
    ),
    "anthropic": ProviderSpec(
        id="anthropic",
        label="Anthropic (Claude)",
        default_base_url="https://api.anthropic.com",
        default_model="claude-sonnet-4-5",
        needs_api_key=True,
        wire="anthropic",
    ),
    "xai": ProviderSpec(
        id="xai",
        label="xAI (Grok)",
        default_base_url="https://api.x.ai/v1",
        default_model="grok-2-latest",
        needs_api_key=True,
        wire="openai_compat",
    ),
    "openrouter": ProviderSpec(
        id="openrouter",
        label="OpenRouter",
        default_base_url="https://openrouter.ai/api/v1",
        default_model="anthropic/claude-sonnet-4",
        needs_api_key=True,
        wire="openai_compat",
    ),
    "openai-compatible": ProviderSpec(
        id="openai-compatible",
        label="Custom OpenAI-compatible",
        default_base_url="",
        default_model="gpt-4o-mini",
        needs_api_key=True,
        wire="openai_compat",
    ),
}


def catalog_public() -> list[dict[str, Any]]:
    """UI/API catalog rows (no secrets)."""
    return [
        {
            "id": p.id,
            "label": p.label,
            "default_base_url": p.default_base_url,
            "default_model": p.default_model,
            "needs_api_key": p.needs_api_key,
        }
        for p in PROVIDERS.values()
    ]


def resolve_spec(provider_id: str) -> ProviderSpec:
    kind = (provider_id or "").strip().lower()
    if kind not in PROVIDERS:
        raise AIProviderError(f"unknown ATTESTRA_AI_PROVIDER {provider_id!r}")
    return PROVIDERS[kind]


def effective_base_url(spec: ProviderSpec, base_url: str | None) -> str:
    url = (base_url or "").strip()
    if url:
        return url
    if spec.default_base_url:
        return spec.default_base_url
    raise AIProviderError("ATTESTRA_AI_BASE_URL is required for this provider")


class OllamaProvider:
    name = "ollama"

    def __init__(
        self, base_url: str = "http://localhost:11434", model: str = "llama3.1", *, http_post: HttpPost | None = None
    ):
        self.url = _check_url(base_url) + "/api/chat"
        self.model = model
        self._post = http_post or _http_post

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> str:
        options: dict[str, Any] = {"temperature": 0.2}
        if max_tokens is not None:
            options["num_predict"] = int(max_tokens)
        body = {
            "model": self.model,
            "stream": False,
            "options": options,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        wait = float(timeout) if timeout is not None else DEFAULT_HTTP_TIMEOUT_S
        doc = _call_http_post(self._post, self.url, {"Content-Type": "application/json"}, body, timeout=wait)
        return str(((doc or {}).get("message") or {}).get("content", "")).strip()


class OpenAICompatProvider:
    """OpenAI-wire chat completions (OpenAI, xAI, OpenRouter, custom)."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        *,
        name: str = "openai",
        http_post: HttpPost | None = None,
    ):
        if not api_key:
            raise AIProviderError("AI API key missing (paste in Settings → AI provider, or set ATTESTRA_AI_API_KEY)")
        self.name = name
        self.url = _check_url(base_url) + "/chat/completions"
        self.model = model
        self._api_key = api_key
        self._headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        self._post = http_post or _http_post

    def __repr__(self) -> str:
        return f"OpenAICompatProvider(name={self.name!r}, url={self.url!r}, model={self.model!r})"

    def _scrub(self, text: str) -> str:
        key = self._api_key
        out = str(text or "")
        if key:
            out = out.replace(key, "[redacted]")
            out = out.replace(f"Bearer {key}", "Bearer [redacted]")
        return out

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        if max_tokens is not None:
            body["max_tokens"] = int(max_tokens)
        wait = float(timeout) if timeout is not None else DEFAULT_HTTP_TIMEOUT_S
        try:
            doc = _call_http_post(self._post, self.url, dict(self._headers), body, timeout=wait)
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(self._scrub(str(exc)) or "AI provider request failed") from None
        choices = (doc or {}).get("choices") or [{}]
        return str((choices[0].get("message") or {}).get("content", "")).strip()


def _anthropic_messages_url(base_url: str) -> str:
    """Build Messages API URL; tolerate bases that already end with ``/v1``."""
    root = _check_url(base_url)
    if root.endswith("/v1"):
        return root + "/messages"
    return root + "/v1/messages"


class AnthropicProvider:
    """Native Anthropic Messages API (``/v1/messages``)."""

    name = "anthropic"

    def __init__(self, base_url: str, model: str, api_key: str, *, http_post: HttpPost | None = None):
        if not api_key:
            raise AIProviderError("AI API key missing (paste in Settings → AI provider, or set ATTESTRA_AI_API_KEY)")
        self.url = _anthropic_messages_url(base_url)
        self.model = model
        self._api_key = api_key
        self._headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        self._post = http_post or _http_post

    def __repr__(self) -> str:
        return f"AnthropicProvider(url={self.url!r}, model={self.model!r})"

    def _scrub(self, text: str) -> str:
        key = self._api_key
        out = str(text or "")
        if key:
            out = out.replace(key, "[redacted]")
            out = out.replace(f"x-api-key: {key}", "x-api-key: [redacted]")
        return out

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> str:
        # Omit temperature: newer Claude models (e.g. claude-sonnet-5) reject it as deprecated.
        body = {
            "model": self.model,
            "max_tokens": int(max_tokens) if max_tokens is not None else 2048,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        wait = float(timeout) if timeout is not None else DEFAULT_HTTP_TIMEOUT_S
        try:
            doc = _call_http_post(self._post, self.url, dict(self._headers), body, timeout=wait)
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(self._scrub(str(exc)) or "AI provider request failed") from None
        parts = (doc or {}).get("content") or []
        texts: list[str] = []
        for block in parts:
            if isinstance(block, dict) and block.get("type", "text") == "text":
                texts.append(str(block.get("text") or ""))
            elif isinstance(block, str):
                texts.append(block)
        return "".join(texts).strip()


def build_provider(
    *,
    provider: str,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str = "",
    http_post: HttpPost | None = None,
) -> Provider:
    """Build a provider from explicit settings (Mongo UI or env)."""
    spec = resolve_spec(provider)
    model_name = (model or "").strip() or spec.default_model
    url = effective_base_url(spec, base_url)
    if spec.wire == "ollama":
        return OllamaProvider(url, model_name, http_post=http_post)
    if spec.wire == "anthropic":
        return AnthropicProvider(url, model_name, api_key, http_post=http_post)
    if spec.wire == "openai_compat":
        return OpenAICompatProvider(url, model_name, api_key, name=spec.id, http_post=http_post)
    raise AIProviderError(f"unsupported provider wire {spec.wire!r}")


__all__ = [
    "AIProviderError",
    "ANTHROPIC_VERSION",
    "AnthropicProvider",
    "HttpPost",
    "OllamaProvider",
    "OpenAICompatProvider",
    "PROVIDERS",
    "Provider",
    "ProviderSpec",
    "build_provider",
    "catalog_public",
    "effective_base_url",
    "resolve_spec",
]
