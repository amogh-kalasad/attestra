"""SSRF guard for webhook URLs: reuse the runner's IP validation (private/internal blocked)."""

from __future__ import annotations

from urllib.parse import urlsplit

from attestra.runner.authorization import AuthorizationError, validate_resolved_ips
from attestra.runner.dns_pin import PinnedTarget, resolve_host


class WebhookUrlError(ValueError):
    pass


def check_url(url: str, *, resolver=resolve_host, require_https: bool = True) -> PinnedTarget:
    """Validate scheme/host and resolve once. Every resolved IP must be public. Returns a pin."""
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise WebhookUrlError("webhook URL must be an absolute http(s) URL")
    if require_https and parts.scheme != "https":
        raise WebhookUrlError("webhook URL must use https")
    if parts.username or parts.password:
        raise WebhookUrlError("credentials in webhook URL are not allowed")
    host = parts.hostname.lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise WebhookUrlError(f"internal host not allowed: {host}")
    try:
        ips = resolver(host)
        validated = validate_resolved_ips(ips, allow_private=False)
    except AuthorizationError as exc:
        raise WebhookUrlError(f"webhook URL blocked: {exc}") from exc
    except OSError as exc:
        raise WebhookUrlError(f"cannot resolve {host}: {exc}") from exc
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return PinnedTarget(host=host, ip=str(validated[0]), port=port, scheme=parts.scheme)
