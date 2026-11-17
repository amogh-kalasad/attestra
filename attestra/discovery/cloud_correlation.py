"""Passive hostname → cloud storage / CDN correlation (F-01).

Pure string matching over a hostname and its CNAME chain: no request is sent and no
bucket is listed. The result tells a reviewer "this candidate is served from an S3
bucket / Azure blob container / GCS bucket / CDN", which feeds review and the cloud
posture workstream; it is never a finding by itself.
"""
# @lat: [[attack-surface-and-platform#Cloud correlation and Prowler disclosure]]

from __future__ import annotations

import re

_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("aws", "s3_website", re.compile(r"^(?P<res>[a-z0-9.\-]{3,63})\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$")),
    ("aws", "s3_bucket", re.compile(r"^(?P<res>[a-z0-9.\-]{3,63})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$")),
    ("aws", "cloudfront", re.compile(r"^(?P<res>[a-z0-9]+)\.cloudfront\.net$")),
    ("aws", "elb", re.compile(r"^(?P<res>[a-z0-9.\-]+)\.elb\.amazonaws\.com$")),
    ("azure", "blob_container", re.compile(r"^(?P<res>[a-z0-9]{3,24})\.blob\.core\.windows\.net$")),
    ("azure", "static_website", re.compile(r"^(?P<res>[a-z0-9]{3,24})\.z\d+\.web\.core\.windows\.net$")),
    ("azure", "app_service", re.compile(r"^(?P<res>[a-z0-9\-]+)\.azurewebsites\.net$")),
    ("azure", "front_door", re.compile(r"^(?P<res>[a-z0-9\-]+)\.(?:azurefd|azureedge)\.net$")),
    ("gcp", "gcs_bucket", re.compile(r"^(?P<res>[a-z0-9._\-]{3,63})\.storage\.googleapis\.com$")),
    ("gcp", "gcs_bucket", re.compile(r"^storage\.googleapis\.com$")),
    ("gcp", "app_engine", re.compile(r"^(?P<res>[a-z0-9\-]+)\.appspot\.com$")),
    ("gcp", "firebase", re.compile(r"^(?P<res>[a-z0-9\-]+)\.(?:web\.app|firebaseapp\.com)$")),
    ("digitalocean", "spaces", re.compile(r"^(?P<res>[a-z0-9\-]+)\.[a-z0-9]+\.digitaloceanspaces\.com$")),
    ("cloudflare", "r2_public", re.compile(r"^pub-(?P<res>[a-f0-9]+)\.r2\.dev$")),
)

STORAGE_KINDS = frozenset({"s3_bucket", "s3_website", "blob_container", "static_website", "gcs_bucket", "spaces", "r2_public"})


def correlate_host(host: str) -> dict | None:
    h = (host or "").lower().rstrip(".")
    for provider, kind, rx in _RULES:
        m = rx.match(h)
        if m:
            res = m.groupdict().get("res") or ""
            return {"provider": provider, "kind": kind, "resource": res, "via": h, "storage": kind in STORAGE_KINDS}
    return None


def correlate(name: str, cnames=()) -> dict:
    """First match over the name and then each CNAME hop. ``{}`` when nothing matches."""
    for host in (name, *list(cnames or ())):
        hit = correlate_host(host)
        if hit:
            hit["through_cname"] = host != name
            return hit
    return {}
