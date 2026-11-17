"""F-01: passive hostname/CNAME → cloud storage correlation (string matching only)."""
# @lat: [[attack-surface-and-platform#Cloud correlation and Prowler disclosure]]

from __future__ import annotations

import pytest

from attestra.discovery.cloud_correlation import correlate, correlate_host


@pytest.mark.parametrize(
    "host,provider,kind,res",
    [
        ("acme-data.s3.amazonaws.com", "aws", "s3_bucket", "acme-data"),
        ("acme-data.s3.eu-west-1.amazonaws.com", "aws", "s3_bucket", "acme-data"),
        ("acme-site.s3-website-us-east-1.amazonaws.com", "aws", "s3_website", "acme-site"),
        ("d111111abcdef8.cloudfront.net", "aws", "cloudfront", "d111111abcdef8"),
        ("acmestore.blob.core.windows.net", "azure", "blob_container", "acmestore"),
        ("acmestore.z13.web.core.windows.net", "azure", "static_website", "acmestore"),
        ("acme-app.azurewebsites.net", "azure", "app_service", "acme-app"),
        ("acme-bucket.storage.googleapis.com", "gcp", "gcs_bucket", "acme-bucket"),
        ("acme.appspot.com", "gcp", "app_engine", "acme"),
        ("acme.web.app", "gcp", "firebase", "acme"),
        ("pub-0123abcd.r2.dev", "cloudflare", "r2_public", "0123abcd"),
    ],
)
def test_known_patterns(host, provider, kind, res):
    hit = correlate_host(host)
    assert hit and hit["provider"] == provider and hit["kind"] == kind and hit["resource"] == res


def test_storage_flag_and_cname_path():
    hit = correlate("files.example.com", ["acme-files.s3.us-east-1.amazonaws.com"])
    assert hit["storage"] is True and hit["through_cname"] is True
    assert correlate("acme.cloudfront.net")["storage"] is False


@pytest.mark.parametrize("host", ["www.example.com", "s3.amazonaws.com.evil.example", "blob.core.windows.net", ""])
def test_non_matches(host):
    assert correlate(host) == {}
