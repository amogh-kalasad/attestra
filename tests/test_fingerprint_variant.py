"""Phase 0: empty variant must keep fingerprints byte-identical to pre-variant keys."""
from __future__ import annotations

from attestra.fingerprint import fingerprint


# @lat: [[findings#Deduplication]]
def test_empty_variant_fingerprint_unchanged():
    """A known no-variant fingerprint value is unchanged when variant is omitted or empty."""
    kwargs = dict(
        location="https://shop.example.com/search",
        cwe=79,
        cves=[],
        title="Cross Site Scripting (Reflected)",
        param="q",
        package="",
        asset_id=1,
    )
    baseline = fingerprint(**kwargs)
    assert fingerprint(**kwargs, variant="") == baseline
    assert fingerprint(**kwargs) == baseline
    # Non-empty variant must change the key.
    assert fingerprint(**kwargs, variant="10055-5") != baseline
