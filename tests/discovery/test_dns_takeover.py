"""A-05: CNAME chains (multi-hop, loop, NXDOMAIN, SERVFAIL, wildcard) and passive takeover labels."""
# @lat: [[attack-surface-and-platform#DNS chain and takeover fingerprints]]

from __future__ import annotations

from attestra.discovery import dns_chain as D
from attestra.discovery import pipeline
from attestra.discovery import takeover_fingerprints as TK
from attestra.discovery.candidates import Observation


def fake_resolver(zone: dict, wildcard_ip: str | None = None, apex: str = "example.com"):
    """zone: name -> {"CNAME": target} | {"A": [...]} | "NXDOMAIN" | "SERVFAIL"."""

    def resolve(name: str, rtype: str) -> D.DnsAnswer:
        entry = zone.get(name)
        if entry is None and wildcard_ip and name.endswith("." + apex):
            entry = {"A": [wildcard_ip]}
        if entry is None or entry == "NXDOMAIN":
            return D.DnsAnswer("NXDOMAIN")
        if entry == "SERVFAIL":
            return D.DnsAnswer("SERVFAIL")
        if rtype == "CNAME":
            return D.DnsAnswer("NOERROR", (entry["CNAME"],)) if "CNAME" in entry else D.DnsAnswer("NOERROR")
        vals = entry.get(rtype) or []
        if "CNAME" in entry:
            return D.DnsAnswer("NOERROR")
        return D.DnsAnswer("NOERROR", tuple(vals)) if vals else D.DnsAnswer("NODATA")

    return resolve


def test_multi_hop_chain():
    r = fake_resolver(
        {
            "www.example.com": {"CNAME": "www.example.com.cdn.net."},
            "www.example.com.cdn.net": {"CNAME": "edge-1.cdn.net"},
            "edge-1.cdn.net": {"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]},
        }
    )
    c = D.follow_cname_chain("www.example.com", r)
    assert c.chain == ["www.example.com.cdn.net", "edge-1.cdn.net"]
    assert c.terminal == "edge-1.cdn.net"
    assert c.status == "NOERROR" and c.addresses == ["192.0.2.1", "2001:db8::1"]
    assert not c.dangling


def test_cname_loop_detected():
    r = fake_resolver({"a.example.com": {"CNAME": "b.example.com"}, "b.example.com": {"CNAME": "a.example.com"}})
    c = D.follow_cname_chain("a.example.com", r)
    assert c.loop is True and c.status == "SERVFAIL"
    assert TK.assess(c).status == TK.INCONCLUSIVE


def test_too_many_hops_truncated():
    zone = {f"h{i}.example.com": {"CNAME": f"h{i + 1}.example.com"} for i in range(20)}
    c = D.follow_cname_chain("h0.example.com", fake_resolver(zone), max_hops=5)
    assert c.truncated and len(c.chain) == 5


def test_nxdomain_dangling_cname():
    r = fake_resolver({"old.example.com": {"CNAME": "gone-app.azurewebsites.net"}})
    c = D.follow_cname_chain("old.example.com", r)
    assert c.status == "NXDOMAIN" and c.dangling
    a = TK.assess(c)
    assert a.status == TK.SUSPECTED and a.provider == "azure"
    assert a.as_dict()["claim_attempted"] is False


def test_plain_nxdomain_is_not_takeover():
    c = D.follow_cname_chain("nothing.example.com", fake_resolver({}))
    assert c.status == "NXDOMAIN" and not c.dangling
    assert TK.assess(c).status == TK.NOT_SUSPECTED


def test_servfail_is_inconclusive():
    r = fake_resolver({"x.example.com": {"CNAME": "x.herokudns.com"}, "x.herokudns.com": "SERVFAIL"})
    c = D.follow_cname_chain("x.example.com", r)
    assert c.status == "SERVFAIL"
    assert TK.assess(c).status == TK.INCONCLUSIVE


def test_resolver_exception_becomes_servfail():
    def broken(name, rtype):
        raise OSError("socket")

    c = D.follow_cname_chain("x.example.com", broken)
    assert c.status == "SERVFAIL" and "resolver error" in c.error


def test_wildcard_detection_and_classification():
    r = fake_resolver({"www.example.com": {"A": ["192.0.2.5"]}}, wildcard_ip="192.0.2.99")
    wc = D.detect_wildcard("example.com", r)
    assert wc == frozenset({"192.0.2.99"})
    random_name = D.follow_cname_chain("whatever.example.com", r)
    assert D.classify(random_name, wc) == "wildcard"
    assert D.classify(D.follow_cname_chain("www.example.com", r), wc) == "resolved"
    assert D.detect_wildcard("example.com", fake_resolver({})) == frozenset()


def test_github_pages_fingerprint_with_cname_is_suspected():
    r = fake_resolver({"docs.example.com": {"CNAME": "acme.github.io"}, "acme.github.io": {"A": ["185.199.108.153"]}})
    c = D.follow_cname_chain("docs.example.com", r)
    body = "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>"
    a = TK.assess(c, http_body=body, http_status=404)
    assert a.status == TK.SUSPECTED and a.provider == "github_pages"


def test_provider_error_page_without_cname_is_false_positive_guarded():
    r = fake_resolver({"www.example.com": {"A": ["192.0.2.1"]}})
    c = D.follow_cname_chain("www.example.com", r)
    a = TK.assess(c, http_body="There isn't a GitHub Pages site here.", http_status=404)
    assert a.status == TK.NOT_SUSPECTED
    assert any("ignored" in x for x in a.reasons)


def test_provider_cname_with_normal_page_not_suspected():
    r = fake_resolver({"shop.example.com": {"CNAME": "acme.myshopify.com"}, "acme.myshopify.com": {"A": ["23.227.38.65"]}})
    c = D.follow_cname_chain("shop.example.com", r)
    assert TK.assess(c, http_body="<html>Welcome to Acme</html>", http_status=200).status == TK.NOT_SUSPECTED


def test_status_mismatch_not_suspected():
    r = fake_resolver({"docs.example.com": {"CNAME": "acme.github.io"}, "acme.github.io": {"A": ["185.199.108.153"]}})
    c = D.follow_cname_chain("docs.example.com", r)
    assert TK.assess(c, http_body="There isn't a GitHub Pages site here.", http_status=200).status == TK.NOT_SUSPECTED


def test_dangling_cname_to_body_only_provider_is_inconclusive():
    r = fake_resolver({"app.example.com": {"CNAME": "gone.herokuapp.com"}})
    c = D.follow_cname_chain("app.example.com", r)
    assert TK.assess(c).status == TK.INCONCLUSIVE


def test_wildcard_flag_makes_takeover_inconclusive():
    r = fake_resolver({"docs.example.com": {"CNAME": "acme.github.io"}, "acme.github.io": {"A": ["185.199.108.153"]}})
    c = D.follow_cname_chain("docs.example.com", r)
    assert TK.assess(c, http_body="There isn't a GitHub Pages site here.", http_status=404, wildcard=True).status == TK.INCONCLUSIVE


def test_s3_regional_endpoint_matches_but_elb_does_not():
    sigs = TK.load_signatures()
    s3 = next(s for s in sigs if s.id == "aws_s3")
    assert s3.matches_name("bucket.s3.eu-west-1.amazonaws.com")
    assert s3.matches_name("bucket.s3-website-us-east-1.amazonaws.com")
    assert not s3.matches_name("my-lb-123.us-east-1.elb.amazonaws.com")


def test_signature_data_is_valid():
    sigs = TK.load_signatures()
    assert len(sigs) >= 10
    for s in sigs:
        assert s.cname_suffixes and (s.fingerprints or s.nxdomain_indicates), s.id


def test_pipeline_enrichment_uses_injected_resolver_only():
    r = fake_resolver(
        {
            "old.example.com": {"CNAME": "gone-app.azurewebsites.net"},
            "www.example.com": {"A": ["192.0.2.1"]},
            "assets.example.com": {"CNAME": "acme-assets.s3.us-east-1.amazonaws.com"},
            "acme-assets.s3.us-east-1.amazonaws.com": {"A": ["52.216.0.1"]},
        }
    )
    res = pipeline.merge_observations(
        [Observation(n, "ct") for n in ("old.example.com", "www.example.com", "assets.example.com")],
        apex="example.com",
        allowed_hosts=["example.com"],
    )
    pipeline.enrich_with_dns(res, r)
    by = {c.name: c for c in res.candidates}
    assert by["old.example.com"].resolution == "nxdomain"
    assert by["old.example.com"].takeover["status"] == "suspected"
    assert by["www.example.com"].resolution == "resolved"
    assert by["assets.example.com"].cloud["kind"] == "s3_bucket"
    assert by["old.example.com"].confidence < by["www.example.com"].confidence
