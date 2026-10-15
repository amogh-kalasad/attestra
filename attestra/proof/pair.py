"""HTTP request/response pair stored as ``http_pair`` evidence (JSON)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from attestra.proof.redact import redact_body, redact_headers, redact_url

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
FORMAT = "attestra.http_pair/1"


@dataclass
class HttpPair:
    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    match: str = ""  # optional string whose presence in the response proves the issue
    source: str = "manual"

    def redacted(self) -> HttpPair:
        req_ct = _ct(self.request_headers)
        resp_ct = _ct(self.response_headers)
        return HttpPair(
            method=self.method.upper(),
            url=redact_url(self.url),
            request_headers=redact_headers(self.request_headers),
            request_body=redact_body(self.request_body, req_ct),
            status=self.status,
            response_headers=redact_headers(self.response_headers),
            response_body=redact_body(self.response_body, resp_ct)[:200_000],
            match=self.match,
            source=self.source,
        )

    def to_bytes(self) -> bytes:
        return json.dumps({"format": FORMAT, **asdict(self)}, indent=2, sort_keys=True).encode()

    @classmethod
    def from_dict(cls, d: dict) -> HttpPair:
        method = str(d.get("method") or "GET").upper()
        url = str(d.get("url") or "")
        if urlsplit(url).scheme not in ("http", "https") or not urlsplit(url).hostname:
            raise ValueError("http pair needs an absolute http(s) url")
        return cls(
            method=method,
            url=url,
            request_headers={str(k): str(v) for k, v in (d.get("request_headers") or {}).items()},
            request_body=str(d.get("request_body") or ""),
            status=int(d["status"]) if d.get("status") not in (None, "") else None,
            response_headers={str(k): str(v) for k, v in (d.get("response_headers") or {}).items()},
            response_body=str(d.get("response_body") or ""),
            match=str(d.get("match") or ""),
            source=str(d.get("source") or "manual"),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HttpPair:
        return cls.from_dict(json.loads(data.decode("utf-8", "replace")))


def _ct(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v
    return ""


def _split_head(raw: str) -> tuple[list[str], str]:
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    return head.split("\n"), body


def _headers(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_raw_request(raw: str, fallback_url: str = "") -> tuple[str, str, dict[str, str], str]:
    """Parse ``GET /path HTTP/1.1`` + headers + body. Returns (method, absolute url, headers, body)."""
    lines, body = _split_head(raw or "")
    first = (lines[0] if lines else "").split()
    method = first[0].upper() if first else "GET"
    target = first[1] if len(first) > 1 else "/"
    headers = _headers(lines[1:])
    if urlsplit(target).scheme in ("http", "https"):
        url = target
    else:
        base = fallback_url
        host = next((v for k, v in headers.items() if k.lower() == "host"), "")
        if host:
            scheme = urlsplit(fallback_url).scheme or "https"
            base = f"{scheme}://{host}/"
        url = urljoin(base, target) if base else target
    return method, url, headers, body


def parse_raw_response(raw: str) -> tuple[int | None, dict[str, str], str]:
    lines, body = _split_head(raw or "")
    first = (lines[0] if lines else "").split()
    status = int(first[1]) if len(first) > 1 and first[1].isdigit() else None
    return status, _headers(lines[1:]), body


def pair_from_raw(request: str, response: str, *, url: str = "", match: str = "", source: str = "manual") -> HttpPair:
    method, full_url, req_h, req_b = parse_raw_request(request, url)
    status, resp_h, resp_b = parse_raw_response(response)
    return HttpPair(method, full_url or url, req_h, req_b, status, resp_h, resp_b, match, source)
