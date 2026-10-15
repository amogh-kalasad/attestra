"""Prove control of a target before the first scan (DNS TXT or well-known file)."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlsplit

from attestra.models import Asset, utcnow
from attestra.runner.authorization import (
    AuthorizationError,
    AuthorizedScope,
    authorize_target,
    owner_confirm_host,
)

WELL_KNOWN_PATH = "/.well-known/attestra-verify.txt"
TXT_PREFIX = "attestra-verify="
CHECK_TIMEOUT = 5  # seconds, for both the DNS lookup and the file fetch
MAX_FILE_BYTES = 4096
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def issue_token(asset: Asset) -> str:
    token = secrets.token_urlsafe(24)
    asset.ownership_token = token
    return token


def ensure_token(asset: Asset) -> str:
    """Return the target's ownership token, issuing one the first time it is needed."""
    return asset.ownership_token or issue_token(asset)


def is_verified(asset: Asset) -> bool:
    if asset.ownership_verified_at is not None:
        return True
    # Loopback / explicitly private fixtures skip ownership in development.
    ident = (asset.identifier or "").lower()
    notes = (asset.notes or "").lower()
    if "allow_private" in notes or "127.0.0.1" in ident or "localhost" in ident:
        return True
    return False


def verify(
    asset: Asset,
    *,
    scope: AuthorizedScope | None = None,
    dns_lookup=None,
    http_get=None,
) -> bool:
    """Return True and set ownership_verified_at when DNS TXT or well-known file matches."""
    token = asset.ownership_token
    if not token:
        token = issue_token(asset)
    expected = f"{TXT_PREFIX}{token}"
    host = _host_for(asset)
    if not host:
        return False

    # DNS TXT
    lookup = dns_lookup or _default_dns_txt
    try:
        txts = lookup(host)
        if any(expected in t or token in t for t in txts):
            asset.ownership_verified_at = utcnow()
            return True
    except Exception:
        pass

    # Well-known HTTP file
    if asset.kind in ("web_app", "api") and scope is not None:
        url = asset.identifier.rstrip("/") + WELL_KNOWN_PATH
        getter = http_get or _default_http_get
        try:
            body = getter(url, scope=scope)
            if token in body.decode("utf-8", errors="replace"):
                asset.ownership_verified_at = utcnow()
                return True
        except Exception:
            return False
    return False


# ---------------------------------------------------------------- UI check (show token, check now)


def instructions(asset: Asset) -> dict:
    """What the client must publish to prove control of this target (both methods)."""
    host = _host_for(asset)
    token = asset.ownership_token or ""
    labels = host.split(".") if host else []
    if len(labels) > 2:
        short_name, zone = ".".join(labels[:-2]), ".".join(labels[-2:])
    else:
        short_name, zone = "@", host
    return {
        "host": host,
        "token": token,
        "txt_name": host,
        "txt_short_name": short_name,
        "txt_zone": zone,
        "txt_value": f"{TXT_PREFIX}{token}",
        "file_url": well_known_url(asset),
        "file_content": token,
        # Private network address: Option C (owner confirms) is offered instead of DNS / file.
        "private_confirm": bool(owner_confirm_host(asset.kind, asset.identifier)),
    }


def well_known_url(asset: Asset) -> str:
    host = _host_for(asset)
    if not host:
        return ""
    if asset.kind in ("web_app", "api"):
        parts = urlsplit(asset.identifier.strip())
        scheme = parts.scheme if parts.scheme in ("http", "https") else "https"
        netloc = host if parts.port is None else f"{host}:{parts.port}"
        return f"{scheme}://{netloc}{WELL_KNOWN_PATH}"
    return f"https://{host}{WELL_KNOWN_PATH}"


@dataclass
class FileFetch:
    status: int
    body: bytes = b""
    location: str = ""


@dataclass
class OwnershipCheck:
    ok: bool = False
    method: str = ""  # "dns" | "file" when ok ("owner_confirmed" is recorded by services, not here)
    dns_note: str = ""
    file_note: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def message(self) -> str:
        parts = [p for p in (self.dns_note, self.file_note, *self.notes) if p]
        return " ".join(parts)


def check(asset: Asset, *, scope: AuthorizedScope | None, scope_error: str = "") -> OwnershipCheck:
    """Look for the token: one DNS TXT lookup, then (if needed) one HTTPS GET of the well-known file.

    Never scans and never follows redirects. Sets ``ownership_verified_at`` on success.
    Every outcome is described in plain words in ``OwnershipCheck.message``.
    """
    result = OwnershipCheck()
    token = ensure_token(asset)
    expected = f"{TXT_PREFIX}{token}"
    host = _host_for(asset)
    if not host or not _HOSTNAME.match(host):
        result.notes.append("This target has no host name Attestra can check.")
        return result

    # 1. DNS TXT on the host itself
    records, error = _dns_txt_records(host, expected=expected)
    if error:
        result.dns_note = f"DNS: could not look up TXT records for {host} ({error})."
    elif any(expected in r for r in records):
        result.ok, result.method = True, "dns"
        asset.ownership_verified_at = utcnow()
        result.dns_note = f"DNS: found the TXT record {expected} on {host}."
        return result
    elif not records:
        result.dns_note = f"DNS: no TXT record found on {host}. Add a TXT record named {host} with value {expected}."
    else:
        others = [r for r in records if r.startswith(TXT_PREFIX)]
        if others:
            result.dns_note = (
                f"DNS: found an attestra-verify TXT record on {host}, but its value does not match this target's "
                f"token. Change it to {expected}."
            )
        else:
            result.dns_note = (
                f"DNS: found {len(records)} TXT record(s) on {host}, but none is {expected}."
            )

    # 2. Well-known file, one plain GET, only for targets inside a valid signed authorization
    url = well_known_url(asset)
    if scope is None:
        why = scope_error or "no valid signed authorization"
        result.file_note = f"File: not checked, because the target is not covered by a valid signed authorization ({why})."
        return result
    try:
        authorize_target(scope, url, "url")
    except AuthorizationError as exc:
        result.file_note = f"File: not checked, because {url} is outside the authorized scope ({exc})."
        return result
    try:
        fetched = _fetch_well_known(url, scope=scope)
    except AuthorizationError as exc:
        result.file_note = f"File: not checked ({exc})."
        return result
    except Exception as exc:  # noqa: BLE001 - network errors become a friendly message
        result.file_note = f"File: could not fetch {url} ({_short_error(exc)})."
        return result

    if fetched.status in (301, 302, 303, 307, 308):
        where = f" to {fetched.location}" if fetched.location else ""
        result.file_note = (
            f"File: {url} redirects{where}. Attestra does not follow redirects for this check, "
            "so serve the file directly at that address."
        )
    elif fetched.status != 200:
        result.file_note = f"File: {url} answered HTTP {fetched.status}, so the file is not there yet."
    else:
        text = fetched.body.decode("utf-8", errors="replace")
        if token in text:
            result.ok, result.method = True, "file"
            asset.ownership_verified_at = utcnow()
            result.file_note = f"File: found the token in {url}."
        else:
            seen = " ".join(text.split())[:60]
            shown = f'it contains "{seen}"' if seen else "it is empty"
            result.file_note = f"File: {url} exists but does not contain the token ({shown})."
    return result


def _short_error(exc: Exception) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return f"no answer within {CHECK_TIMEOUT} seconds"
    return text[:120]


DEFAULT_DNS_RESOLVERS = "1.1.1.1,8.8.8.8"


def dns_resolvers() -> list[str | None]:
    """Resolvers to ask, in order: ATTESTRA_DNS_RESOLVERS (IP addresses, comma separated), then the system default.

    Public resolvers come first because a home or office router often caches an old "no record" answer.
    Anything that is not a plain IP address is ignored, so nothing odd reaches the command line.
    """
    raw = os.environ.get("ATTESTRA_DNS_RESOLVERS", DEFAULT_DNS_RESOLVERS)
    out: list[str | None] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            ip = str(ipaddress.ip_address(item))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    out.append(None)  # system default resolver last
    return out


def _dns_txt_records(host: str, *, expected: str = "") -> tuple[list[str], str]:
    """TXT strings for ``host`` and an error text ('' when at least one lookup worked).

    Asks each resolver from :func:`dns_resolvers` in turn and stops as soon as one returns ``expected``.
    """
    if not _HOSTNAME.match(host):
        return [], "invalid host name"
    records: list[str] = []
    errors: list[str] = []
    answered = False
    for server in dns_resolvers():
        found, error = _txt_lookup(host, server)
        if error:
            errors.append(f"{server or 'system resolver'}: {error}")
            continue
        answered = True
        for r in found:
            if r not in records:
                records.append(r)
        if expected and any(expected in r for r in found):
            break
    if answered or records:
        return records, ""
    return [], "; ".join(errors) or "no DNS server answered"


def _txt_lookup(host: str, server: str | None) -> tuple[list[str], str]:
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return _nslookup_txt(host, server)
    resolver = dns.resolver.Resolver(configure=server is None)
    if server is not None:
        resolver.nameservers = [server]
    try:
        answers = resolver.resolve(host, "TXT", lifetime=CHECK_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], ""
    except Exception as exc:  # noqa: BLE001
        return [], _short_error(exc)
    out: list[str] = []
    for r in answers:
        out.append("".join(s.decode() if isinstance(s, bytes) else str(s) for s in r.strings))
    return out, ""


def _nslookup_txt(host: str, server: str | None = None) -> tuple[list[str], str]:
    """Fallback when dnspython is not installed: the system ``nslookup`` (Windows and most Linux)."""
    if not _HOSTNAME.match(host):
        return [], "invalid host name"
    cmd = ["nslookup", f"-timeout={CHECK_TIMEOUT}", "-retry=1", "-type=TXT", host]
    if server:
        cmd.append(server)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=CHECK_TIMEOUT + 2, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError:
        return [], "no DNS lookup tool available on this server"
    except subprocess.TimeoutExpired:
        return [], f"no answer within {CHECK_TIMEOUT} seconds"
    out = proc.stdout or ""
    records = _parse_nslookup(out)
    if records:
        return records, ""
    # 'Non-authoritative answer:' and "can't find" go to stderr on Windows; only timeouts count as errors.
    low = (out + "\n" + (proc.stderr or "")).lower()
    if "timed out" in low or "no response" in low or "request to" in low and "timed-out" in low:
        return [], "the DNS server did not answer"
    return [], ""


def _parse_nslookup(output: str) -> list[str]:
    """Pull TXT strings out of nslookup stdout.

    Handles ``host<TAB>text =`` followed by quoted chunks on the same or later lines (long records
    are split into several quoted chunks, which are joined). Lines outside a ``text =`` block are ignored.
    """
    records: list[str] = []
    current: list[str] | None = None
    for line in output.splitlines():
        if "text =" in line:
            if current:
                records.append("".join(current))
            current = re.findall(r'"([^"]*)"', line.split("text =", 1)[1])
            continue
        if current is None:
            continue
        chunks = re.findall(r'"([^"]*)"', line)
        if chunks:
            current.extend(chunks)
        elif line.strip() == "":
            continue
        else:
            records.append("".join(current))
            current = None
    if current:
        records.append("".join(current))
    return records


class _PinnedHTTPSConnection(HTTPSConnection):
    """Connect to the pinned IP but verify the certificate for the real host name (SNI)."""

    def __init__(self, ip: str, port: int, *, server_hostname: str, timeout: float):
        super().__init__(ip, port, timeout=timeout, context=ssl.create_default_context())
        self._server_hostname = server_hostname

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._server_hostname)


def _fetch_well_known(url: str, *, scope: AuthorizedScope) -> FileFetch:
    """One GET of the well-known file: pinned, short timeout, small body, redirects not followed."""
    from attestra.runner.dns_pin import pin_url

    target = pin_url(url, scope)
    if target.scheme == "https":
        conn = _PinnedHTTPSConnection(target.ip, target.port, server_hostname=target.host, timeout=CHECK_TIMEOUT)
    else:
        conn = HTTPConnection(target.ip, target.port, timeout=CHECK_TIMEOUT)
    try:
        conn.request("GET", WELL_KNOWN_PATH, headers={
            "Host": target.host_header, "User-Agent": "attestra-ownership-check/1", "Accept": "text/plain",
        })
        resp = conn.getresponse()
        body = resp.read(MAX_FILE_BYTES)
        return FileFetch(status=resp.status, body=body, location=resp.getheader("Location") or "")
    finally:
        conn.close()


def _host_for(asset: Asset) -> str:
    if asset.kind in ("web_app", "api"):
        return (urlsplit(asset.identifier).hostname or "").lower()
    if asset.kind == "host":
        return asset.identifier.split("/")[0].lower()
    return ""


def _default_dns_txt(host: str) -> list[str]:
    """Best-effort TXT lookup; tests inject ``dns_lookup``. No hard dependency on dnspython."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(host, "TXT")
    except Exception:
        return []
    out: list[str] = []
    for r in answers:
        out.extend(s.decode() if isinstance(s, bytes) else str(s) for s in r.strings)
    return out


def _default_http_get(url: str, *, scope: AuthorizedScope) -> bytes:
    from attestra.runner.http_safe import safe_get

    return safe_get(url, scope=scope).body
