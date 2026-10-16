"""Importance, effort, fix steps and server config snippets for library writeups.

Snippets stay as library data (seed + DB columns). Templates only display them.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

FIX_TAGS = frozenset({"headers", "tls", "cookies", "csp"})
IMPORTANCE_VALUES = ("High", "Medium", "Low")
EFFORT_VALUES = ("Easy", "Medium", "Hard")
SNIPPET_KEYS = ("nginx", "apache", "iis", "cloudflare")
SERVER_TYPES = ("nginx", "apache", "iis", "cloudflare")
FIX_FIELD_KEYS = (
    "importance",
    "effort",
    "fix_steps",
    "snippet_nginx",
    "snippet_apache",
    "snippet_iis",
    "snippet_cloudflare",
)

# Built-in fix text keyed by seed title. Merged into SEED on load / seed_defaults.
BY_TITLE: dict[str, dict[str, str]] = {
    "Session cookie missing Secure or HttpOnly flag": {
        "importance": "High",
        "effort": "Easy",
        "fix_steps": (
            "Mark every session cookie Secure; HttpOnly; SameSite=Lax (or Strict if the app allows).\n"
            "Set flags in the app cookie API, not only in the reverse proxy.\n"
            "Confirm Set-Cookie on login still works across your main flows."
        ),
        "snippet_nginx": (
            "# Prefer setting flags in the app. Proxy example (use with care):\n"
            "proxy_cookie_path / \"/; Secure; HttpOnly; SameSite=Lax\";"
        ),
        "snippet_apache": (
            "# Prefer setting flags in the app. Header edit example:\n"
            "Header edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\""
        ),
        "snippet_iis": (
            "<!-- Prefer app-level cookie flags. web.config outbound rule sketch: -->\n"
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <rewrite>\n"
            "      <outboundRules>\n"
            "        <rule name=\"SessionCookieFlags\">\n"
            "          <match serverVariable=\"RESPONSE_Set-Cookie\" pattern=\"^(.*)$\" />\n"
            "          <action type=\"Rewrite\" value=\"{R:1}; Secure; HttpOnly; SameSite=Lax\" />\n"
            "        </rule>\n"
            "      </outboundRules>\n"
            "    </rewrite>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Cloudflare cannot fully set app session flags. Set Secure; HttpOnly; SameSite=Lax in the origin app.\n"
            "Optional: Transform Rules → Modify Response Header only if you control a CDN-set cookie."
        ),
    },
    "Sensitive data sent over unencrypted HTTP": {
        "importance": "High",
        "effort": "Medium",
        "fix_steps": (
            "Serve the site only over HTTPS.\n"
            "Redirect every http:// request to https:// on the same host with 301 or 308.\n"
            "Then enable HSTS on HTTPS responses."
        ),
        "snippet_nginx": (
            "server {\n"
            "  listen 80;\n"
            "  server_name example.com;\n"
            "  return 301 https://$host$request_uri;\n"
            "}"
        ),
        "snippet_apache": (
            "RewriteEngine On\n"
            "RewriteCond %{HTTPS} !=on\n"
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <rewrite>\n"
            "      <rules>\n"
            "        <rule name=\"HttpToHttps\" stopProcessing=\"true\">\n"
            "          <match url=\"(.*)\" />\n"
            "          <conditions>\n"
            "            <add input=\"{HTTPS}\" pattern=\"off\" ignoreCase=\"true\" />\n"
            "          </conditions>\n"
            "          <action type=\"Redirect\" url=\"https://{HTTP_HOST}/{R:1}\" redirectType=\"Permanent\" />\n"
            "        </rule>\n"
            "      </rules>\n"
            "    </rewrite>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "SSL/TLS → Overview: set mode to Full (strict).\n"
            "SSL/TLS → Edge Certificates: enable Always Use HTTPS.\n"
            "Optional: redirect rule http → https for the hostname."
        ),
    },
    "Outdated TLS protocol or weak cipher suites": {
        "importance": "High",
        "effort": "Medium",
        "fix_steps": (
            "Disable TLS 1.0 and TLS 1.1.\n"
            "Allow TLS 1.2 and TLS 1.3 only with modern AEAD ciphers and forward secrecy.\n"
            "Retest with a TLS scanner after the change."
        ),
        "snippet_nginx": (
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_prefer_server_ciphers off;\n"
            "ssl_ciphers HIGH:!aNULL:!MD5:!3DES;"
        ),
        "snippet_apache": (
            "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
            "SSLCipherSuite HIGH:!aNULL:!MD5:!3DES\n"
            "SSLHonorCipherOrder off"
        ),
        "snippet_iis": (
            "<!-- Disable TLS 1.0/1.1 via registry or IIS Crypto, then reboot. Example registry values: -->\n"
            "<configuration>\n"
            "  <!-- Prefer Schannel policy: Enabled=0 for TLS 1.0 and TLS 1.1 protocols. -->\n"
            "  <system.webServer>\n"
            "    <security>\n"
            "      <access sslFlags=\"Ssl, Ssl128\" />\n"
            "    </security>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "SSL/TLS → Edge Certificates → Minimum TLS Version: set TLS 1.2 (or 1.3).\n"
            "Keep Modern cipher suite recommendation enabled."
        ),
    },
    "Certificate expires soon": {
        "importance": "High",
        "effort": "Easy",
        "fix_steps": (
            "Renew the certificate before notAfter.\n"
            "Prefer ACME auto-renewal and monitor the end date.\n"
            "Reload the TLS service after install and confirm the chain."
        ),
        "snippet_nginx": (
            "# After renew (certbot example):\n"
            "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n"
            "ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n"
            "# nginx -s reload;"
        ),
        "snippet_apache": (
            "SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem\n"
            "SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem\n"
            "# apachectl graceful"
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <!-- Bind the renewed cert in IIS Manager → Sites → Bindings → https. -->\n"
            "  <system.webServer>\n"
            "    <security>\n"
            "      <access sslFlags=\"Ssl\" />\n"
            "    </security>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "If using Cloudflare Origin CA or Universal SSL, renew/replace the origin cert before expiry.\n"
            "SSL/TLS → Origin Server: upload the new origin certificate if you terminate TLS at the edge."
        ),
    },
    "TLS: certificate expired": {
        "importance": "High",
        "effort": "Easy",
        "fix_steps": (
            "Replace the expired certificate immediately.\n"
            "Install the full chain (leaf + intermediates).\n"
            "Reload TLS and verify with a browser and a TLS check."
        ),
        "snippet_nginx": (
            "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n"
            "ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n"
            "# nginx -s reload;"
        ),
        "snippet_apache": (
            "SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem\n"
            "SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem\n"
            "# apachectl graceful"
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <!-- Replace the expired binding cert in IIS Manager, then recycle the site. -->\n"
            "  <system.webServer>\n"
            "    <security>\n"
            "      <access sslFlags=\"Ssl\" />\n"
            "    </security>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Upload a valid origin certificate under SSL/TLS → Origin Server, or switch to a working Cloudflare Origin CA cert.\n"
            "Confirm SSL/TLS mode is Full (strict)."
        ),
    },
    "Missing HTTP Strict Transport Security header": {
        "importance": "High",
        "effort": "Easy",
        "fix_steps": (
            "Send Strict-Transport-Security only on HTTPS responses.\n"
            "Start with max-age=31536000; includeSubDomains after every subdomain supports HTTPS.\n"
            "Add preload only after you have checked all subdomains and submitted to the preload list."
        ),
        "snippet_nginx": (
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        ),
        "snippet_apache": (
            "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <add name=\"Strict-Transport-Security\" value=\"max-age=31536000; includeSubDomains\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS): enable.\n"
            "Set max-age to 12 months, include subdomains when ready; enable preload only after all subdomains are HTTPS."
        ),
    },
    "Missing or weak Content Security Policy": {
        "importance": "High",
        "effort": "Hard",
        "fix_steps": (
            "Start with Content-Security-Policy-Report-Only and collect violations.\n"
            "Use a starter policy with default-src 'self'; avoid unsafe-inline when you can.\n"
            "Tighten script-src with nonces or hashes, then switch to enforcing CSP."
        ),
        "snippet_nginx": (
            "# Test first with Report-Only, then switch the header name to Content-Security-Policy.\n"
            "add_header Content-Security-Policy-Report-Only \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; img-src 'self' data:;\" always;"
        ),
        "snippet_apache": (
            "# Test first with Report-Only, then switch to Content-Security-Policy.\n"
            "Header always set Content-Security-Policy-Report-Only \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; img-src 'self' data:\""
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <add name=\"Content-Security-Policy-Report-Only\" value=\"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; img-src 'self' data:\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Rules → Transform Rules → Modify Response Header: set Content-Security-Policy-Report-Only to\n"
            "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; img-src 'self' data:.\n"
            "Switch to Content-Security-Policy after testing."
        ),
    },
    "Clickjacking: page can be framed": {
        "importance": "Medium",
        "effort": "Easy",
        "fix_steps": (
            "Send Content-Security-Policy frame-ancestors 'self' (or 'none').\n"
            "Also send X-Frame-Options SAMEORIGIN (or DENY) for older browsers.\n"
            "Allow only trusted parents if the page must be framed."
        ),
        "snippet_nginx": (
            "add_header Content-Security-Policy \"frame-ancestors 'self'\" always;\n"
            "add_header X-Frame-Options \"SAMEORIGIN\" always;"
        ),
        "snippet_apache": (
            "Header always set Content-Security-Policy \"frame-ancestors 'self'\"\n"
            "Header always set X-Frame-Options \"SAMEORIGIN\""
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <add name=\"Content-Security-Policy\" value=\"frame-ancestors 'self'\" />\n"
            "        <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Transform Rules → Modify Response Header: set Content-Security-Policy to frame-ancestors 'self'.\n"
            "Also set X-Frame-Options to SAMEORIGIN."
        ),
    },
    "Server version disclosed in headers": {
        "importance": "Low",
        "effort": "Easy",
        "fix_steps": (
            "Stop sending detailed Server and X-Powered-By values.\n"
            "Use a generic token or remove the headers at the proxy.\n"
            "Reload and confirm the banner is gone."
        ),
        "snippet_nginx": (
            "server_tokens off;\n"
            "more_clear_headers Server;"
        ),
        "snippet_apache": (
            "ServerTokens Prod\n"
            "ServerSignature Off\n"
            "Header unset X-Powered-By"
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <security>\n"
            "      <requestFiltering removeServerHeader=\"true\" />\n"
            "    </security>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <remove name=\"X-Powered-By\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Transform Rules → Modify Response Header: remove Server and X-Powered-By if present from origin.\n"
            "Cloudflare may still add its own cf-ray style headers; that is expected."
        ),
    },
    "Active mixed content": {
        "importance": "High",
        "effort": "Medium",
        "fix_steps": (
            "Find every http:// script, stylesheet, frame, object, or form action on HTTPS pages.\n"
            "Change those URLs to https:// or same-origin relative paths.\n"
            "Redeploy and recheck the page."
        ),
        "snippet_nginx": (
            "add_header Content-Security-Policy \"block-all-mixed-content\" always;"
        ),
        "snippet_apache": (
            "Header always set Content-Security-Policy \"block-all-mixed-content\""
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <add name=\"Content-Security-Policy\" value=\"block-all-mixed-content\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Fix asset URLs at the origin. Optional: Transform Rules cannot rewrite HTML bodies; use a worker only if you already manage one for URL upgrades."
        ),
    },
    "Passive mixed content": {
        "importance": "Medium",
        "effort": "Easy",
        "fix_steps": (
            "Find http:// image and media URLs on HTTPS pages.\n"
            "Serve them over https:// or from the same origin.\n"
            "Recheck the page after deploy."
        ),
        "snippet_nginx": (
            "add_header Content-Security-Policy \"upgrade-insecure-requests\" always;"
        ),
        "snippet_apache": (
            "Header always set Content-Security-Policy \"upgrade-insecure-requests\""
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <add name=\"Content-Security-Policy\" value=\"upgrade-insecure-requests\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Upgrade image/media URLs at the origin to https://. Optional: enable Automatic HTTPS Rewrites under SSL/TLS → Edge Certificates."
        ),
    },
    "HTTP does not redirect to HTTPS": {
        "importance": "High",
        "effort": "Easy",
        "fix_steps": (
            "Respond to http://host/ with 301 or 308 and Location https://same-host/...\n"
            "Do not send HSTS on the HTTP response.\n"
            "Prefer permanent redirects over 302/307."
        ),
        "snippet_nginx": (
            "server {\n"
            "  listen 80;\n"
            "  server_name example.com;\n"
            "  return 301 https://$host$request_uri;\n"
            "}"
        ),
        "snippet_apache": (
            "RewriteEngine On\n"
            "RewriteCond %{HTTPS} !=on\n"
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <rewrite>\n"
            "      <rules>\n"
            "        <rule name=\"HttpToHttps\" stopProcessing=\"true\">\n"
            "          <match url=\"(.*)\" />\n"
            "          <conditions>\n"
            "            <add input=\"{HTTPS}\" pattern=\"off\" ignoreCase=\"true\" />\n"
            "          </conditions>\n"
            "          <action type=\"Redirect\" url=\"https://{HTTP_HOST}/{R:1}\" redirectType=\"Permanent\" />\n"
            "        </rule>\n"
            "      </rules>\n"
            "    </rewrite>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "SSL/TLS → Edge Certificates → Always Use HTTPS: On.\n"
            "Or add a Redirect Rule: http://*example.com/* → https://$1example.com/$2 (301)."
        ),
    },
    "Temporary redirect to HTTPS": {
        "importance": "Medium",
        "effort": "Easy",
        "fix_steps": (
            "Change the HTTP→HTTPS upgrade from 302/307 to 301 or 308.\n"
            "Keep the Location on the same host.\n"
            "Retest the first HTTP request."
        ),
        "snippet_nginx": (
            "return 301 https://$host$request_uri;"
        ),
        "snippet_apache": (
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <rewrite>\n"
            "      <rules>\n"
            "        <rule name=\"HttpToHttpsPermanent\" stopProcessing=\"true\">\n"
            "          <match url=\"(.*)\" />\n"
            "          <conditions>\n"
            "            <add input=\"{HTTPS}\" pattern=\"off\" />\n"
            "          </conditions>\n"
            "          <action type=\"Redirect\" url=\"https://{HTTP_HOST}/{R:1}\" redirectType=\"Permanent\" />\n"
            "        </rule>\n"
            "      </rules>\n"
            "    </rewrite>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Use a Redirect Rule with status 301 (permanent), not 302.\n"
            "Always Use HTTPS already issues a permanent upgrade."
        ),
    },
    "HTTP redirects to another host before HTTPS on the same host": {
        "importance": "Medium",
        "effort": "Medium",
        "fix_steps": (
            "First redirect http://this-host/ to https://this-host/ with 301 or 308.\n"
            "Only after HTTPS on this host, move users to another hostname if needed.\n"
            "That lets HSTS apply to this name."
        ),
        "snippet_nginx": (
            "server {\n"
            "  listen 80;\n"
            "  server_name old.example.com;\n"
            "  return 301 https://old.example.com$request_uri;\n"
            "}\n"
            "# Separate HTTPS server_name old.example.com can then 301 to the final host."
        ),
        "snippet_apache": (
            "# On the HTTP vhost for this host only:\n"
            "RewriteEngine On\n"
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <rewrite>\n"
            "      <rules>\n"
            "        <rule name=\"SameHostHttpsFirst\" stopProcessing=\"true\">\n"
            "          <match url=\"(.*)\" />\n"
            "          <conditions>\n"
            "            <add input=\"{HTTPS}\" pattern=\"off\" />\n"
            "          </conditions>\n"
            "          <action type=\"Redirect\" url=\"https://{HTTP_HOST}/{R:1}\" redirectType=\"Permanent\" />\n"
            "        </rule>\n"
            "      </rules>\n"
            "    </rewrite>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Create a Redirect Rule that upgrades http://current-host to https://current-host first.\n"
            "Put any hostname-change rule after that, matching https only."
        ),
    },
    "X-Content-Type-Options is missing or not nosniff": {
        "importance": "Medium",
        "effort": "Easy",
        "fix_steps": (
            "Send X-Content-Type-Options: nosniff on all responses.\n"
            "Keep Content-Type accurate so nosniff does not break downloads.\n"
            "Verify with a single response header check."
        ),
        "snippet_nginx": (
            "add_header X-Content-Type-Options \"nosniff\" always;"
        ),
        "snippet_apache": (
            "Header always set X-Content-Type-Options \"nosniff\""
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Transform Rules → Modify Response Header: set X-Content-Type-Options to nosniff."
        ),
    },
    "Referrer-Policy is not a strict value": {
        "importance": "Medium",
        "effort": "Easy",
        "fix_steps": (
            "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).\n"
            "Prefer no-referrer or same-origin for highly sensitive apps.\n"
            "Confirm analytics still work with the new policy."
        ),
        "snippet_nginx": (
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
        ),
        "snippet_apache": (
            "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
        ),
        "snippet_iis": (
            "<configuration>\n"
            "  <system.webServer>\n"
            "    <httpProtocol>\n"
            "      <customHeaders>\n"
            "        <add name=\"Referrer-Policy\" value=\"strict-origin-when-cross-origin\" />\n"
            "      </customHeaders>\n"
            "    </httpProtocol>\n"
            "  </system.webServer>\n"
            "</configuration>"
        ),
        "snippet_cloudflare": (
            "Transform Rules → Modify Response Header: set Referrer-Policy to strict-origin-when-cross-origin."
        ),
    },
}


def is_fix_target(tags: list[str] | None, title: str = "") -> bool:
    """True when a library writeup is header / TLS / cookie / CSP scoped."""
    tagset = {str(t).lower() for t in (tags or [])}
    if tagset & {"dns", "email", "dmarc", "dkim", "mta-sts", "tls-rpt", "dnssec"}:
        return False
    if tagset & FIX_TAGS:
        return True
    low = (title or "").lower()
    return any(
        k in low
        for k in (
            "content security policy",
            "hsts",
            "cookie",
            "x-content-type",
            "referrer-policy",
            "x-frame",
            "mixed content",
        )
    )


def enrich(item: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a seed item with fix fields filled from BY_TITLE when present."""
    out = dict(item)
    extra = BY_TITLE.get(out.get("title", ""))
    if not extra:
        for k in FIX_FIELD_KEYS:
            out.setdefault(k, "")
        return out
    for k in FIX_FIELD_KEYS:
        out[k] = extra.get(k, out.get(k, "")) or ""
    return out


def guidance_from_mapping(data: dict[str, Any] | Any) -> dict[str, Any]:
    """Normalize fix fields from a LibraryEntry or seed dict."""
    def _get(key: str) -> str:
        if isinstance(data, dict):
            return str(data.get(key) or "").strip()
        return str(getattr(data, key, "") or "").strip()

    snippets = {k: _get(f"snippet_{k}") for k in SNIPPET_KEYS}
    return {
        "importance": _get("importance"),
        "effort": _get("effort"),
        "fix_steps": _get("fix_steps"),
        "snippets": snippets,
        "snippet_nginx": snippets["nginx"],
        "snippet_apache": snippets["apache"],
        "snippet_iis": snippets["iis"],
        "snippet_cloudflare": snippets["cloudflare"],
    }


def has_fix_content(guidance: dict[str, Any] | None) -> bool:
    if not guidance:
        return False
    if guidance.get("importance") or guidance.get("effort") or guidance.get("fix_steps"):
        return True
    return any((guidance.get("snippets") or {}).values())


def detect_server_type(*texts: str) -> str | None:
    """Return nginx / apache / iis / cloudflare when clearly mentioned, else None."""
    blob = " ".join(t for t in texts if t).lower()
    if not blob:
        return None
    patterns = (
        ("cloudflare", r"\bcloudflare\b"),
        ("nginx", r"\bnginx\b"),
        ("apache", r"\bapache\b|\bhttpd\b"),
        ("iis", r"\biis\b|\bmicrosoft-iis\b|\bweb\.config\b"),
    )
    hits = [name for name, pat in patterns if re.search(pat, blob)]
    if len(hits) == 1:
        return hits[0]
    return None


def snippets_for_report(guidance: dict[str, Any], server_type: str | None) -> list[tuple[str, str]]:
    """Pick snippets for a report: known server only, else nginx + Apache."""
    snippets = guidance.get("snippets") or {}
    if server_type and snippets.get(server_type):
        return [(server_type, snippets[server_type])]
    out = []
    for key in ("nginx", "apache"):
        text = snippets.get(key) or ""
        if text:
            out.append((key, text))
    return out


def empty_fix_fields() -> dict[str, str]:
    return {k: "" for k in FIX_FIELD_KEYS}


def api_fix_fields(guidance: dict[str, Any] | None) -> dict[str, str]:
    """Flat fields for API finding output (always present, may be empty)."""
    base = empty_fix_fields()
    if not guidance:
        return base
    base["importance"] = str(guidance.get("importance") or "")
    base["effort"] = str(guidance.get("effort") or "")
    base["fix_steps"] = str(guidance.get("fix_steps") or "")
    snippets = guidance.get("snippets") or {}
    for key in SNIPPET_KEYS:
        base[f"snippet_{key}"] = str(snippets.get(key) or "")
    return base


def nginx_lines_ok(text: str) -> bool:
    """Heuristic: non-comment nginx directive lines end with ';'."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s in ("{", "}"):
            continue
        if s.endswith("{") or s.endswith("}"):
            continue
        if not s.endswith(";"):
            return False
    return True


def iis_xml_ok(text: str) -> bool:
    """IIS snippets should parse as XML (fragment wrapped if needed)."""
    body = text.strip()
    if not body:
        return False
    # Allow a leading comment-only preface before <configuration>.
    start = body.find("<")
    if start < 0:
        return False
    try:
        ET.fromstring(body[start:])
    except ET.ParseError:
        return False
    return True


def match_seed_guidance(finding: Any) -> dict[str, Any] | None:
    """Best built-in SEED guidance for a finding (rule id, then CWE, then title)."""
    from attestra.library.seed import SEED

    rules = {str(r).lower() for r in (getattr(finding, "rule_ids", None) or [])}
    tools = {str(t).lower() for t in (getattr(finding, "tools", None) or [])}
    keys = rules | {f"{t}:{r}" for t in tools for r in rules}
    cwe = getattr(finding, "cwe", None)
    title = (getattr(finding, "title", "") or "").lower()

    scored: list[tuple[int, str, dict]] = []
    for raw in SEED:
        item = enrich(raw)
        if not is_fix_target(item.get("tags"), item.get("title", "")):
            continue
        if not has_fix_content(guidance_from_mapping(item)):
            continue
        score = 0
        item_rules = {r.lower() for r in (item.get("rule_ids") or [])}
        if keys and keys & item_rules:
            score += 2
        if cwe and item.get("cwe") == cwe:
            score += 1
        if title and title == (item.get("title") or "").lower():
            score += 2
        elif title and (item.get("title") or "").lower() in title:
            score += 1
        if score:
            scored.append((-score, item["title"], item))
    if not scored:
        return None
    scored.sort(key=lambda t: (t[0], t[1]))
    return guidance_from_mapping(scored[0][2])
