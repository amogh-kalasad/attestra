"""World-Class Phase 7 remediation packs keyed by concept.

Concept keys align with ``crossmerge.CONCEPT_RULES`` / finding_normalize where
those exist. App-level packs (IDOR, SQLi, reflected XSS) use title patterns.
"""

from __future__ import annotations

from typing import Any

# @lat: [[findings#Remediation packs (Phase 7)]]

Pack = dict[str, Any]

REMEDIATION_PACKS: dict[str, Pack] = {
    "header:hsts-missing": {
        "concept": "header:hsts-missing",
        "title_match": [
            "strict-transport-security header not set",
            "hsts missing",
            "missing hsts",
            "http strict transport security",
            "strict-transport-security",
        ],
        "root_cause": (
            "Responses over HTTPS do not send Strict-Transport-Security, so browsers "
            "may still attempt plain HTTP on later visits and are more exposed to "
            "SSL-stripping or captive-portal downgrade attacks."
        ),
        "recommended_fix": (
            "Send Strict-Transport-Security only on HTTPS responses. Start with "
            "max-age=31536000; includeSubDomains after every subdomain supports HTTPS. "
            "Add preload only after all subdomains are HTTPS-ready and you intend to "
            "submit to the HSTS preload list."
        ),
        "config_examples": {
            "nginx": (
                'add_header Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains" always;'
            ),
            "apache": (
                'Header always set Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains"'
            ),
            "iis": (
                "<configuration>\n"
                "  <system.webServer>\n"
                "    <httpProtocol>\n"
                "      <customHeaders>\n"
                '        <add name="Strict-Transport-Security" '
                'value="max-age=31536000; includeSubDomains" />\n'
                "      </customHeaders>\n"
                "    </httpProtocol>\n"
                "  </system.webServer>\n"
                "</configuration>"
            ),
            "cloudflare": (
                "SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS): "
                "enable; set max-age ≥ 12 months; include subdomains when ready; "
                "enable preload only after all subdomains are HTTPS."
            ),
        },
        "compatibility": (
            "HSTS applies only to HTTPS. Enabling includeSubDomains or preload on "
            "hosts that still need HTTP will break those subdomains until they support TLS."
        ),
        "verification_steps": (
            "curl -sI https://example.com | grep -i strict-transport-security; "
            "confirm max-age and that the header is absent on plain HTTP."
        ),
        "retest_instructions": (
            "Re-request the same HTTPS URL; confirm HSTS is present with the intended "
            "directives and that browsers no longer offer an HTTP first hop for the host."
        ),
        "importance": "High",
        "effort": "Easy",
    },
    "header:csp-missing": {
        "concept": "header:csp-missing",
        "title_match": [
            "content security policy (csp) header not set",
            "content-security-policy header not set",
            "csp header not set",
            "missing content security policy",
            "missing csp",
        ],
        "root_cause": (
            "No Content-Security-Policy header is set, so the browser has no "
            "declarative allow-list for scripts, frames, and other resource types."
        ),
        "recommended_fix": (
            "Roll out Content-Security-Policy-Report-Only first, collect violations, "
            "then enforce. Prefer default-src 'self'; avoid unsafe-inline/unsafe-eval; "
            "use nonces or hashes for scripts when possible."
        ),
        "config_examples": {
            "nginx": (
                "# Prefer Report-Only while tuning, then rename to Content-Security-Policy.\n"
                'add_header Content-Security-Policy-Report-Only '
                "\"default-src 'self'; object-src 'none'; base-uri 'self'; "
                "frame-ancestors 'self'; img-src 'self' data:\" always;"
            ),
            "apache": (
                "# Prefer Report-Only while tuning, then switch to Content-Security-Policy.\n"
                "Header always set Content-Security-Policy-Report-Only "
                "\"default-src 'self'; object-src 'none'; base-uri 'self'; "
                "frame-ancestors 'self'; img-src 'self' data:\""
            ),
            "iis": (
                "<configuration>\n"
                "  <system.webServer>\n"
                "    <httpProtocol>\n"
                "      <customHeaders>\n"
                '        <add name="Content-Security-Policy-Report-Only" '
                "value=\"default-src 'self'; object-src 'none'; base-uri 'self'; "
                "frame-ancestors 'self'; img-src 'self' data:\" />\n"
                "      </customHeaders>\n"
                "    </httpProtocol>\n"
                "  </system.webServer>\n"
                "</configuration>"
            ),
            "cloudflare": (
                "Transform Rules → Modify Response Header: set "
                "Content-Security-Policy-Report-Only, then switch to "
                "Content-Security-Policy after violations are clean."
            ),
            "app": (
                "Set the CSP (or Report-Only) header in the application response "
                "middleware so it applies consistently across origins and CDNs."
            ),
        },
        "compatibility": (
            "Strict CSP can break inline scripts, third-party widgets, and older "
            "analytics until nonces/hashes or allow-listed hosts are configured."
        ),
        "verification_steps": (
            "Inspect response headers for Content-Security-Policy (or Report-Only); "
            "confirm directives match the intended policy and report-uri/report-to if used."
        ),
        "retest_instructions": (
            "Re-scan the URL; confirm CSP is present and that previously failing "
            "missing-CSP checks clear. Spot-check critical UI flows for regressions."
        ),
        "importance": "High",
        "effort": "Hard",
    },
    "header:csp-weak": {
        "concept": "header:csp-weak",
        "title_match": [
            "csp: script-src unsafe-inline",
            "csp: script-src unsafe-eval",
            "csp: style-src unsafe-inline",
            "unsafe-inline",
            "unsafe-eval",
            "weak content security policy",
            "weak csp",
        ],
        "root_cause": (
            "A Content-Security-Policy is present but uses weak directives "
            "(for example script-src 'unsafe-inline' or 'unsafe-eval'), which "
            "largely defeats XSS containment."
        ),
        "recommended_fix": (
            "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. Prefer "
            "nonces or hashes; tighten object-src 'none' and base-uri 'self'. "
            "Iterate with Report-Only before enforcing."
        ),
        "config_examples": {
            "nginx": (
                'add_header Content-Security-Policy '
                "\"default-src 'self'; script-src 'self' 'nonce-REPLACE'; "
                "object-src 'none'; base-uri 'self'\" always;"
            ),
            "apache": (
                "Header always set Content-Security-Policy "
                "\"default-src 'self'; script-src 'self' 'nonce-REPLACE'; "
                "object-src 'none'; base-uri 'self'\""
            ),
            "app": (
                "Generate a per-response nonce, attach it to script tags, and put "
                "the same nonce in script-src. Do not fall back to unsafe-inline."
            ),
        },
        "code_example": (
            "# Pseudocode: per-response nonce\n"
            "nonce = secrets.token_urlsafe(16)\n"
            "response.headers['Content-Security-Policy'] = (\n"
            "    f\"default-src 'self'; script-src 'self' 'nonce-{nonce}'\"\n"
            ")\n"
            '# Render: <script nonce="{nonce}">...</script>'
        ),
        "compatibility": (
            "Removing unsafe-inline breaks pages that still inject inline event "
            "handlers or style attributes; migrate those to external files or nonces."
        ),
        "verification_steps": (
            "Confirm CSP no longer contains unsafe-inline/unsafe-eval for scripts; "
            "load the app and check the browser console for CSP violations."
        ),
        "retest_instructions": (
            "Re-run the CSP weakness check; confirm the weak directive finding is gone "
            "and UI flows still work under the tightened policy."
        ),
        "importance": "High",
        "effort": "Hard",
    },
    "header:coep-missing": {
        "concept": "header:coep-missing",
        "title_match": [
            "cross-origin-embedder-policy header missing",
            "cross-origin-embedder-policy",
            "coep missing",
            "missing coep",
        ],
        "root_cause": (
            "Cross-Origin-Embedder-Policy is not set, so the document cannot opt into "
            "cross-origin isolation required for powerful features (for example "
            "SharedArrayBuffer) and stronger Spectre mitigations."
        ),
        "recommended_fix": (
            "Send Cross-Origin-Embedder-Policy: require-corp (or credentialless where "
            "supported) on documents that need cross-origin isolation. Ensure embedded "
            "cross-origin resources send a compatible CORP/CORS policy."
        ),
        "config_examples": {
            "nginx": 'add_header Cross-Origin-Embedder-Policy "require-corp" always;',
            "apache": 'Header always set Cross-Origin-Embedder-Policy "require-corp"',
            "iis": (
                "<add name=\"Cross-Origin-Embedder-Policy\" value=\"require-corp\" />"
            ),
            "cloudflare": (
                "Transform Rules → Modify Response Header: set "
                "Cross-Origin-Embedder-Policy to require-corp (or credentialless)."
            ),
        },
        "compatibility": (
            "require-corp blocks cross-origin subresources that lack CORP or CORS. "
            "Audit images, scripts, fonts, and embeds before enabling site-wide."
        ),
        "verification_steps": (
            "curl -sI https://example.com | grep -i cross-origin-embedder-policy; "
            "in DevTools Application/Frame check crossOriginIsolated where required."
        ),
        "retest_instructions": (
            "Confirm Cross-Origin-Embedder-Policy is present and that critical "
            "third-party assets still load under the chosen policy."
        ),
        "importance": "Medium",
        "effort": "Medium",
    },
    "header:coop-missing": {
        "concept": "header:coop-missing",
        "title_match": [
            "cross-origin-opener-policy header missing",
            "cross-origin-opener-policy",
            "coop missing",
            "missing coop",
        ],
        "root_cause": (
            "Cross-Origin-Opener-Policy is not set, so cross-origin window.open / "
            "OAuth popups may retain a reference to your browsing context "
            "(window.opener), enabling cross-origin interaction attacks."
        ),
        "recommended_fix": (
            "Send Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups "
            "when popup flows must keep a limited opener relationship)."
        ),
        "config_examples": {
            "nginx": 'add_header Cross-Origin-Opener-Policy "same-origin" always;',
            "apache": 'Header always set Cross-Origin-Opener-Policy "same-origin"',
            "iis": '<add name="Cross-Origin-Opener-Policy" value="same-origin" />',
            "cloudflare": (
                "Transform Rules → Modify Response Header: set "
                "Cross-Origin-Opener-Policy to same-origin."
            ),
        },
        "compatibility": (
            "same-origin severs window.opener across origins and can break OAuth or "
            "payment popups that rely on opener messaging; use "
            "same-origin-allow-popups when those flows are required."
        ),
        "verification_steps": (
            "Inspect response headers for Cross-Origin-Opener-Policy; exercise "
            "login/OAuth popups if you use same-origin-allow-popups."
        ),
        "retest_instructions": (
            "Confirm COOP is present with the intended value and that intentional "
            "cross-window flows still succeed."
        ),
        "importance": "Medium",
        "effort": "Easy",
    },
    "header:corp-missing": {
        "concept": "header:corp-missing",
        "title_match": [
            "cross-origin-resource-policy header missing",
            "cross-origin-resource-policy",
            "corp missing",
            "missing corp",
        ],
        "root_cause": (
            "Cross-Origin-Resource-Policy is not set on sensitive responses, so other "
            "origins may embed or read certain resource types depending on browser "
            "defaults and COEP requirements."
        ),
        "recommended_fix": (
            "Send Cross-Origin-Resource-Policy: same-origin for private resources, "
            "or same-site / cross-origin when intentional sharing is required "
            "(especially when pairing with COEP require-corp)."
        ),
        "config_examples": {
            "nginx": 'add_header Cross-Origin-Resource-Policy "same-origin" always;',
            "apache": 'Header always set Cross-Origin-Resource-Policy "same-origin"',
            "iis": '<add name="Cross-Origin-Resource-Policy" value="same-origin" />',
            "cloudflare": (
                "Transform Rules → Modify Response Header: set "
                "Cross-Origin-Resource-Policy to same-origin (or cross-origin for public assets)."
            ),
        },
        "compatibility": (
            "same-origin CORP will block other sites from embedding the resource; "
            "public CDNs and intentionally shareable assets may need cross-origin."
        ),
        "verification_steps": (
            "Confirm Cross-Origin-Resource-Policy on document and asset responses; "
            "verify embeds that should work still load."
        ),
        "retest_instructions": (
            "Re-check headers and any COEP-dependent pages; confirm no unintended "
            "cross-origin embedding of private resources."
        ),
        "importance": "Medium",
        "effort": "Easy",
    },
    "header:permissions-policy-missing": {
        "concept": "header:permissions-policy-missing",
        "title_match": [
            "permissions policy header not set",
            "permissions-policy header",
            "permissions-policy",
            "permissions policy",
            "feature-policy header not set",
        ],
        "root_cause": (
            "No Permissions-Policy header is set, so powerful browser features "
            "(camera, microphone, geolocation, payment, etc.) remain available to "
            "this document and nested browsing contexts by default."
        ),
        "recommended_fix": (
            "Send a Permissions-Policy that disables unused powerful features "
            "(for example camera=(), microphone=(), geolocation=()) and explicitly "
            "allow-lists only origins that need a given feature."
        ),
        "config_examples": {
            "nginx": (
                'add_header Permissions-Policy '
                '"camera=(), microphone=(), geolocation=(), payment=()" always;'
            ),
            "apache": (
                "Header always set Permissions-Policy "
                '"camera=(), microphone=(), geolocation=(), payment=()"'
            ),
            "iis": (
                "<configuration>\n"
                "  <system.webServer>\n"
                "    <httpProtocol>\n"
                "      <customHeaders>\n"
                '        <add name="Permissions-Policy" '
                'value="camera=(), microphone=(), geolocation=(), payment=()" />\n'
                "      </customHeaders>\n"
                "    </httpProtocol>\n"
                "  </system.webServer>\n"
                "</configuration>"
            ),
            "cloudflare": (
                "Transform Rules → Modify Response Header: set Permissions-Policy to "
                "camera=(), microphone=(), geolocation=(), payment=() (adjust allow-lists)."
            ),
            "app": (
                "Set the Permissions-Policy response header in application middleware "
                "so feature gates stay with the app rather than only the edge."
            ),
        },
        "compatibility": (
            "Denying a feature that the product legitimately uses (for example "
            "geolocation or payment) will break that UX until an allow-list is added."
        ),
        "verification_steps": (
            "curl -sI https://example.com | grep -i permissions-policy; "
            "confirm only intended features are allowed."
        ),
        "retest_instructions": (
            "Confirm Permissions-Policy is present with the intended directives and "
            "that product features that need a capability still work."
        ),
        "importance": "Medium",
        "effort": "Easy",
    },
    "header:xss-protection-deprecated": {
        "concept": "header:xss-protection-deprecated",
        "title_match": [
            "x-xss-protection",
            "xss protection header",
            "xss-protection",
            "deprecated xss protection",
        ],
        "root_cause": (
            "The X-XSS-Protection header is obsolete. Modern browsers ignore it or "
            "have removed the XSS auditor; keeping a non-zero value can create "
            "unexpected filtering side effects and does not fix XSS vulnerabilities."
        ),
        "recommended_fix": (
            "Remove the X-XSS-Protection header, or set it explicitly to 0. Do not "
            "treat this finding as an XSS vulnerability fix — use output encoding "
            "and Content-Security-Policy for XSS defense in depth."
        ),
        "config_examples": {
            "nginx": (
                "# Prefer removing the header entirely.\n"
                'add_header X-XSS-Protection "0" always;'
            ),
            "apache": (
                "# Prefer unsetting any inherited X-XSS-Protection.\n"
                'Header always set X-XSS-Protection "0"'
            ),
            "iis": (
                "Remove any custom X-XSS-Protection entry, or set value=\"0\"."
            ),
            "cloudflare": (
                "Transform Rules → Modify Response Header: remove X-XSS-Protection, "
                "or set it to 0."
            ),
        },
        "compatibility": (
            "Setting 0 or removing the header is safe on current browsers. This change "
            "does not remediate reflected or stored XSS by itself."
        ),
        "verification_steps": (
            "Confirm X-XSS-Protection is absent or equals 0; do not expect this alone "
            "to clear real XSS findings."
        ),
        "retest_instructions": (
            "Re-check response headers for X-XSS-Protection. Separately retest any "
            "actual XSS findings after encoding/CSP fixes."
        ),
        "importance": "Low",
        "effort": "Easy",
    },
    "cors:misconfiguration": {
        "concept": "cors:misconfiguration",
        "title_match": [
            "cross-domain misconfiguration",
            "cors misconfiguration",
            "cross-origin resource sharing",
            "access-control-allow-origin",
        ],
        "root_cause": (
            "Cross-Origin Resource Sharing is configured too permissively (for "
            "example reflecting arbitrary Origins with credentials, or allowing "
            "untrusted origins to read authenticated responses)."
        ),
        "recommended_fix": (
            "Allow only explicit trusted origins. Never combine "
            "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. "
            "Validate Origin against an allow-list before echoing it."
        ),
        "config_examples": {
            "nginx": (
                "# Example: fixed trusted origin (prefer app-level allow-list).\n"
                'add_header Access-Control-Allow-Origin "https://app.example.com" always;\n'
                'add_header Vary "Origin" always;'
            ),
            "apache": (
                'Header always set Access-Control-Allow-Origin "https://app.example.com"\n'
                'Header always set Vary "Origin"'
            ),
            "app": (
                "Maintain an allow-list of origins; if request Origin is listed, set "
                "Access-Control-Allow-Origin to that exact value and Vary: Origin. "
                "Omit credentials unless required."
            ),
        },
        "code_example": (
            "ALLOWED = {'https://app.example.com'}\n"
            "origin = request.headers.get('Origin')\n"
            "if origin in ALLOWED:\n"
            "    response.headers['Access-Control-Allow-Origin'] = origin\n"
            "    response.headers['Vary'] = 'Origin'\n"
            "    # Only if cookies/auth headers must cross origin:\n"
            "    # response.headers['Access-Control-Allow-Credentials'] = 'true'"
        ),
        "compatibility": (
            "Tightening CORS can break legitimate SPAs or partner integrations that "
            "relied on a wildcard or reflected Origin; update those clients' origins "
            "in the allow-list."
        ),
        "verification_steps": (
            "Send requests with trusted and untrusted Origin values; confirm only "
            "allow-listed origins receive ACAO and that * is never paired with credentials."
        ),
        "retest_instructions": (
            "Re-run CORS checks with an untrusted Origin; confirm no ACAO reflection "
            "and that authenticated cross-origin reads fail as expected."
        ),
        "importance": "High",
        "effort": "Medium",
    },
    "cors:acao-wildcard": {
        "concept": "cors:acao-wildcard",
        "title_match": [
            "acao wildcard",
            "access-control-allow-origin: *",
            "allow-origin wildcard",
            "cors wildcard",
        ],
        "root_cause": (
            "Access-Control-Allow-Origin is set to * (or effectively allows any "
            "origin), which lets any website read the response when credentials "
            "are not required — often unintended for authenticated or sensitive APIs."
        ),
        "recommended_fix": (
            "Replace * with an explicit Origin allow-list. If public cacheable "
            "content truly needs *, ensure responses contain no sensitive data and "
            "do not enable credentials."
        ),
        "config_examples": {
            "nginx": (
                "# Do not use * for authenticated APIs.\n"
                'add_header Access-Control-Allow-Origin "https://app.example.com" always;\n'
                'add_header Vary "Origin" always;'
            ),
            "apache": (
                'Header always set Access-Control-Allow-Origin "https://app.example.com"\n'
                'Header always set Vary "Origin"'
            ),
            "cloudflare": (
                "Replace any Transform Rule that sets ACAO to *; use a specific "
                "trusted origin or handle CORS at the origin app."
            ),
            "app": (
                "Echo only allow-listed Origins; never send ACAO: * on responses that "
                "include session data or PII."
            ),
        },
        "compatibility": (
            "Removing * breaks anonymous cross-origin readers that depended on it; "
            "document which public endpoints remain intentionally open."
        ),
        "verification_steps": (
            "Confirm ACAO is not * on sensitive endpoints; test preflight and simple "
            "requests from an untrusted origin."
        ),
        "retest_instructions": (
            "Re-scan CORS/wildcard templates; confirm untrusted origins no longer "
            "receive a usable ACAO on sensitive responses."
        ),
        "importance": "High",
        "effort": "Medium",
    },
    "cookie:samesite-none": {
        "concept": "cookie:samesite-none",
        "title_match": [
            "cookie with samesite attribute none",
            "samesite attribute none",
            "samesite=none",
            "samesite none",
        ],
        "root_cause": (
            "A cookie is set with SameSite=None, so it is sent on cross-site "
            "requests (when Secure is also set). That increases CSRF and "
            "cross-site leak risk if the cookie is a session or auth token."
        ),
        "recommended_fix": (
            "Prefer SameSite=Lax or Strict for session cookies. Use SameSite=None; "
            "Secure only when a deliberate cross-site flow requires it, and pair "
            "with CSRF tokens / additional auth checks."
        ),
        "config_examples": {
            "nginx": (
                "# Prefer setting flags in the app. Proxy sketch:\n"
                'proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";'
            ),
            "apache": (
                'Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"'
            ),
            "app": (
                "Set session cookies with Secure; HttpOnly; SameSite=Lax (or Strict). "
                "Reserve SameSite=None for known cross-site embed/auth cases only."
            ),
        },
        "code_example": (
            "response.set_cookie(\n"
            "    'session',\n"
            "    value,\n"
            "    secure=True,\n"
            "    httponly=True,\n"
            "    samesite='Lax',\n"
            ")"
        ),
        "compatibility": (
            "Moving from None to Lax/Strict can break embedded iframes, SSO, or "
            "third-party payment widgets that relied on cross-site cookie sends."
        ),
        "verification_steps": (
            "Inspect Set-Cookie on login; confirm SameSite is Lax/Strict unless a "
            "documented cross-site case requires None; Secure must be present with None."
        ),
        "retest_instructions": (
            "Re-login and capture Set-Cookie; confirm SameSite change and that "
            "legitimate cross-site flows still work."
        ),
        "importance": "High",
        "effort": "Medium",
    },
    "cookie:samesite": {
        "concept": "cookie:samesite",
        "title_match": [
            "cookie without samesite attribute",
            "missing samesite",
            "samesite attribute",
        ],
        "root_cause": (
            "A cookie is issued without an explicit SameSite attribute. Browser "
            "defaults vary; older clients may treat the cookie as available on "
            "some cross-site requests, increasing CSRF risk."
        ),
        "recommended_fix": (
            "Set SameSite=Lax (or Strict) on session cookies together with Secure "
            "and HttpOnly. Set flags in the application cookie API, not only at "
            "the reverse proxy."
        ),
        "config_examples": {
            "nginx": (
                "# Prefer app-level flags. Proxy example (use with care):\n"
                'proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";'
            ),
            "apache": (
                'Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"'
            ),
            "iis": (
                "Prefer app-level cookie flags; outbound rewrite of Set-Cookie can "
                "append Secure; HttpOnly; SameSite=Lax when necessary."
            ),
            "cloudflare": (
                "Cloudflare cannot fully set origin session flags. Configure "
                "SameSite in the application; use Transform Rules only for CDN-owned cookies."
            ),
            "app": (
                "Mark every session cookie Secure; HttpOnly; SameSite=Lax "
                "(or Strict if the app allows)."
            ),
        },
        "code_example": (
            "response.set_cookie(\n"
            "    'session',\n"
            "    value,\n"
            "    secure=True,\n"
            "    httponly=True,\n"
            "    samesite='Lax',\n"
            ")"
        ),
        "compatibility": (
            "Explicit SameSite is widely supported; Strict can break top-level "
            "cross-site GET navigations that expect a session cookie."
        ),
        "verification_steps": (
            "Capture Set-Cookie after authentication; confirm SameSite is present "
            "with the intended value."
        ),
        "retest_instructions": (
            "Re-authenticate and confirm the cookie includes SameSite; retest CSRF "
            "protections on state-changing endpoints."
        ),
        "importance": "High",
        "effort": "Easy",
    },
    "tls:weak-cipher": {
        "concept": "tls:weak-cipher",
        "title_match": [
            "weak cipher",
            "weak cipher suite",
            "weak-cipher-suites",
            "cipher suite",
        ],
        "root_cause": (
            "The TLS stack offers weak or obsolete cipher suites (for example "
            "NULL, EXPORT, RC4, 3DES, or non-AEAD suites), which weaken "
            "confidentiality or integrity of the channel."
        ),
        "recommended_fix": (
            "Disable weak suites; prefer TLS 1.2+ with AEAD ciphers "
            "(AES-GCM / ChaCha20-Poly1305) and modern key exchange (ECDHE). "
            "Disable TLS 1.0/1.1 and SSL where still enabled."
        ),
        "config_examples": {
            "nginx": (
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_ciphers "
                "'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                "TLS_CHACHA20_POLY1305_SHA256:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\n"
                "ssl_prefer_server_ciphers off;"
            ),
            "apache": (
                "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                "SSLCipherSuite "
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
                "SSLHonorCipherOrder off"
            ),
            "cloudflare": (
                "SSL/TLS → Edge Certificates → Minimum TLS Version: 1.2; "
                "disable legacy cipher suites if the plan exposes that control."
            ),
        },
        "compatibility": (
            "Removing legacy ciphers can block very old clients (legacy Java, "
            "old POS devices). Inventory dependencies before tightening."
        ),
        "verification_steps": (
            "Re-scan with testssl/ssllabs/nuclei; confirm weak suites are absent "
            "and only modern AEAD suites remain."
        ),
        "retest_instructions": (
            "Confirm the weak-cipher finding clears and that primary clients still "
            "negotiate TLS 1.2 or 1.3 successfully."
        ),
        "importance": "High",
        "effort": "Medium",
    },
    "authz:idor": {
        "concept": "authz:idor",
        "title_match": [
            "idor",
            "insecure direct object",
            "broken object level authorization",
            "bola",
            "horizontal privilege",
            "object access control",
            "direct object reference",
        ],
        "root_cause": (
            "The server trusts a client-supplied object identifier (ID, slug, "
            "filename) without verifying that the authenticated principal is "
            "authorized to access that object (IDOR / BOLA)."
        ),
        "recommended_fix": (
            "Enforce server-side object authorization on every read and write: "
            "after authentication, load the object and verify ownership or role "
            "grants before returning or mutating it. Prefer opaque IDs and "
            "centralized authorization checks; never rely on hiding URLs alone."
        ),
        "config_examples": {
            "app": (
                "Apply a shared authorization helper/middleware on all object "
                "routes (GET/PUT/PATCH/DELETE). Deny by default when the "
                "resource is missing or not owned by the caller."
            ),
        },
        "code_example": (
            "# Pseudocode: server-side object authorization\n"
            "obj = db.get_order(order_id)\n"
            "if obj is None or obj.owner_id != current_user.id:\n"
            "    raise Forbidden()  # same response for missing vs unauthorized\n"
            "return obj"
        ),
        "compatibility": (
            "Centralizing authorization may change error codes (404 vs 403); "
            "keep responses consistent to avoid user/object enumeration."
        ),
        "verification_steps": (
            "As user A, request user B's object IDs; expect 403/404. Repeat for "
            "create/update/delete. Cover horizontal and vertical privilege cases."
        ),
        "retest_instructions": (
            "Replay the original IDOR proof with swapped object IDs across roles; "
            "confirm authorization denies access and no sensitive body is returned."
        ),
        "importance": "High",
        "effort": "Medium",
    },
    "injection:sqli": {
        "concept": "injection:sqli",
        "title_match": [
            "sql injection",
            "sqli",
            "sql query",
            "cwe-89",
        ],
        "root_cause": (
            "Untrusted input is concatenated into SQL statements, allowing "
            "attackers to alter query logic (SQL injection)."
        ),
        "recommended_fix": (
            "Use parameterized queries / prepared statements / bind variables "
            "for all untrusted input. Avoid building SQL with string "
            "concatenation or format strings. Prefer a vetted ORM query API; "
            "whitelist any dynamic identifiers (table/column names)."
        ),
        "config_examples": {
            "app": (
                "Ban raw string-built SQL in code review. Use the driver's "
                "parameter API or ORM filters. Escaping is not a substitute "
                "for parameterization."
            ),
        },
        "code_example": (
            "# Bad: cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "# Good:\n"
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
            "# ORM example:\n"
            "session.query(User).filter(User.id == user_id).one_or_none()"
        ),
        "compatibility": (
            "Migrating to bound parameters is compatible with all major databases; "
            "dynamic ORDER BY/LIMIT still need allow-lists, not bind parameters alone."
        ),
        "verification_steps": (
            "Confirm the vulnerable sink uses binds; retest classic payloads "
            "(' OR '1'='1, boolean/time probes) and confirm they no longer alter logic."
        ),
        "retest_instructions": (
            "Replay the original SQLi evidence with parameterization in place; "
            "confirm no data leakage or authentication bypass."
        ),
        "importance": "High",
        "effort": "Medium",
    },
    "xss:reflected": {
        "concept": "xss:reflected",
        "title_match": [
            "reflected xss",
            "reflected cross-site",
            "cross-site scripting",
            "xss vulnerability",
            "cwe-79",
        ],
        "root_cause": (
            "Untrusted request data is reflected into HTML (or related contexts) "
            "without context-appropriate encoding, allowing script execution in "
            "the victim's browser."
        ),
        "recommended_fix": (
            "Encode output for the sink context (HTML body, attribute, JS, URL). "
            "Prefer framework auto-escaping templates; never mark untrusted data "
            "as safe HTML. Add a strict Content-Security-Policy as defense in depth "
            "(separate from the obsolete X-XSS-Protection header)."
        ),
        "config_examples": {
            "app": (
                "Use contextual encoding helpers for every reflection point. "
                "CSP with nonces/hashes reduces impact if an encoding bug remains."
            ),
        },
        "code_example": (
            "# Template auto-escape (keep enabled):\n"
            "{{ user_input }}  # HTML-escaped\n"
            "# Attribute context: use attr-aware encoding\n"
            "# JS context: JSON-serialize into a script type=application/json block\n"
            "# Do not use |safe / dangerouslySetInnerHTML on untrusted data"
        ),
        "compatibility": (
            "Encoding can change display of intentional HTML; introduce a vetted "
            "sanitizer only for rich-text fields that must allow a subset of markup."
        ),
        "verification_steps": (
            "Resubmit the reflected payload; confirm it appears encoded in the DOM "
            "and does not execute. Check CSP is present as defense in depth."
        ),
        "retest_instructions": (
            "Replay the original XSS proof (and nearby parameters); confirm no "
            "script execution and that encoding remains correct across browsers."
        ),
        "importance": "High",
        "effort": "Medium",
    },
}


def pack_for_concept(concept: str) -> Pack | None:
    """Return the remediation pack for an exact concept key, or None."""
    if not concept:
        return None
    pack = REMEDIATION_PACKS.get(str(concept).strip())
    return dict(pack) if pack else None
