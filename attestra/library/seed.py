"""Built-in starter writeups (OWASP Top 10 style), written for Attestra.

Tenants copy these with ``seed_defaults`` and then edit their own copies.
"""

from __future__ import annotations

SEED: list[dict] = [
    {
        "title": "SQL injection",
        "cwe": 89,
        "default_severity": "critical",
        "tags": [
            "injection",
            "owasp-a03"
        ],
        "rule_ids": [
            "zap:40018",
            "zap:40019",
            "zap:40024"
        ],
        "description": "User-supplied input reaches a database query without being bound as a parameter, so the input can change the structure of the query.",
        "impact": "An attacker can read or change data they should not reach, bypass login checks, and in some setups run commands on the database host.",
        "remediation": "Use parameterised queries or a safe ORM API for every query. Never build SQL by joining strings. Give the application database account only the rights it needs.",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html"
        ]
    },
    {
        "title": "Reflected cross-site scripting",
        "cwe": 79,
        "default_severity": "high",
        "tags": [
            "xss",
            "owasp-a03"
        ],
        "rule_ids": [
            "zap:40012"
        ],
        "description": "A value from the request is written back into the page without encoding for the context it lands in, so injected script runs in the victim's browser.",
        "impact": "An attacker who gets a user to open a crafted link can act as that user, read data shown in the page, or steal tokens not marked HttpOnly.",
        "remediation": "Encode output for its context (HTML, attribute, JavaScript, URL). Rely on a templating engine that escapes by default and add a restrictive Content Security Policy.",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/79.html"
        ]
    },
    {
        "title": "Stored cross-site scripting",
        "cwe": 79,
        "default_severity": "high",
        "tags": [
            "xss",
            "owasp-a03"
        ],
        "rule_ids": [
            "zap:40014"
        ],
        "description": "Content saved by one user is later shown to other users without output encoding, so script stored in it runs for every viewer.",
        "impact": "Every user who views the affected page is exposed; an attacker can take over sessions at scale, including those of administrators.",
        "remediation": "Encode data when rendering, not only on input. Sanitise any rich text with an allow-list library and set a Content Security Policy.",
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html"
        ]
    },
    {
        "title": "DOM-based cross-site scripting",
        "cwe": 79,
        "default_severity": "medium",
        "tags": [
            "xss",
            "owasp-a03"
        ],
        "rule_ids": [
            "zap:40026"
        ],
        "description": "Client-side script reads attacker-controlled data (such as the URL fragment) and writes it into the page through an unsafe sink like innerHTML.",
        "impact": "Script supplied by the attacker runs in the user's session, with the same effects as other cross-site scripting.",
        "remediation": "Use safe DOM APIs such as textContent, avoid eval-style sinks, and consider Trusted Types to block unsafe assignments.",
        "references": [
            "https://cwe.mitre.org/data/definitions/79.html"
        ]
    },
    {
        "title": "OS command injection",
        "cwe": 78,
        "default_severity": "critical",
        "tags": [
            "injection",
            "owasp-a03"
        ],
        "rule_ids": [
            "zap:90020"
        ],
        "description": "Input is passed to a system shell as part of a command line, letting an attacker append or change commands.",
        "impact": "Commands run on the server with the application's privileges, which usually means full compromise of the host.",
        "remediation": "Avoid calling a shell. Use library functions or pass arguments as a list without a shell, and validate input against a strict allow-list.",
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html"
        ]
    },
    {
        "title": "Server-side template injection",
        "cwe": 1336,
        "default_severity": "high",
        "tags": [
            "injection",
            "owasp-a03"
        ],
        "rule_ids": [
            "zap:90035"
        ],
        "description": "User input is placed into a server-side template source rather than passed as data, so template expressions in it are evaluated.",
        "impact": "Depending on the engine this ranges from data disclosure to running code on the server.",
        "remediation": "Pass user input to templates only as variables. If users must author templates, use a sandboxed engine with a minimal context.",
        "references": [
            "https://cwe.mitre.org/data/definitions/1336.html"
        ]
    },
    {
        "title": "XML external entity processing",
        "cwe": 611,
        "default_severity": "high",
        "tags": [
            "xxe",
            "owasp-a05"
        ],
        "rule_ids": [
            "zap:90023"
        ],
        "description": "The XML parser resolves external entities in documents supplied by users.",
        "impact": "An attacker can read local files, make the server send requests to internal systems, or exhaust resources.",
        "remediation": "Disable DTDs and external entity resolution in every XML parser, or use a hardened parser library.",
        "references": [
            "https://cwe.mitre.org/data/definitions/611.html"
        ]
    },
    {
        "title": "Server-side request forgery",
        "cwe": 918,
        "default_severity": "high",
        "tags": [
            "ssrf",
            "owasp-a10"
        ],
        "rule_ids": [
            "zap:40046"
        ],
        "description": "The server fetches a URL that the user controls without restricting where it may connect.",
        "impact": "Attackers can reach internal services and cloud metadata endpoints that are not exposed to the internet, often leading to credential theft.",
        "remediation": "Allow-list destination hosts and schemes, resolve and check the address before connecting, block private and link-local ranges, and require IMDSv2 on cloud hosts.",
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
        ]
    },
    {
        "title": "Insecure direct object reference",
        "cwe": 639,
        "default_severity": "high",
        "tags": [
            "access-control",
            "owasp-a01"
        ],
        "rule_ids": [],
        "description": "The application uses an identifier from the request to load a record but does not check that the caller is allowed to access that record.",
        "impact": "Users can read or change other users' data by changing an ID in the request.",
        "remediation": "Enforce an ownership or permission check on the server for every object access, and scope queries to the current user or tenant.",
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        ]
    },
    {
        "title": "Missing function-level authorization",
        "cwe": 285,
        "default_severity": "high",
        "tags": [
            "access-control",
            "owasp-a01"
        ],
        "rule_ids": [],
        "description": "Privileged functions or API routes can be called by users whose role should not allow it; the check exists only in the user interface.",
        "impact": "Low-privileged users can perform administrative actions.",
        "remediation": "Deny by default and check the caller's role on the server for each route. Add tests that call privileged routes as an ordinary user.",
        "references": [
            "https://cwe.mitre.org/data/definitions/285.html"
        ]
    },
    {
        "title": "Path traversal",
        "cwe": 22,
        "default_severity": "high",
        "tags": [
            "access-control",
            "owasp-a01"
        ],
        "rule_ids": [
            "zap:6"
        ],
        "description": "A file path built from user input is not normalised and checked, so sequences like ../ reach files outside the intended folder.",
        "impact": "Attackers can read configuration files, source code or secrets, and sometimes overwrite files.",
        "remediation": "Map user choices to server-side identifiers instead of paths. If paths are needed, resolve them and confirm they stay under the allowed base folder.",
        "references": [
            "https://cwe.mitre.org/data/definitions/22.html"
        ]
    },
    {
        "title": "Cross-site request forgery",
        "cwe": 352,
        "default_severity": "medium",
        "tags": [
            "csrf",
            "owasp-a01"
        ],
        "rule_ids": [
            "zap:10202",
            "zap:20012"
        ],
        "description": "State-changing requests are accepted without a token or other proof that the request came from the application itself.",
        "impact": "A malicious site can make a logged-in user's browser perform actions such as changing their email or password.",
        "remediation": "Require anti-CSRF tokens on state-changing requests, set SameSite on session cookies, and do not change state on GET.",
        "references": [
            "https://cwe.mitre.org/data/definitions/352.html"
        ]
    },
    {
        "title": "Open redirect",
        "cwe": 601,
        "default_severity": "low",
        "tags": [
            "redirect"
        ],
        "rule_ids": [
            "zap:10028"
        ],
        "description": "The application redirects to a URL taken from a parameter without validating it.",
        "impact": "Attackers can craft trusted-looking links that send users to phishing pages, or chain it with OAuth flows to leak tokens.",
        "remediation": "Redirect only to relative paths or to an allow-list of destinations.",
        "references": [
            "https://cwe.mitre.org/data/definitions/601.html"
        ]
    },
    {
        "title": "Weak password policy",
        "cwe": 521,
        "default_severity": "medium",
        "tags": [
            "authentication",
            "owasp-a07"
        ],
        "rule_ids": [],
        "description": "Accounts can be created with short or commonly used passwords.",
        "impact": "Accounts are easier to take over by guessing or credential stuffing.",
        "remediation": "Require a minimum length of at least 12 characters, check new passwords against breached-password lists, and offer multi-factor authentication.",
        "references": [
            "https://pages.nist.gov/800-63-3/sp800-63b.html"
        ]
    },
    {
        "title": "No protection against brute-force login",
        "cwe": 307,
        "default_severity": "medium",
        "tags": [
            "authentication",
            "owasp-a07"
        ],
        "rule_ids": [],
        "description": "The login endpoint allows unlimited attempts without throttling, lockout or challenge.",
        "impact": "Attackers can guess passwords or replay leaked credential lists at speed.",
        "remediation": "Rate-limit by account and by source, add progressive delays or challenges, alert on spikes, and support multi-factor authentication.",
        "references": [
            "https://cwe.mitre.org/data/definitions/307.html"
        ]
    },
    {
        "title": "Session fixation",
        "cwe": 384,
        "default_severity": "medium",
        "tags": [
            "session",
            "owasp-a07"
        ],
        "rule_ids": [],
        "description": "The session identifier is not replaced when the user logs in, so an identifier planted before login stays valid afterwards.",
        "impact": "An attacker who sets a victim's session ID can use the session once the victim authenticates.",
        "remediation": "Issue a new session identifier at login and on privilege change, and invalidate the old one.",
        "references": [
            "https://cwe.mitre.org/data/definitions/384.html"
        ]
    },
    {
        "title": "Session cookie missing Secure or HttpOnly flag",
        "cwe": 614,
        "default_severity": "low",
        "tags": [
            "session",
            "cookies"
        ],
        "rule_ids": [
            "zap:10010",
            "zap:10011"
        ],
        "description": "Session cookies are set without the Secure and/or HttpOnly attributes.",
        "impact": "Cookies may be sent over plain HTTP or read by injected script, which makes session theft easier.",
        "remediation": "Set Secure, HttpOnly and an appropriate SameSite value on every session cookie.",
        "references": [
            "https://cwe.mitre.org/data/definitions/614.html"
        ]
    },
    {
        "title": "Sensitive data sent over unencrypted HTTP",
        "cwe": 319,
        "default_severity": "high",
        "tags": [
            "crypto",
            "headers",
            "tls",
            "owasp-a02"
        ],
        "rule_ids": [
            "zap:10040"
        ],
        "description": "Pages or API calls that carry credentials or personal data are served over plain HTTP.",
        "impact": "Anyone on the network path can read or change the traffic.",
        "remediation": "Serve everything over HTTPS, redirect HTTP to HTTPS, and enable HSTS.",
        "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        ]
    },
    {
        "title": "Outdated TLS protocol or weak cipher suites",
        "cwe": 327,
        "default_severity": "medium",
        "tags": [
            "tls",
            "crypto",
            "owasp-a02"
        ],
        "rule_ids": [],
        "description": "The server still accepts TLS 1.0/1.1 or cipher suites considered weak.",
        "impact": "Traffic may be exposed to downgrade and decryption attacks, and the setup fails PCI DSS and similar requirements.",
        "remediation": "Allow TLS 1.2 and 1.3 only, with modern AEAD cipher suites and forward secrecy.",
        "references": [
            "https://cwe.mitre.org/data/definitions/327.html"
        ]
    },
    {
        "title": "Certificate expires soon",
        "cwe": 298,
        "default_severity": "low",
        "tags": ["tls", "certificate", "expiry"],
        "rule_ids": [
            "cert_notAfter",
            "cert_expirationStatus",
            "webcheck/cert-expiry",
        ],
        "description": "The TLS certificate end date is within 30 days. Severity rises at 14 days (medium) and 7 days (high).",
        "impact": "Browsers and API clients will start failing TLS handshakes when the certificate expires, causing outages.",
        "remediation": "Issue and install a renewed certificate before the current notAfter date. Prefer automated renewal (ACME) with monitoring on the end date.",
        "references": [
            "https://cwe.mitre.org/data/definitions/298.html",
        ],
    },
    {
        "title": "TLS: certificate expired",
        "cwe": 298,
        "default_severity": "high",
        "tags": ["tls", "certificate", "expiry"],
        "rule_ids": [
            "cert_expirationStatus",
            "cert_notAfter",
            "webcheck/cert-expiry",
        ],
        "description": "The TLS certificate notAfter date is in the past, so the certificate is already expired.",
        "impact": "Clients reject the connection; users see certificate errors and automated clients fail.",
        "remediation": "Replace the expired certificate immediately and reload the TLS service. Check that intermediates are served with the leaf.",
        "references": [
            "https://cwe.mitre.org/data/definitions/298.html",
        ],
    },
    {
        "title": "Missing HTTP Strict Transport Security header",
        "cwe": 319,
        "default_severity": "low",
        "tags": [
            "headers",
            "tls"
        ],
        "rule_ids": [
            "zap:10035",
            "webcheck/hsts-present",
        ],
        "description": "Responses over HTTPS do not include the Strict-Transport-Security header.",
        "impact": "A user's first request can be downgraded to HTTP by a network attacker.",
        "remediation": "Send Strict-Transport-Security with a long max-age and includeSubDomains once all subdomains support HTTPS.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
        ]
    },
    {
        "title": "Missing or weak Content Security Policy",
        "cwe": 693,
        "default_severity": "low",
        "tags": [
            "headers",
            "csp"
        ],
        "rule_ids": [
            "zap:10038",
            "zap:10055"
        ],
        "description": "No Content-Security-Policy header is sent, or the policy allows unsafe-inline or broad wildcards.",
        "impact": "The browser has no second line of defence if a cross-site scripting flaw exists.",
        "remediation": "Define a restrictive policy with explicit sources, avoid unsafe-inline, and use nonces or hashes for inline script.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
        ]
    },
    {
        "title": "Clickjacking: page can be framed",
        "cwe": 1021,
        "default_severity": "low",
        "tags": [
            "headers"
        ],
        "rule_ids": [
            "zap:10020"
        ],
        "description": "The page sets neither X-Frame-Options nor a frame-ancestors directive, so other sites can load it in a frame.",
        "impact": "Users can be tricked into clicking hidden buttons on the framed page.",
        "remediation": "Send Content-Security-Policy frame-ancestors 'self' (or 'none'), and X-Frame-Options DENY for older browsers.",
        "references": [
            "https://cwe.mitre.org/data/definitions/1021.html"
        ]
    },
    {
        "title": "X-Content-Type-Options is missing or not nosniff",
        "cwe": 693,
        "default_severity": "low",
        "tags": ["headers"],
        "rule_ids": ["webcheck/x-content-type-options", "zap:10021"],
        "description": "Responses omit X-Content-Type-Options or set a value other than nosniff.",
        "impact": "Browsers may MIME-sniff responses and treat non-script content as script.",
        "remediation": "Send X-Content-Type-Options: nosniff on all responses and keep Content-Type accurate.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            "https://cwe.mitre.org/data/definitions/693.html",
        ],
    },
    {
        "title": "Referrer-Policy is not a strict value",
        "cwe": 200,
        "default_severity": "low",
        "tags": ["headers"],
        "rule_ids": ["webcheck/referrer-policy"],
        "description": "Referrer-Policy is missing or uses a weak value that can leak full URLs to other origins.",
        "impact": "Path and query data may appear in Referer headers sent to third parties.",
        "remediation": "Send Referrer-Policy: strict-origin-when-cross-origin, or a stricter value such as no-referrer.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ],
    },
    {
        "title": "Overly permissive CORS policy",
        "cwe": 942,
        "default_severity": "medium",
        "tags": [
            "cors",
            "owasp-a05"
        ],
        "rule_ids": [
            "zap:40040"
        ],
        "description": "The API reflects any Origin in Access-Control-Allow-Origin, sometimes together with Allow-Credentials.",
        "impact": "Any website can read authenticated API responses from a logged-in user's browser.",
        "remediation": "Allow-list trusted origins explicitly and never combine a reflected origin with credentials.",
        "references": [
            "https://cwe.mitre.org/data/definitions/942.html"
        ]
    },
    {
        "title": "Verbose error messages",
        "cwe": 209,
        "default_severity": "low",
        "tags": [
            "information-disclosure",
            "owasp-a05"
        ],
        "rule_ids": [
            "zap:90022"
        ],
        "description": "Errors return stack traces, SQL statements or framework details to the client.",
        "impact": "Attackers learn internal structure, versions and query shapes that help with further attacks.",
        "remediation": "Show a generic error to users, log the details on the server, and turn off debug mode in production.",
        "references": [
            "https://cwe.mitre.org/data/definitions/209.html"
        ]
    },
    {
        "title": "Server version disclosed in headers",
        "cwe": 200,
        "default_severity": "info",
        "tags": [
            "headers",
            "information-disclosure"
        ],
        "rule_ids": [
            "zap:10036",
            "zap:10037",
            "webcheck/server-disclosure",
        ],
        "description": "Response headers such as Server or X-Powered-By reveal product names and version numbers.",
        "impact": "It makes it easier to match the system with known vulnerabilities.",
        "remediation": "Remove or genericise version banners in the web server and framework configuration.",
        "references": [
            "https://cwe.mitre.org/data/definitions/200.html"
        ]
    },
    {
        "title": "Directory listing enabled",
        "cwe": 548,
        "default_severity": "low",
        "tags": [
            "information-disclosure",
            "owasp-a05"
        ],
        "rule_ids": [
            "zap:0"
        ],
        "description": "The web server shows a file index for folders that have no default page.",
        "impact": "Backup files, scripts or data not meant to be public may be found and downloaded.",
        "remediation": "Turn off automatic directory indexes and remove files that should not be served.",
        "references": [
            "https://cwe.mitre.org/data/definitions/548.html"
        ]
    },
    {
        "title": "Component with known vulnerabilities",
        "cwe": 1104,
        "default_severity": "high",
        "tags": [
            "dependencies",
            "owasp-a06"
        ],
        "rule_ids": [],
        "description": "The application or image includes a library or package version with publicly known vulnerabilities.",
        "impact": "Attackers can use published exploits against the vulnerable component; impact depends on the specific issue.",
        "remediation": "Upgrade to a fixed version, track dependencies with an SBOM, and run software composition analysis in CI.",
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
        ]
    },
    {
        "title": "Hard-coded secret in source code",
        "cwe": 798,
        "default_severity": "high",
        "tags": [
            "secrets",
            "owasp-a07"
        ],
        "rule_ids": [],
        "description": "A password, API key or private key is committed in source code or configuration.",
        "impact": "Anyone with access to the repository, build artefacts or images can use the credential.",
        "remediation": "Revoke and rotate the secret now, move it to a secrets manager or environment injection, and add secret scanning to commits.",
        "references": [
            "https://cwe.mitre.org/data/definitions/798.html"
        ]
    },
    {
        "title": "Insecure deserialization",
        "cwe": 502,
        "default_severity": "critical",
        "tags": [
            "deserialization",
            "owasp-a08"
        ],
        "rule_ids": [],
        "description": "The application deserialises data from users with a format that can create arbitrary objects.",
        "impact": "Crafted payloads can run code, change application logic or cause denial of service.",
        "remediation": "Do not deserialise untrusted data with native object formats; use simple data formats like JSON with schema validation, and sign data that must round-trip.",
        "references": [
            "https://cwe.mitre.org/data/definitions/502.html"
        ]
    },
    {
        "title": "Unrestricted file upload",
        "cwe": 434,
        "default_severity": "high",
        "tags": [
            "upload"
        ],
        "rule_ids": [],
        "description": "Uploaded files are not checked for type and are stored where the server may run or serve them.",
        "impact": "Attackers can upload a web shell, serve malware, or place script that runs for other users.",
        "remediation": "Allow-list file types by content, rename files, store them outside the web root or in object storage, and serve them with a safe Content-Type and Content-Disposition.",
        "references": [
            "https://cwe.mitre.org/data/definitions/434.html"
        ]
    },
    {
        "title": "Insufficient security logging and monitoring",
        "cwe": 778,
        "default_severity": "medium",
        "tags": [
            "logging",
            "owasp-a09"
        ],
        "rule_ids": [],
        "description": "Security-relevant events such as logins, failed access checks and admin changes are not logged or not monitored.",
        "impact": "Attacks go unnoticed and investigations lack the evidence they need.",
        "remediation": "Log authentication, access-control failures and high-value changes with user and time, protect the logs from tampering, and alert on suspicious patterns.",
        "references": [
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
        ]
    },
    {
        "title": "Default or weak credentials on an exposed service",
        "cwe": 1392,
        "default_severity": "critical",
        "tags": [
            "authentication",
            "owasp-a07"
        ],
        "rule_ids": [],
        "description": "A service or admin interface accepts the vendor's default credentials or a trivially guessable password.",
        "impact": "Anyone can log in with full privileges.",
        "remediation": "Change all default credentials, restrict admin interfaces to trusted networks, and require strong unique passwords or SSO.",
        "references": [
            "https://cwe.mitre.org/data/definitions/1392.html"
        ]
    },
    {
        "title": "DNS: no DMARC record",
        "cwe": 16,
        "default_severity": "medium",
        "tags": ["email", "dns", "dmarc"],
        "rule_ids": ["webcheck/dns-dmarc-missing"],
        "description": "The domain has no DMARC TXT record at _dmarc.<domain>, so receivers have no published policy for unauthenticated mail.",
        "impact": "Attackers can spoof mail from the domain more easily, and you get no aggregate failure reports.",
        "remediation": "Add TXT at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>. Move to p=reject once reports look clean.",
        "references": ["https://dmarc.org/overview/", "https://www.rfc-editor.org/rfc/rfc7489"],
    },
    {
        "title": "DNS: DMARC policy is p=none",
        "cwe": 16,
        "default_severity": "low",
        "tags": ["email", "dns", "dmarc"],
        "rule_ids": ["webcheck/dns-dmarc-p-none"],
        "description": "DMARC is published with p=none, so receivers only monitor and do not quarantine or reject failing messages.",
        "impact": "Spoofed mail is still delivered while you only collect reports.",
        "remediation": "Change DMARC p=none to p=quarantine, then p=reject after reviewing rua reports.",
        "references": ["https://dmarc.org/overview/"],
    },
    {
        "title": "DNS: DMARC record has bad syntax",
        "cwe": 16,
        "default_severity": "low",
        "tags": ["email", "dns", "dmarc"],
        "rule_ids": ["webcheck/dns-dmarc-bad-syntax"],
        "description": "A TXT exists at _dmarc.<domain> but it is not a valid v=DMARC1 record with a usable p= tag.",
        "impact": "Receivers may ignore the policy, leaving the domain without DMARC protection.",
        "remediation": "Publish a single TXT starting with v=DMARC1; set p=quarantine or p=reject and add rua=.",
        "references": ["https://www.rfc-editor.org/rfc/rfc7489"],
    },
    {
        "title": "DNS: DMARC has no rua reporting address",
        "cwe": 16,
        "default_severity": "info",
        "tags": ["email", "dns", "dmarc"],
        "rule_ids": ["webcheck/dns-dmarc-no-rua"],
        "description": "The DMARC record has no rua= tag, so aggregate authentication reports are not requested.",
        "impact": "You cannot see who is sending mail as your domain or tune SPF/DKIM before raising the policy.",
        "remediation": "Add rua=mailto:dmarc-reports@<domain> to the DMARC record.",
        "references": ["https://dmarc.org/overview/"],
    },
    {
        "title": "DNS: no DKIM found on common selectors",
        "cwe": 16,
        "default_severity": "info",
        "tags": ["email", "dns", "dkim"],
        "rule_ids": ["webcheck/dns-dkim-none"],
        "description": "No DKIM TXT was found on the short fixed list of common selectors; a custom selector may still exist.",
        "impact": "Without DKIM, DMARC alignment is harder and spoofed mail is more likely to pass weak checks.",
        "remediation": "Publish DKIM at <selector>._domainkey.<domain> for your mail provider, using at least a 2048-bit RSA key.",
        "references": ["https://www.rfc-editor.org/rfc/rfc6376"],
    },
    {
        "title": "DNS: DKIM RSA key is under 1024 bits",
        "cwe": 16,
        "default_severity": "medium",
        "tags": ["email", "dns", "dkim"],
        "rule_ids": ["webcheck/dns-dkim-weak-key"],
        "description": "A DKIM selector publishes an RSA public key shorter than 1024 bits.",
        "impact": "A weak signing key can be factored, letting attackers forge DKIM signatures for the domain.",
        "remediation": "Rotate the DKIM key to RSA 2048-bit or stronger and update the selector TXT record.",
        "references": ["https://www.rfc-editor.org/rfc/rfc8301"],
    },
    {
        "title": "DNS: no MTA-STS record",
        "cwe": 16,
        "default_severity": "low",
        "tags": ["email", "dns", "mta-sts"],
        "rule_ids": ["webcheck/dns-mta-sts-missing"],
        "description": "No MTA-STS TXT exists at _mta-sts.<domain>, so sending MTAs cannot discover a TLS policy for your MX hosts.",
        "impact": "SMTP delivery may fall back to cleartext or accept weaker TLS without a published policy.",
        "remediation": "Add TXT at _mta-sts.<domain> (v=STSv1; id=...) and serve https://mta-sts.<domain>/.well-known/mta-sts.txt with mode=enforce.",
        "references": ["https://www.rfc-editor.org/rfc/rfc8461"],
    },
    {
        "title": "DNS: MTA-STS mode is testing",
        "cwe": 16,
        "default_severity": "info",
        "tags": ["email", "dns", "mta-sts"],
        "rule_ids": ["webcheck/dns-mta-sts-testing"],
        "description": "The MTA-STS policy is published with mode=testing, so failures are reported but not enforced.",
        "impact": "Senders will not refuse insecure delivery; you only learn about problems from reports.",
        "remediation": "Set mode: enforce in the MTA-STS policy file when MX TLS is ready.",
        "references": ["https://www.rfc-editor.org/rfc/rfc8461"],
    },
    {
        "title": "DNS: MTA-STS TXT without a valid policy file",
        "cwe": 16,
        "default_severity": "medium",
        "tags": ["email", "dns", "mta-sts"],
        "rule_ids": ["webcheck/dns-mta-sts-no-policy"],
        "description": "An MTA-STS DNS TXT exists but the HTTPS policy file is missing or invalid.",
        "impact": "Senders that support MTA-STS cannot apply a usable policy and may ignore it.",
        "remediation": "Serve a valid STSv1 policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with mode=enforce.",
        "references": ["https://www.rfc-editor.org/rfc/rfc8461"],
    },
    {
        "title": "DNS: no TLS-RPT record",
        "cwe": 16,
        "default_severity": "info",
        "tags": ["email", "dns", "tls-rpt"],
        "rule_ids": ["webcheck/dns-tls-rpt-missing"],
        "description": "No TLS-RPT TXT exists at _smtp._tls.<domain>, so SMTP TLS failure reports are not requested.",
        "impact": "You will not receive reports when senders cannot negotiate TLS to your MX hosts.",
        "remediation": "Add TXT at _smtp._tls.<domain>: v=TLSRPTv1; rua=mailto:tlsrpt@<domain>.",
        "references": ["https://www.rfc-editor.org/rfc/rfc8460"],
    },
    {
        "title": "DNS: DNSSEC not detected",
        "cwe": 16,
        "default_severity": "low",
        "tags": ["dns", "dnssec"],
        "rule_ids": ["webcheck/dns-dnssec-missing"],
        "description": "No DS and/or RRSIG evidence was found for the domain, so DNSSEC does not appear to be enabled.",
        "impact": "DNS answers can be spoofed on the path, undermining HTTPS and email authentication lookups.",
        "remediation": "Enable DNSSEC with your DNS host and publish DS records at the parent registry.",
        "references": ["https://www.rfc-editor.org/rfc/rfc4035"],
    },
    {
        "title": "External scripts or styles without Subresource Integrity",
        "cwe": 353,
        "default_severity": "medium",
        "tags": ["sri", "supply-chain"],
        "rule_ids": ["webcheck/sri", "observatory:subresource-integrity"],
        "description": "The page loads scripts or stylesheets from another origin without an integrity attribute, so a change on that CDN is not detected by the browser.",
        "impact": "A compromised or replaced third-party file can run script or change styles in the user's session.",
        "remediation": "Add integrity (sha384 or stronger) and crossorigin attributes on every cross-origin script and stylesheet tag. Prefer self-hosting critical assets.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            "https://cwe.mitre.org/data/definitions/353.html",
        ],
    },
    {
        "title": "Active mixed content",
        "cwe": 311,
        "default_severity": "medium",
        "tags": ["mixed-content", "tls"],
        "rule_ids": ["webcheck/mixed-content-active"],
        "description": "An HTTPS page loads a script, stylesheet, frame, object, or form action over plain http://.",
        "impact": "A network attacker can replace or alter the cleartext resource and run code or steal form data in the user's session.",
        "remediation": "Change every http:// script, stylesheet, frame, object, and form action URL to https:// (or a same-origin relative path).",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            "https://cwe.mitre.org/data/definitions/311.html",
        ],
    },
    {
        "title": "Passive mixed content",
        "cwe": 311,
        "default_severity": "low",
        "tags": ["mixed-content", "tls"],
        "rule_ids": ["webcheck/mixed-content-passive"],
        "description": "An HTTPS page loads an image or other media file over plain http://.",
        "impact": "A network attacker can swap the image or media, track users, or use it as a side channel.",
        "remediation": "Change every http:// image and media URL to https:// (or a same-origin relative path).",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            "https://cwe.mitre.org/data/definitions/311.html",
        ],
    },
    {
        "title": "HTTP does not redirect to HTTPS",
        "cwe": 319,
        "default_severity": "medium",
        "tags": ["headers", "tls", "redirect"],
        "rule_ids": ["webcheck/http-no-redirect"],
        "description": "A request to http:// on the host returns a page or a non-HTTPS Location instead of upgrading to https:// on the same host.",
        "impact": "Users and APIs that start on HTTP stay on a cleartext channel, so traffic can be read or changed on the path.",
        "remediation": "Respond to http://<host>/ with 301 or 308 and Location: https://<same-host>/... Send HSTS only on HTTPS. Prefer 301/308 over 302/307.",
        "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
    },
    {
        "title": "Temporary redirect to HTTPS",
        "cwe": 319,
        "default_severity": "low",
        "tags": ["headers", "tls", "redirect"],
        "rule_ids": ["webcheck/http-redirect-temporary"],
        "description": "http:// redirects to https:// on the same host with 302 or 307 instead of a permanent 301 or 308.",
        "impact": "Clients and caches may keep retrying HTTP; HSTS and bookmarks are weaker without a permanent upgrade.",
        "remediation": "Change the upgrade redirect to 301 or 308 pointing at https:// on the same host.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
        ],
    },
    {
        "title": "HTTP redirects to another host before HTTPS on the same host",
        "cwe": 319,
        "default_severity": "low",
        "tags": ["headers", "tls", "redirect"],
        "rule_ids": ["webcheck/http-redirect-other-host"],
        "description": "The first HTTP answer sends the browser to https:// on a different host instead of https:// on the same host.",
        "impact": "HSTS cannot be set for this host on that first hop, so a network attacker can still intercept later HTTP visits to this name.",
        "remediation": "Redirect http://<host>/ to https://<same-host>/ with 301 or 308 first. Only then move to another hostname if needed.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
    },
    {
        "title": "Listed on Google Safe Browsing",
        "cwe": 506,
        "default_severity": "high",
        "tags": ["malware", "reputation", "safe-browsing"],
        "rule_ids": ["webcheck/safe-browsing"],
        "description": "Google Safe Browsing lists this URL for malware, social engineering, or unwanted software.",
        "impact": "Browsers and search warn or block visitors; users lose trust and may be harmed by the listed threat.",
        "remediation": "Clean the site (remove malware, backdoors, and injected script), rotate any stolen credentials, then request a review in Google Search Console.",
        "references": [
            "https://developers.google.com/safe-browsing",
            "https://support.google.com/webmasters/answer/9044101",
            "https://cwe.mitre.org/data/definitions/506.html",
        ],
    },
]

# Attach importance / effort / fix steps / snippets from the fix-snippet library.
from attestra.library.fix_snippets import enrich as _enrich_fix  # noqa: E402

SEED = [_enrich_fix(item) for item in SEED]
