"""Elite automated security-test modules (authn/authz/session/API + safe probes)."""

from attestra.automated_vapt.testing.api_security_tests import run as run_api_security
from attestra.automated_vapt.testing.authentication_tests import run as run_authentication
from attestra.automated_vapt.testing.authorization_tests import run as run_authorization
from attestra.automated_vapt.testing.file_security_tests import run as run_file_security
from attestra.automated_vapt.testing.idor_bola_tests import run as run_idor_bola
from attestra.automated_vapt.testing.injection_tests import run as run_injection
from attestra.automated_vapt.testing.privilege_escalation_tests import (
    probe_horizontal_privilege,
    probe_vertical_privilege,
)
from attestra.automated_vapt.testing.privilege_escalation_tests import (
    run as run_privilege,
)
from attestra.automated_vapt.testing.session_security_tests import run as run_session
from attestra.automated_vapt.testing.xss_tests import run as run_xss

__all__ = [
    "probe_horizontal_privilege",
    "probe_vertical_privilege",
    "run_api_security",
    "run_authentication",
    "run_authorization",
    "run_file_security",
    "run_idor_bola",
    "run_injection",
    "run_privilege",
    "run_session",
    "run_xss",
]
