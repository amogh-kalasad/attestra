"""Elite automated security-test modules (authn/authz/API)."""

from attestra.automated_vapt.testing.api_security_tests import run as run_api_security
from attestra.automated_vapt.testing.authentication_tests import run as run_authentication
from attestra.automated_vapt.testing.authorization_tests import run as run_authorization
from attestra.automated_vapt.testing.idor_bola_tests import run as run_idor_bola
from attestra.automated_vapt.testing.privilege_escalation_tests import run as run_privilege

__all__ = [
    "run_api_security",
    "run_authentication",
    "run_authorization",
    "run_idor_bola",
    "run_privilege",
]
