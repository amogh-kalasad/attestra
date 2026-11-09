"""Local-only mock applications and shared Elite test fixtures."""

from tests.automated_vapt.fixtures.mock_header_conflict_app import create_header_conflict_app
from tests.automated_vapt.fixtures.mock_secure_app import create_secure_app
from tests.automated_vapt.fixtures.mock_session_expiry_app import create_session_expiry_app
from tests.automated_vapt.fixtures.mock_vulnerable_app import create_vulnerable_app
from tests.automated_vapt.fixtures.mock_waf_challenge_app import create_waf_challenge_app

__all__ = [
    "create_header_conflict_app",
    "create_secure_app",
    "create_session_expiry_app",
    "create_vulnerable_app",
    "create_waf_challenge_app",
]
