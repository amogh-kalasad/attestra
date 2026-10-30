"""Local-only mock applications and shared Elite test fixtures."""

from tests.automated_vapt.fixtures.mock_secure_app import create_secure_app
from tests.automated_vapt.fixtures.mock_vulnerable_app import create_vulnerable_app

__all__ = ["create_secure_app", "create_vulnerable_app"]
