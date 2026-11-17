"""Local-only mock apps for the WP2 safe-probe pack (CORS, Host header, open redirect,
cache posture, GraphQL, API posture). Never deployed; used through FastAPI TestClient."""

from tests.automated_vapt.fixtures.probes.mock_probe_app import create_probe_app

__all__ = ["create_probe_app"]
