"""Fixtures for Elite automated security-testing package tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app


@pytest.fixture
def secure_client() -> TestClient:
    return TestClient(create_secure_app())


@pytest.fixture
def vulnerable_client() -> TestClient:
    return TestClient(create_vulnerable_app())


def login(client: TestClient, username: str, password: str) -> None:
    r = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert r.status_code == 303
