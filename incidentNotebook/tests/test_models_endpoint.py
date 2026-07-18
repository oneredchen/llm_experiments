"""Tests for GET /workflow/models against a mocked LLM server connection.

Run with: ``uv run pytest tests/test_models_endpoint.py``
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.utils import llm


@pytest.fixture
def client():
    return TestClient(app)


def test_models_success(monkeypatch, client):
    monkeypatch.setattr(
        llm, "list_models", lambda: ["mistral:latest", "qwen3:30b"]
    )

    response = client.get("/workflow/models")

    assert response.status_code == 200
    assert response.json() == {"models": ["mistral:latest", "qwen3:30b"]}


def test_models_unreachable_server_returns_503(monkeypatch, client):
    def boom():
        raise ConnectionError("Connection refused")

    monkeypatch.setattr(llm, "list_models", boom)

    response = client.get("/workflow/models")

    assert response.status_code == 503
    # The detail names the configured base URL so the misconfiguration is obvious
    assert llm.LLM_BASE_URL in response.json()["detail"]
