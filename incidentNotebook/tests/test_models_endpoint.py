"""Tests for GET /workflow/models against a mocked LLM server connection.

Run with: ``uv run pytest tests/test_models_endpoint.py``
"""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError

from backend.main import app
from backend.routers import workflow
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


def test_list_models_closes_client(monkeypatch):
    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.models = self
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.closed = True

        def list(self):
            return [SimpleNamespace(id="model-a"), SimpleNamespace(id="model-b")]

    fake_client = FakeOpenAI()
    monkeypatch.setattr(llm, "OpenAI", lambda **kwargs: fake_client)

    assert llm.list_models() == ["model-a", "model-b"]
    assert fake_client.closed is True


def test_extraction_sanitizes_upstream_http_error(monkeypatch, client):
    def reject_model(*args, **kwargs):
        raise ModelHTTPError(
            status_code=409,
            model_name="broken-model",
            body={"message": "cannot read /private/model/config.json"},
        )

    monkeypatch.setattr(workflow, "ioc_extraction_agent_workflow", reject_model)

    response = client.post(
        "/cases/CASE-1/extract",
        json={"incident_description": "Incident", "llm_model": "broken-model"},
    )

    assert response.status_code == 502
    assert "broken-model" in response.json()["detail"]
    assert "/private/model" not in response.text


def test_extraction_sanitizes_provider_connection_error(monkeypatch, client):
    def connection_error(*args, **kwargs):
        raise ModelAPIError("offline-model", "Connection error to private host")

    monkeypatch.setattr(workflow, "ioc_extraction_agent_workflow", connection_error)

    response = client.post(
        "/cases/CASE-1/extract",
        json={"incident_description": "Incident", "llm_model": "offline-model"},
    )

    assert response.status_code == 502
    assert response.json()["detail"] == "LLM request failed for model 'offline-model'."
    assert "private host" not in response.text
