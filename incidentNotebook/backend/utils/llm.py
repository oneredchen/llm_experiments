"""Shared LLM configuration and model factory.

The app talks to any OpenAI-v1-compatible endpoint (Ollama, LM Studio, vLLM,
llama.cpp server, ...) — this module is the single place that reads the
configuration:

- ``LLM_BASE_URL``    — e.g. ``http://localhost:11434/v1`` (Ollama),
  ``http://localhost:1234/v1`` (LM Studio), ``http://localhost:8000/v1`` (vLLM).
  Note the required ``/v1`` path suffix.
- ``LLM_API_KEY``     — local servers accept any non-empty key (default ``"local"``).
- ``LLM_OUTPUT_MODE`` — ``native`` (OpenAI ``json_schema`` response format, default)
  or ``prompted`` (schema injected into the prompt) structured-output mode.
"""

import logging
import os
from urllib.parse import urlparse

from dotenv import load_dotenv
from openai import OpenAI
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

load_dotenv()

logger = logging.getLogger(__name__)

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "local")
LLM_OUTPUT_MODE = os.getenv("LLM_OUTPUT_MODE", "native").strip().lower()

if LLM_OUTPUT_MODE not in ("native", "prompted"):
    logger.warning(
        "Unknown LLM_OUTPUT_MODE %r — falling back to 'native'.", LLM_OUTPUT_MODE
    )
    LLM_OUTPUT_MODE = "native"


def _warn_if_base_url_missing_v1() -> None:
    """Log the classic misconfiguration: base URL without the /v1 path."""
    path = (urlparse(LLM_BASE_URL).path or "").rstrip("/")
    if not path.endswith("/v1"):
        logger.warning(
            "LLM_BASE_URL %r does not end in '/v1' — OpenAI-compatible endpoints "
            "are usually served at <host>/v1 (e.g. http://localhost:11434/v1).",
            LLM_BASE_URL,
        )


_warn_if_base_url_missing_v1()


def build_model(model_name: str) -> OpenAIChatModel:
    """Build a chat model for the configured OpenAI-v1-compatible server.

    This is the only place in the codebase that constructs an LLM client/model.
    """
    provider = OpenAIProvider(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)
    return OpenAIChatModel(model_name, provider=provider)


def get_output_mode() -> str:
    """Structured-output mode: ``native`` (json_schema) or ``prompted``."""
    return LLM_OUTPUT_MODE


def list_models() -> list[str]:
    """Return the model IDs served at ``GET {LLM_BASE_URL}/models``.

    Short timeout and no retries: this powers a UI dropdown, so an unreachable
    server must fail fast (and surface as a clear 503) rather than hang.
    """
    with OpenAI(
        base_url=LLM_BASE_URL, api_key=LLM_API_KEY, timeout=5.0, max_retries=0
    ) as client:
        return [model.id for model in client.models.list()]
