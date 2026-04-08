from deepagents import create_deep_agent
from langchain_ollama import ChatOllama

from config import settings

OLLAMA_SETTINGS = settings.ollama
AGENT_SETTINGS = settings.agent


def _create_llm():
    return ChatOllama(
        base_url=OLLAMA_SETTINGS.host,
        model=OLLAMA_SETTINGS.model,
        temperature=AGENT_SETTINGS.temperature,
        num_ctx=AGENT_SETTINGS.num_ctx,
        keep_alive=OLLAMA_SETTINGS.keep_alive,
    )


def create_phase_agent(system_prompt: str, tools: list):
    """Return a deep agent configured for a single phase."""
    llm = _create_llm()
    return create_deep_agent(
        model=llm,
        tools=tools,
        system_prompt=system_prompt,
    )
