"""LLM factory functions and decision extraction helper."""

from pydantic import BaseModel
from deepagents import create_deep_agent
from langchain_ollama import ChatOllama

from config import settings

OLLAMA_SETTINGS = settings.ollama
AGENT_SETTINGS = settings.agent


def create_llm() -> ChatOllama:
    """Create a ChatOllama instance. Safe to reuse across multiple agents."""
    return ChatOllama(
        base_url=OLLAMA_SETTINGS.host,
        model=OLLAMA_SETTINGS.model,
        temperature=AGENT_SETTINGS.temperature,
        num_ctx=AGENT_SETTINGS.num_ctx,
        keep_alive=OLLAMA_SETTINGS.keep_alive,
        reasoning=True,
    )


def create_phase_agent(
    system_prompt: str,
    tools: list,
    llm=None,
    response_format=None,
    subagents=None,
):
    """Return a deep agent configured for a single phase.

    Args:
        system_prompt: Phase-specific system instructions.
        tools: Tools the orchestrator agent can call directly.
        llm: Reusable ChatOllama instance (creates new if None).
        response_format: Pydantic model for structured output (e.g. Phase 6).
        subagents: List of SubAgent specs for phases with subagents.
    """
    llm = llm or create_llm()
    return create_deep_agent(
        model=llm,
        tools=tools,
        system_prompt=system_prompt,
        response_format=response_format,
        subagents=subagents,
    )


async def extract_decision(
    llm, findings: str, decision_model: type[BaseModel]
) -> BaseModel:
    """Make a single LLM call to extract a decision model from findings text.

    This is a cheap follow-up call with no tools — just structured extraction.
    Keeps the main phase agent focused on doing work rather than formatting.
    """
    agent = create_deep_agent(
        model=llm,
        tools=[],
        system_prompt=(
            "Extract structured data from the provided penetration test findings. "
            "Populate every field accurately based on the evidence present. "
            "If information for a field is not present, use the default value."
        ),
        response_format=decision_model,
    )
    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": findings}]}
    )
    return result["structured_response"]
