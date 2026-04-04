import json
import logging
from typing import Any, Union
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

logger = logging.getLogger("agent.tools")


class ToolCallLogger(BaseCallbackHandler):
    """Logs every tool call, result, and error made by the agent."""

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        try:
            parsed = json.loads(input_str)
            formatted = json.dumps(parsed, indent=2)
        except (json.JSONDecodeError, TypeError):
            formatted = input_str
        logger.info("TOOL CALL [%s]\n%s", tool_name, formatted)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        logger.info("TOOL RESULT\n%s", str(output))

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        logger.error("TOOL ERROR: %s", error)

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        model = serialized.get("name", "unknown")
        logger.debug("LLM START [%s]", model)

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        text = ""
        if response.generations:
            gen = response.generations[0]
            if gen and hasattr(gen[0], "text"):
                text = gen[0].text[:200]
        logger.debug("LLM END — response preview: %s", text)