import logging

from agent.callbacks import ToolCallLogger
from agent.llm import create_red_team_agent

logger = logging.getLogger("agent.workflow")

CHAT_HISTORY = []
_callback = ToolCallLogger()


async def run_workflow(prompt: str):
    agent = await create_red_team_agent()
    CHAT_HISTORY.append({"role": "user", "content": prompt})
    logger.info("USER: %s", prompt)
    response = await agent.ainvoke(
        {"messages": CHAT_HISTORY},
        config={"callbacks": [_callback]},
    )
    output = response["messages"][-1].content
    CHAT_HISTORY.append({"role": "assistant", "content": output})
    logger.info("AGENT: %s", output)
    return output
