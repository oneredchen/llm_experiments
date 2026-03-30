from agent.llm import create_red_team_agent

CHAT_HISTORY = []


async def run_workflow(prompt: str):
    agent = await create_red_team_agent()
    CHAT_HISTORY.append({"role": "user", "content": prompt})
    response = await agent.ainvoke({"messages": CHAT_HISTORY})
    output = response["messages"][-1].content
    CHAT_HISTORY.append({"role": "assistant", "content": output})
    return output
