import asyncio
from agent.workflow import run_workflow
from agent.tools.kali_mcp import get_tools


async def main():
    print("Hello from agentic-red-team!")
    user_prompt = input("What would you like the Red Team Agent to do ? ")
    response = await run_workflow(user_prompt)
    print(response)


if __name__ == "__main__":
    asyncio.run(main())
