from pathlib import Path
from langchain_mcp_adapters.client import MultiServerMCPClient

KALI_SERVER_URL = "http://100.108.113.101:5000"
CLIENT_PATH = Path(__file__).parent / "kali_mcp_client.py"


def get_kali_mcp_client() -> MultiServerMCPClient:
    return MultiServerMCPClient(
        {
            "kali": {
                "transport": "stdio",
                "command": "python3",
                "args": [
                    str(CLIENT_PATH),
                    "--server",
                    KALI_SERVER_URL,
                ],
            }
        }
    )


async def get_tools():
    client = get_kali_mcp_client()
    tools = await client.get_tools()  # returns list of LangChain-compatible tools
    return tools
