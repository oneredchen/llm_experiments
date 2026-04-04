from langchain_mcp_adapters.client import MultiServerMCPClient

KALI_SERVER_URL = "http://192.168.50.21:3000/mcp/"


def get_kali_mcp_client() -> MultiServerMCPClient:
    return MultiServerMCPClient(
        {
            "kali": {
                "transport": "streamable_http",
                "url": KALI_SERVER_URL,
            }
        }
    )


async def get_tools():
    client = get_kali_mcp_client()
    tools = await client.get_tools()  # returns list of LangChain-compatible tools
    for tool in tools:
        print(tool)
    return tools
