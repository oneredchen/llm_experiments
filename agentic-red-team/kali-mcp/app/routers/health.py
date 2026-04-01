import logging

from fastapi import APIRouter

from services.command_executor import execute_command

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health")
def health_check():
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except Exception:
            tools_status[tool] = False

    all_essential_tools_available = all(tools_status.values())

    return {
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
    }


@router.get("/mcp/capabilities")
def get_capabilities():
    """Return tool capabilities similar to our existing MCP server."""
    # TODO: implement MCP capability discovery
    pass


@router.post("/mcp/tools/kali_tools/{tool_name}")
def execute_tool(tool_name: str):
    """Direct tool execution without going through the API server."""
    # TODO: implement direct MCP tool execution
    pass
