"""LangChain tools that call the Kali FastAPI server directly over httpx.

Replaces the MCP transport layer entirely — no SSE, no session state, no
reconnection logic. Each tool is a plain async function wrapped with
@tool. Timeouts are enforced by httpx.
"""

import logging
from typing import Any

import httpx
from langchain_core.tools import tool

from config import settings

logger = logging.getLogger("agent.tools")

_BASE_URL = "http://192.168.50.21:3000"
_TIMEOUT = settings.agent.tool_timeout


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT)


def _fmt(result: dict[str, Any]) -> str:
    """Format the API response into a readable string for the agent."""
    parts = []
    if result.get("timed_out"):
        parts.append(f"[TIMED OUT after {_TIMEOUT}s — partial results below]")
    if result.get("stdout"):
        parts.append(result["stdout"])
    if result.get("stderr"):
        parts.append(f"[stderr]\n{result['stderr']}")
    if not parts:
        rc = result.get("return_code", "?")
        parts.append(f"[no output — return code {rc}]")
    return "\n".join(parts)


async def _api_post(endpoint: str, payload: dict[str, Any]) -> str:
    """POST to the Kali API and return a formatted string result.
    All HTTP and network errors are caught and returned as error strings
    so the agent can reason about failures instead of crashing."""
    try:
        async with _client() as c:
            r = await c.post(endpoint, json=payload)
            r.raise_for_status()
            return _fmt(r.json())
    except httpx.TimeoutException:
        msg = f"TOOL TIMEOUT: {endpoint} did not respond within {_TIMEOUT}s. Try a different approach or move to the next candidate."
        logger.warning(msg)
        return msg
    except httpx.ConnectError:
        msg = f"TOOL ERROR: could not connect to Kali API at {_BASE_URL}. The server may be down."
        logger.error(msg)
        return msg
    except httpx.HTTPStatusError as e:
        msg = f"TOOL ERROR: {endpoint} returned HTTP {e.response.status_code} — {e.response.text[:300]}"
        logger.error(msg)
        return msg
    except Exception as e:
        msg = f"TOOL ERROR: unexpected error calling {endpoint} — {type(e).__name__}: {e}"
        logger.error(msg, exc_info=True)
        return msg


@tool
async def run_command(command: str) -> str:
    """Run an arbitrary non-interactive shell command on the Kali machine.
    Only use for commands that exit on their own (curl, searchsploit, etc.).
    Never use nc, netcat, or anything that opens an interactive session."""
    return await _api_post("/api/command", {"command": command})


@tool
async def nmap(
    target: str,
    scan_type: str = "-sCV",
    ports: str = "",
    additional_args: str = "-T4 -Pn",
) -> str:
    """Run an nmap scan against a target.
    scan_type: nmap flags e.g. '-sCV', '-sU', '-sS'.
    ports: port range e.g. '1-500', '80,443', '' for default.
    additional_args: extra nmap flags."""
    return await _api_post(
        "/api/tools/nmap",
        {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args},
    )


@tool
async def gobuster(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> str:
    """Run gobuster directory/DNS/vhost brute-forcing against a URL.
    mode: 'dir', 'dns', 'fuzz', or 'vhost'."""
    return await _api_post(
        "/api/tools/gobuster",
        {"url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args},
    )


@tool
async def dirb(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> str:
    """Run dirb web content scanner against a URL."""
    return await _api_post(
        "/api/tools/dirb",
        {"url": url, "wordlist": wordlist, "additional_args": additional_args},
    )


@tool
async def nikto(target: str, additional_args: str = "") -> str:
    """Run nikto web server vulnerability scanner against a target host or URL."""
    return await _api_post("/api/tools/nikto", {"target": target, "additional_args": additional_args})


@tool
async def sqlmap(url: str, data: str = "", additional_args: str = "") -> str:
    """Run sqlmap SQL injection scanner against a URL.
    data: POST body string for POST requests."""
    return await _api_post("/api/tools/sqlmap", {"url": url, "data": data, "additional_args": additional_args})


@tool
async def metasploit(module: str, options: dict[str, Any] = {}) -> str:
    """Run a Metasploit module non-interactively.
    module: full module path e.g. 'exploit/unix/irc/unreal_ircd_3281_backdoor'.
    options: dict of MSF options e.g. {'RHOSTS': '192.168.1.1', 'LHOST': '192.168.1.2'}.
    Use this instead of nc/netcat for any exploit that requires a shell connection."""
    return await _api_post("/api/tools/metasploit", {"module": module, "options": options})


@tool
async def hydra(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "",
    additional_args: str = "",
) -> str:
    """Run hydra credential brute-forcing.
    service: protocol e.g. 'ssh', 'ftp', 'http-post-form', 'smb'.
    Provide username or username_file, and password or password_file."""
    return await _api_post(
        "/api/tools/hydra",
        {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args,
        },
    )


@tool
async def john(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
    additional_args: str = "",
) -> str:
    """Run John the Ripper to crack password hashes.
    hash_file: path to file containing hashes on the Kali machine.
    format: hash format e.g. 'md5crypt', 'sha512crypt' (leave empty to auto-detect)."""
    return await _api_post(
        "/api/tools/john",
        {"hash_file": hash_file, "wordlist": wordlist, "format": format, "additional_args": additional_args},
    )


@tool
async def wpscan(url: str, additional_args: str = "") -> str:
    """Run WPScan WordPress vulnerability scanner against a URL."""
    return await _api_post("/api/tools/wpscan", {"url": url, "additional_args": additional_args})


@tool
async def enum4linux(target: str, additional_args: str = "-a") -> str:
    """Run enum4linux SMB/NetBIOS enumeration against a target."""
    return await _api_post("/api/tools/enum4linux", {"target": target, "additional_args": additional_args})


def get_tools() -> list:
    return [
        run_command,
        nmap,
        gobuster,
        dirb,
        nikto,
        sqlmap,
        metasploit,
        hydra,
        john,
        wpscan,
        enum4linux,
    ]