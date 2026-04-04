"""MCP server with Streamable HTTP transport wrapping Kali Linux tools."""

import shlex
import os
import re
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

from services.command_executor import execute_command

mcp = FastMCP(
    name="kali-mcp",
    instructions="MCP server exposing Kali Linux security tools for authorized penetration testing.",
    host="0.0.0.0",
)


def _format_result(result: Dict[str, Any]) -> str:
    """Format command execution result as a string."""
    parts = []
    if result.get("stdout"):
        parts.append(result["stdout"])
    if result.get("stderr"):
        parts.append(f"[stderr]\n{result['stderr']}")
    if result.get("timed_out"):
        parts.append("[Note: command timed out, output may be partial]")
    if not parts:
        parts.append(f"(no output, return code: {result.get('return_code')})")
    return "\n".join(parts)


@mcp.tool()
def run_command(command: str) -> str:
    """Execute an arbitrary shell command on the Kali host.

    Args:
        command: The shell command to execute.
    """
    result = execute_command(command)
    return _format_result(result)


@mcp.tool()
def nmap(
    target: str,
    scan_type: str = "-sCV",
    ports: str = "",
    additional_args: str = "-T4 -Pn",
) -> str:
    """Run an nmap scan against a target.

    Args:
        target: IP address, hostname, or CIDR range to scan.
        scan_type: nmap scan flags (default: -sCV for version/script scan).
        ports: Port specification, e.g. '80,443' or '1-1000' (empty = nmap default).
        additional_args: Extra nmap arguments (default: -T4 -Pn).
    """
    command = ["nmap"] + shlex.split(scan_type)
    if ports:
        command += ["-p", ports]
    if additional_args:
        command += shlex.split(additional_args)
    command.append(target)
    return _format_result(execute_command(command))


@mcp.tool()
def gobuster(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> str:
    """Run gobuster for directory/DNS/vhost enumeration.

    Args:
        url: Target URL.
        mode: Enumeration mode — dir, dns, fuzz, or vhost.
        wordlist: Path to wordlist file.
        additional_args: Extra gobuster arguments.
    """
    if mode not in ("dir", "dns", "fuzz", "vhost"):
        return f"Invalid mode '{mode}'. Must be one of: dir, dns, fuzz, vhost"
    command = ["gobuster", mode, "-u", url, "-w", wordlist]
    if additional_args:
        command += shlex.split(additional_args)
    return _format_result(execute_command(command))


@mcp.tool()
def dirb(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> str:
    """Run dirb for web content discovery.

    Args:
        url: Target URL.
        wordlist: Path to wordlist file.
        additional_args: Extra dirb arguments.
    """
    command = ["dirb", url, wordlist]
    if additional_args:
        command += shlex.split(additional_args)
    return _format_result(execute_command(command))


@mcp.tool()
def nikto(target: str, additional_args: str = "") -> str:
    """Run nikto web server scanner.

    Args:
        target: Target host or URL.
        additional_args: Extra nikto arguments.
    """
    command = ["nikto", "-h", target]
    if additional_args:
        command += shlex.split(additional_args)
    return _format_result(execute_command(command))


@mcp.tool()
def sqlmap(url: str, data: str = "", additional_args: str = "") -> str:
    """Run sqlmap SQL injection scanner.

    Args:
        url: Target URL to test.
        data: POST data string (optional, for POST request testing).
        additional_args: Extra sqlmap arguments.
    """
    command = ["sqlmap", "-u", url, "--batch"]
    if data:
        command += ["--data", data]
    if additional_args:
        command += shlex.split(additional_args)
    return _format_result(execute_command(command))


@mcp.tool()
def metasploit(module: str, options: Dict[str, Any] = {}) -> str:
    """Run a Metasploit module.

    Args:
        module: Metasploit module path, e.g. 'exploit/multi/handler'.
        options: Dictionary of module options, e.g. {"RHOSTS": "10.0.0.1", "LPORT": 4444}.
    """
    if not re.match(r"^[a-zA-Z0-9/_-]+$", module):
        return "Invalid module name — only alphanumeric characters, slashes, underscores, and hyphens are allowed."

    resource_content = f"use {module}\n"
    for key, value in options.items():
        if not re.match(r"^[a-zA-Z0-9_]+$", str(key)):
            return f"Invalid option key: {key}"
        resource_content += f"set {key} {value}\n"
    resource_content += "exploit\n"

    resource_file = "/tmp/mcp_msf_resource.rc"
    with open(resource_file, "w") as f:
        f.write(resource_content)

    result = execute_command(["msfconsole", "-q", "-r", resource_file])

    try:
        os.remove(resource_file)
    except OSError:
        pass

    return _format_result(result)


@mcp.tool()
def hydra(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "",
    additional_args: str = "",
) -> str:
    """Run hydra for online password brute-forcing.

    Args:
        target: Target host.
        service: Service to attack (e.g. ssh, ftp, http-post-form).
        username: Single username to try.
        username_file: Path to username wordlist (used if username is empty).
        password: Single password to try.
        password_file: Path to password wordlist (used if password is empty).
        additional_args: Extra hydra arguments.
    """
    if not username and not username_file:
        return "Either username or username_file is required."
    if not password and not password_file:
        return "Either password or password_file is required."

    command = ["hydra", "-t", "4"]
    if username:
        command += ["-l", username]
    else:
        command += ["-L", username_file]
    if password:
        command += ["-p", password]
    else:
        command += ["-P", password_file]
    command += [target, service]
    if additional_args:
        command += shlex.split(additional_args)
    return _format_result(execute_command(command))


@mcp.tool()
def john(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
    additional_args: str = "",
) -> str:
    """Run John the Ripper for offline password cracking.

    Args:
        hash_file: Path to the file containing hashes.
        wordlist: Path to wordlist (default: rockyou.txt).
        format: Hash format (e.g. NT, sha256crypt). Leave empty for auto-detect.
        additional_args: Extra john arguments.
    """
    command = ["john"]
    if format:
        command.append(f"--format={format}")
    if wordlist:
        command.append(f"--wordlist={wordlist}")
    if additional_args:
        command += shlex.split(additional_args)
    command.append(hash_file)
    return _format_result(execute_command(command))


@mcp.tool()
def wpscan(url: str, additional_args: str = "") -> str:
    """Run WPScan WordPress vulnerability scanner.

    Args:
        url: Target WordPress URL.
        additional_args: Extra wpscan arguments.
    """
    command = ["wpscan", "--url", url]
    if additional_args:
        command += shlex.split(additional_args)
    return _format_result(execute_command(command))


@mcp.tool()
def enum4linux(target: str, additional_args: str = "-a") -> str:
    """Run enum4linux for SMB/Samba enumeration.

    Args:
        target: Target IP or hostname.
        additional_args: Extra enum4linux arguments (default: -a for all enumeration).
    """
    command = ["enum4linux"] + shlex.split(additional_args) + [target]
    return _format_result(execute_command(command))
