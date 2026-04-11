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


# ──────────────────────────────────────────────────────────────────────
# Recon Tools  (kali-api: routers/recon.py — prefix /api/tools)
# ──────────────────────────────────────────────────────────────────────

@tool
async def run_command(command: str) -> str:
    """Run an arbitrary non-interactive shell command on the Kali machine.
    Only use for commands that exit on their own (curl, dig, whois, etc.).
    Never use nc, netcat, or anything that opens an interactive session."""
    return await _api_post("/api/tools/command", {"command": command})


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
async def masscan(target: str, ports: str = "0-65535", rate: int = 1000, additional_args: str = "") -> str:
    """Fast port discovery across large port ranges. Use before nmap to find open ports quickly,
    then run nmap -sCV only against the discovered ports.
    rate: packets/sec — keep ≤1000 on shared networks to avoid drops."""
    return await _api_post("/api/tools/masscan", {"target": target, "ports": ports, "rate": rate, "additional_args": additional_args})


@tool
async def searchsploit(query: str, additional_args: str = "") -> str:
    """Search ExploitDB for known public exploits matching a service name or version string.
    query: e.g. 'vsftpd 2.3.4', 'Apache 2.2', 'Samba 3.0.20', 'ProFTPD 1.3.1'"""
    return await _api_post("/api/tools/searchsploit", {"query": query, "additional_args": additional_args})


@tool
async def whatweb(target: str, aggression: int = 1, additional_args: str = "") -> str:
    """Fingerprint web technologies, CMS, JavaScript frameworks, and server headers.
    aggression: 1=passive/stealthy, 3=aggressive (more requests), 4=heavy."""
    return await _api_post("/api/tools/whatweb", {"target": target, "aggression": aggression, "additional_args": additional_args})


@tool
async def sslscan(target: str, additional_args: str = "") -> str:
    """Scan SSL/TLS configuration for weak ciphers, expired certificates, and known vulnerabilities
    (POODLE, Heartbleed, BEAST, CRIME). target: host or host:port."""
    return await _api_post("/api/tools/sslscan", {"target": target, "additional_args": additional_args})


# ──────────────────────────────────────────────────────────────────────
# Web Tools  (kali-api: routers/web.py — prefix /api/tools)
# ──────────────────────────────────────────────────────────────────────

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
async def wpscan(url: str, additional_args: str = "") -> str:
    """Run WPScan WordPress vulnerability scanner against a URL."""
    return await _api_post("/api/tools/wpscan", {"url": url, "additional_args": additional_args})


# ──────────────────────────────────────────────────────────────────────
# Exploitation Tools  (kali-api: routers/exploitation.py — prefix /api/tools)
# ──────────────────────────────────────────────────────────────────────

@tool
async def metasploit(module: str, options: dict[str, Any] = {}) -> str:
    """Run a Metasploit module non-interactively.
    module: full module path e.g. 'exploit/unix/irc/unreal_ircd_3281_backdoor'.
    options: dict of MSF options e.g. {'RHOSTS': '192.168.1.1', 'LHOST': '192.168.1.2'}.
    Use this instead of nc/netcat for any exploit that requires a shell connection."""
    return await _api_post("/api/tools/metasploit", {"module": module, "options": options})


@tool
async def msfvenom(
    payload: str,
    lhost: str = "",
    lport: int = 4444,
    format: str = "elf",
    output: str = "/tmp/kali-loot/payload",
    additional_args: str = "",
) -> str:
    """Generate a standalone payload with msfvenom, saved to the loot directory.
    payload: e.g. 'linux/x86/meterpreter/reverse_tcp', 'windows/x64/meterpreter/reverse_tcp'.
    format: elf (Linux), exe (Windows), py, raw, etc.
    Returns the path to the generated file."""
    return await _api_post("/api/tools/msfvenom", {
        "payload": payload, "lhost": lhost, "lport": lport,
        "format": format, "output": output, "additional_args": additional_args,
    })


# ──────────────────────────────────────────────────────────────────────
# Credential Tools  (kali-api: routers/credentials.py — prefix /api/tools)
# ──────────────────────────────────────────────────────────────────────

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
async def hashcat(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    hash_type: int = 0,
    attack_mode: int = 0,
    additional_args: str = "",
) -> str:
    """GPU-accelerated password cracking. Faster than john for NTLM and modern hashes.
    hash_type: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt.
    attack_mode: 0=dictionary, 3=brute-force mask."""
    return await _api_post("/api/tools/hashcat", {
        "hash_file": hash_file, "wordlist": wordlist,
        "hash_type": hash_type, "attack_mode": attack_mode, "additional_args": additional_args,
    })


@tool
async def crackmapexec(
    protocol: str,
    target: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "",
    additional_args: str = "",
) -> str:
    """Validate credentials and enumerate accessible services via netexec (nxc).
    protocol: smb | ssh | winrm | ldap | rdp | ftp.
    Use after hydra to confirm working credentials, check share access, or spray passwords.
    additional_args examples: '--shares' (list SMB shares), '--sam' (dump SAM), '--users'."""
    return await _api_post("/api/tools/crackmapexec", {
        "protocol": protocol, "target": target,
        "username": username, "username_file": username_file,
        "password": password, "password_file": password_file,
        "additional_args": additional_args,
    })


# ──────────────────────────────────────────────────────────────────────
# Post-Exploitation Tools  (kali-api: routers/post_exploit.py — prefix /api/tools)
# ──────────────────────────────────────────────────────────────────────

@tool
async def enum4linux(target: str, additional_args: str = "-a") -> str:
    """Run enum4linux SMB/NetBIOS enumeration against a target."""
    return await _api_post("/api/tools/enum4linux", {"target": target, "additional_args": additional_args})


@tool
async def smbclient(
    target: str,
    share: str,
    username: str = "",
    password: str = "",
    command: str = "ls",
    additional_args: str = "",
) -> str:
    """Access an SMB share and run a single command.
    command examples: 'ls', 'get filename', 'put localfile remotefile', 'recurse ON; ls'.
    Leave username/password empty for anonymous access."""
    return await _api_post("/api/tools/smbclient", {
        "target": target, "share": share, "username": username,
        "password": password, "command": command, "additional_args": additional_args,
    })


@tool
async def impacket(
    tool: str,
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    hash: str = "",
    additional_args: str = "",
) -> str:
    """Run an Impacket tool for Windows/AD attacks.
    tool: secretsdump | psexec | smbexec | GetNPUsers | GetUserSPNs.
    hash: NTLM hash for pass-the-hash in LM:NT format (e.g. aad3b435b51404eeaad3b435b51404ee:hash).
    secretsdump: dumps SAM/NTDS hashes. psexec/smbexec: remote command execution.
    GetNPUsers: find AS-REP roastable accounts. GetUserSPNs: find Kerberoastable accounts."""
    return await _api_post("/api/tools/impacket", {
        "tool": tool, "target": target, "username": username,
        "password": password, "domain": domain, "hash": hash,
        "additional_args": additional_args,
    })


@tool
async def linpeas(target_os: str = "linux") -> str:
    """Stage linpeas (Linux) or winpeas (Windows) in the loot directory for upload to a target.
    Returns the staged file path. Upload to the target with Metasploit:
      use post/multi/manage/upload; set SESSION <id>; set SRC <path>; set DEST /tmp/; run
    Then execute: post/multi/manage/shell_to_meterpreter → shell → chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh"""
    return await _api_post("/api/tools/linpeas", {"target_os": target_os})


# ──────────────────────────────────────────────────────────────────────
# File Management  (kali-api: routers/files.py — prefix /api/files)
# ──────────────────────────────────────────────────────────────────────

@tool
async def read_file(path: str) -> str:
    """Read the content of a file from the Kali machine.
    path: absolute path (e.g. /root/.msf4/loot/hash.txt) or relative to loot directory.
    Returns file content as text. Binary files are returned as base64."""
    try:
        async with _client() as c:
            r = await c.get("/api/files/read", params={"path": path})
            r.raise_for_status()
            data = r.json()
            if data.get("encoding") == "base64":
                return f"[binary file — base64]\n{data['content']}"
            return data["content"]
    except httpx.HTTPStatusError as e:
        return f"TOOL ERROR: HTTP {e.response.status_code} — {e.response.text[:300]}"
    except Exception as e:
        return f"TOOL ERROR: {type(e).__name__}: {e}"


@tool
async def list_files(path: str = "") -> str:
    """List files and directories at a path on the Kali machine.
    path: absolute path or relative to loot directory (defaults to loot directory root).
    Useful for browsing Metasploit loot (/root/.msf4/loot/) or captured files."""
    try:
        async with _client() as c:
            r = await c.get("/api/files/list", params={"path": path})
            r.raise_for_status()
            data = r.json()
            lines = [f"  {e['type'][0].upper()}  {e['name']}" + (f"  ({e['size']} bytes)" if e["size"] is not None else "") for e in data["entries"]]
            return f"{data['path']}/\n" + ("\n".join(lines) if lines else "  (empty)")
    except httpx.HTTPStatusError as e:
        return f"TOOL ERROR: HTTP {e.response.status_code} — {e.response.text[:300]}"
    except Exception as e:
        return f"TOOL ERROR: {type(e).__name__}: {e}"


@tool
async def upload_file(local_path: str, dest_path: str = "") -> str:
    """Upload a file from the Kali machine's local filesystem to the loot directory.
    local_path: absolute path to the file on the Kali machine to read and upload.
    dest_path: optional subdirectory/filename within the loot directory (e.g. 'wordlists/custom.txt').
    If dest_path is empty, the original filename is used."""
    try:
        async with _client() as c:
            # Read the file content first, then upload via multipart
            read_resp = await c.get("/api/files/read", params={"path": local_path})
            read_resp.raise_for_status()
            data = read_resp.json()
            content = data["content"].encode("utf-8")

            files = {"file": (local_path.split("/")[-1], content)}
            r = await c.post("/api/files/upload", files=files, data={"path": dest_path} if dest_path else {})
            r.raise_for_status()
            result = r.json()
            return f"Uploaded to: {result['path']} ({result['size']} bytes)"
    except httpx.HTTPStatusError as e:
        return f"TOOL ERROR: HTTP {e.response.status_code} — {e.response.text[:300]}"
    except Exception as e:
        return f"TOOL ERROR: {type(e).__name__}: {e}"


@tool
async def delete_file(path: str) -> str:
    """Delete a file from the loot directory on the Kali machine.
    path: relative path within the loot directory.
    Use for cleanup after extracting sensitive data."""
    try:
        async with _client() as c:
            r = await c.request("DELETE", "/api/files", params={"path": path})
            r.raise_for_status()
            result = r.json()
            return f"Deleted: {result['deleted']}"
    except httpx.HTTPStatusError as e:
        return f"TOOL ERROR: HTTP {e.response.status_code} — {e.response.text[:300]}"
    except Exception as e:
        return f"TOOL ERROR: {type(e).__name__}: {e}"


# ──────────────────────────────────────────────────────────────────────
# Tool Registry
# ──────────────────────────────────────────────────────────────────────

def get_tools() -> list:
    return [
        # Recon  (routers/recon.py)
        run_command,
        nmap,
        masscan,
        searchsploit,
        whatweb,
        sslscan,
        # Web  (routers/web.py)
        gobuster,
        dirb,
        nikto,
        sqlmap,
        wpscan,
        # Exploitation  (routers/exploitation.py)
        metasploit,
        msfvenom,
        # Credentials  (routers/credentials.py)
        hydra,
        john,
        hashcat,
        crackmapexec,
        # Post-exploitation  (routers/post_exploit.py)
        enum4linux,
        smbclient,
        impacket,
        linpeas,
        # Files  (routers/files.py)
        read_file,
        list_files,
        upload_file,
        delete_file,
    ]