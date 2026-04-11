"""Tool subsets for phase orchestrators and subagents.

Each function returns a list of tool objects. Import and call these in phase
modules rather than importing individual tools everywhere.
"""

from agent.tools.kali_api import (
    run_command,
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
    read_file,
    list_files,
    upload_file,
    delete_file,
)
from agent.tools.kali_api import get_tools as get_all_tools  # noqa: F401


# ── Phase 1: Recon (passive only) ──────────────────────────────────
def recon_tools() -> list:
    return [run_command, read_file, list_files]


# ── Phase 2: Scanning orchestrator (port discovery) ────────────────
def scanning_tools() -> list:
    return [nmap, masscan, run_command]


# ── Phase 2 subagent tool sets ─────────────────────────────────────
def http_enum_tools() -> list:
    return [whatweb, gobuster, dirb, nikto, wpscan, sslscan, run_command]


def smb_enum_tools() -> list:
    return [enum4linux, smbclient, crackmapexec, run_command]


def ftp_enum_tools() -> list:
    return [run_command, read_file, list_files]


def ssh_enum_tools() -> list:
    return [run_command]


def generic_enum_tools() -> list:
    return [nmap, run_command]


# ── Phase 3: Vulnerability identification ──────────────────────────
def vuln_id_tools() -> list:
    return [searchsploit, nmap, nikto, sslscan, run_command, read_file]


# ── Phase 4 subagent tool sets ─────────────────────────────────────
def msf_exploit_tools() -> list:
    return [metasploit, msfvenom, run_command, read_file, list_files]


def web_exploit_tools() -> list:
    return [sqlmap, nikto, run_command, read_file]


def cred_exploit_tools() -> list:
    return [hydra, crackmapexec, john, hashcat, run_command, read_file]


def smb_exploit_tools() -> list:
    return [metasploit, crackmapexec, impacket, smbclient, run_command]


# ── Phase 5: Post-exploitation ─────────────────────────────────────
def post_exploit_tools() -> list:
    return [
        metasploit, impacket, linpeas, crackmapexec,
        run_command, read_file, list_files, upload_file, delete_file,
    ]
