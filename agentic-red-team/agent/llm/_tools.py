"""Tool subsets for each phase agent.

Each function returns a list of tool objects. Import and call these in phase
modules rather than importing individual tools everywhere.
"""

from agent.tools.kali_api import (
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
)
from agent.tools.kali_api import get_tools as get_all_tools  # noqa: F401


# ── Phase 1: Recon (passive only) ──────────────────────────────────
def recon_tools() -> list:
    return [kali_command, kali_read_file, kali_list_files]


# ── Phase 2: Scanning & Enumeration ────────────────────────────────
def scanning_tools() -> list:
    return [
        nmap, masscan,
        whatweb, gobuster, dirb, nikto, wpscan, sslscan,
        enum4linux, smbclient, crackmapexec,
        kali_command, kali_read_file, kali_list_files,
    ]


# ── Phase 3: Vulnerability identification ──────────────────────────
def vuln_id_tools() -> list:
    return [searchsploit, nmap, nikto, sslscan, kali_command, kali_read_file]


# ── Phase 4: Exploitation ───────────────────────────────────────────
def exploit_tools() -> list:
    return [
        metasploit, msfvenom,
        sqlmap, nikto,
        hydra, john, hashcat,
        crackmapexec, impacket, smbclient,
        kali_command, kali_read_file, kali_list_files,
    ]


# ── Phase 5: Post-exploitation ─────────────────────────────────────
def post_exploit_tools() -> list:
    return [
        metasploit,
        impacket,
        linpeas,
        crackmapexec,
        kali_command,
        kali_read_file,
        kali_list_files,
        kali_upload_file,
        kali_delete_file,
    ]
