"""Pydantic request schemas for tool endpoints."""

from typing import Any, Dict

from pydantic import BaseModel, Field


class CommandRequest(BaseModel):
    command: str


class StartJobRequest(BaseModel):
    command: str
    timeout: int = 300


class NmapRequest(BaseModel):
    target: str
    scan_type: str = "-sCV"
    ports: str = ""
    additional_args: str = "-T4 -Pn"


class GobusterRequest(BaseModel):
    url: str
    mode: str = "dir"
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = ""


class DirbRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = ""


class NiktoRequest(BaseModel):
    target: str
    additional_args: str = ""


class SqlmapRequest(BaseModel):
    url: str
    data: str = ""
    additional_args: str = ""


class MetasploitRequest(BaseModel):
    module: str
    options: Dict[str, Any] = Field(default_factory=dict)


class HydraRequest(BaseModel):
    target: str
    service: str
    username: str = ""
    username_file: str = ""
    password: str = ""
    password_file: str = ""
    additional_args: str = ""


class JohnRequest(BaseModel):
    hash_file: str
    wordlist: str = "/usr/share/wordlists/rockyou.txt"
    format: str = ""
    additional_args: str = ""


class WpscanRequest(BaseModel):
    url: str
    additional_args: str = ""


class Enum4linuxRequest(BaseModel):
    target: str
    additional_args: str = "-a"


# --- Recon ---

class SearchsploitRequest(BaseModel):
    query: str
    additional_args: str = ""


class WhatwebRequest(BaseModel):
    target: str
    aggression: int = 1  # 1=stealthy, 3=aggressive, 4=heavy
    additional_args: str = ""


class SslscanRequest(BaseModel):
    target: str  # host or host:port
    additional_args: str = ""


class MasscanRequest(BaseModel):
    target: str
    ports: str = "0-65535"
    rate: int = 1000
    additional_args: str = ""


# --- Exploitation ---

class MsfvenomRequest(BaseModel):
    payload: str           # e.g. linux/x86/meterpreter/reverse_tcp
    lhost: str = ""
    lport: int = 4444
    format: str = "elf"    # elf, exe, py, raw, etc.
    output: str = "/tmp/kali-loot/payload"
    additional_args: str = ""


# --- Credentials ---

class HashcatRequest(BaseModel):
    hash_file: str
    wordlist: str = "/usr/share/wordlists/rockyou.txt"
    hash_type: int = 0     # hashcat -m value; 0=MD5, 1000=NTLM, 1800=sha512crypt
    attack_mode: int = 0   # 0=dictionary, 3=brute-force
    additional_args: str = ""


class CrackmapexecRequest(BaseModel):
    protocol: str          # smb, ssh, winrm, ldap, rdp, ftp
    target: str
    username: str = ""
    username_file: str = ""
    password: str = ""
    password_file: str = ""
    additional_args: str = ""


# --- Post-exploitation ---

class SmbclientRequest(BaseModel):
    target: str
    share: str
    username: str = ""
    password: str = ""
    command: str = "ls"    # smbclient -c command
    additional_args: str = ""


class ImpacketRequest(BaseModel):
    tool: str              # secretsdump | psexec | GetNPUsers | GetUserSPNs | smbexec
    target: str            # IP or domain/user:pass@IP
    username: str = ""
    password: str = ""
    domain: str = ""
    hash: str = ""         # NTLM hash for pass-the-hash (LM:NT format)
    additional_args: str = ""


class LinpeasRequest(BaseModel):
    target_os: str = "linux"   # linux | windows
    # Stages the script in the loot dir; upload to target via metasploit
