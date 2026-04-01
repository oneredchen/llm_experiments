"""Pydantic request schemas for tool endpoints."""

from typing import Any, Dict

from pydantic import BaseModel, Field


class CommandRequest(BaseModel):
    command: str


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
