"""Reconnaissance tool endpoints: nmap, masscan, searchsploit, whatweb, sslscan."""

import logging
import shlex
import traceback

from fastapi import APIRouter, HTTPException

from services.command_executor import execute_command
from routers.schemas import (
    NmapRequest,
    CommandRequest,
    SearchsploitRequest,
    WhatwebRequest,
    SslscanRequest,
    MasscanRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tools", tags=["recon"])


@router.post("/command")
def generic_command(req: CommandRequest):
    """Execute any non-interactive shell command on the Kali machine."""
    try:
        if not req.command:
            raise HTTPException(status_code=400, detail="command is required")
        return execute_command(req.command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nmap")
def nmap(req: NmapRequest):
    """Run an nmap scan against a target."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="target is required")
        command = ["nmap"] + shlex.split(req.scan_type)
        if req.ports:
            command += ["-p", req.ports]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        command.append(req.target)
        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/masscan")
def masscan(req: MasscanRequest):
    """Run masscan for high-speed port discovery across large port ranges."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="target is required")
        command = ["masscan", req.target, "-p", req.ports, "--rate", str(req.rate)]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/searchsploit")
def searchsploit(req: SearchsploitRequest):
    """Search ExploitDB for known exploits matching a service name or version string."""
    try:
        if not req.query:
            raise HTTPException(status_code=400, detail="query is required")
        command = ["searchsploit", "--color=never"] + shlex.split(req.query)
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/whatweb")
def whatweb(req: WhatwebRequest):
    """Fingerprint web technologies, CMS, frameworks, and server headers."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="target is required")
        command = ["whatweb", f"--aggression={req.aggression}", req.target]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sslscan")
def sslscan(req: SslscanRequest):
    """Scan SSL/TLS configuration for weak ciphers, expired certs, and known vulnerabilities."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="target is required")
        command = ["sslscan", "--no-color"]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        command.append(req.target)
        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))