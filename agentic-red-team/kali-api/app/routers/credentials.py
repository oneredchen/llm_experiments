"""Credential attack tool endpoints: hydra, john, hashcat, crackmapexec."""

import logging
import shlex
import traceback

from fastapi import APIRouter, HTTPException

from services.command_executor import execute_command
from routers.schemas import (
    HydraRequest,
    JohnRequest,
    HashcatRequest,
    CrackmapexecRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tools", tags=["credentials"])


@router.post("/hydra")
def hydra(req: HydraRequest):
    """Run hydra credential brute-forcing."""
    try:
        if not req.target or not req.service:
            raise HTTPException(
                status_code=400, detail="target and service are required"
            )
        if not (req.username or req.username_file) or not (
            req.password or req.password_file
        ):
            raise HTTPException(
                status_code=400,
                detail="username/username_file and password/password_file are required",
            )
        command = ["hydra", "-t", "4"]
        if req.username:
            command += ["-l", req.username]
        elif req.username_file:
            command += ["-L", req.username_file]
        if req.password:
            command += ["-p", req.password]
        elif req.password_file:
            command += ["-P", req.password_file]
        command += [req.target, req.service]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/john")
def john(req: JohnRequest):
    """Run John the Ripper to crack password hashes."""
    try:
        if not req.hash_file:
            raise HTTPException(status_code=400, detail="hash_file is required")
        command = ["john"]
        if req.format:
            command.append(f"--format={req.format}")
        if req.wordlist:
            command.append(f"--wordlist={req.wordlist}")
        if req.additional_args:
            command += shlex.split(req.additional_args)
        command.append(req.hash_file)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hashcat")
def hashcat(req: HashcatRequest):
    """Run hashcat GPU-accelerated password cracking against a hash file."""
    try:
        if not req.hash_file:
            raise HTTPException(status_code=400, detail="hash_file is required")
        command = [
            "hashcat",
            f"-m{req.hash_type}",
            f"-a{req.attack_mode}",
            "--force",  # suppress GPU warnings in VM environments
            "--status",
            "--status-timer=30",
            req.hash_file,
        ]
        if req.attack_mode == 0 and req.wordlist:
            command.append(req.wordlist)
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/crackmapexec")
def crackmapexec(req: CrackmapexecRequest):
    """Validate credentials and enumerate services over SMB/SSH/WinRM/LDAP/RDP via netexec (nxc)."""
    try:
        if not req.target or not req.protocol:
            raise HTTPException(
                status_code=400, detail="target and protocol are required"
            )
        if req.protocol not in ("smb", "ssh", "winrm", "ldap", "rdp", "ftp"):
            raise HTTPException(
                status_code=400, detail=f"Unsupported protocol: {req.protocol}"
            )

        command = ["nxc", req.protocol, req.target]

        if req.username:
            command += ["-u", req.username]
        elif req.username_file:
            command += ["-u", req.username_file]

        if req.password:
            command += ["-p", req.password]
        elif req.password_file:
            command += ["-p", req.password_file]

        if req.additional_args:
            command += shlex.split(req.additional_args)

        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
