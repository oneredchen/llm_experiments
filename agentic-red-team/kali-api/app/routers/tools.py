import logging
import os
import re
import shlex
import traceback

from fastapi import APIRouter, HTTPException

from services.command_executor import execute_command
from routers.schemas import (
    CommandRequest,
    NmapRequest,
    GobusterRequest,
    DirbRequest,
    NiktoRequest,
    SqlmapRequest,
    MetasploitRequest,
    HydraRequest,
    JohnRequest,
    WpscanRequest,
    Enum4linuxRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/api/command")
def generic_command(req: CommandRequest):
    """Execute any command provided in the request."""
    try:
        if not req.command:
            raise HTTPException(status_code=400, detail="Command parameter is required")

        return execute_command(req.command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/nmap")
def nmap(req: NmapRequest):
    """Execute nmap scan with the provided parameters."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="Target parameter is required")

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
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/gobuster")
def gobuster(req: GobusterRequest):
    """Execute gobuster with the provided parameters."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="URL parameter is required")

        if req.mode not in ["dir", "dns", "fuzz", "vhost"]:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid mode: {req.mode}. Must be one of: dir, dns, fuzz, vhost",
            )

        command = ["gobuster", req.mode, "-u", req.url, "-w", req.wordlist]

        if req.additional_args:
            command += shlex.split(req.additional_args)

        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/dirb")
def dirb(req: DirbRequest):
    """Execute dirb with the provided parameters."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="URL parameter is required")

        command = ["dirb", req.url, req.wordlist]

        if req.additional_args:
            command += shlex.split(req.additional_args)

        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/nikto")
def nikto(req: NiktoRequest):
    """Execute nikto with the provided parameters."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="Target parameter is required")

        command = ["nikto", "-h", req.target]

        if req.additional_args:
            command += shlex.split(req.additional_args)

        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/sqlmap")
def sqlmap(req: SqlmapRequest):
    """Execute sqlmap with the provided parameters."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="URL parameter is required")

        command = ["sqlmap", "-u", req.url, "--batch"]

        if req.data:
            command += ["--data", req.data]

        if req.additional_args:
            command += shlex.split(req.additional_args)

        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/metasploit")
def metasploit(req: MetasploitRequest):
    """Execute metasploit module with the provided parameters."""
    try:
        if not req.module:
            raise HTTPException(status_code=400, detail="Module parameter is required")

        # Validate module name (allow only alphanumeric, slashes, underscores, hyphens)
        if not re.match(r"^[a-zA-Z0-9/_-]+$", req.module):
            raise HTTPException(status_code=400, detail="Invalid module name")

        # Create an MSF resource script with validated options
        resource_content = f"use {req.module}\n"
        for key, value in req.options.items():
            # Validate option keys
            if not re.match(r"^[a-zA-Z0-9_]+$", str(key)):
                raise HTTPException(
                    status_code=400, detail=f"Invalid option key: {key}"
                )
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mks_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = ["msfconsole", "-q", "-r", resource_file]
        result = execute_command(command)

        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/hydra")
def hydra(req: HydraRequest):
    """Execute hydra with the provided parameters."""
    try:
        if not req.target or not req.service:
            raise HTTPException(
                status_code=400,
                detail="Target and service parameters are required",
            )

        if not (req.username or req.username_file) or not (
            req.password or req.password_file
        ):
            raise HTTPException(
                status_code=400,
                detail="Username/username_file and password/password_file are required",
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

        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/john")
def john(req: JohnRequest):
    """Execute john with the provided parameters."""
    try:
        if not req.hash_file:
            raise HTTPException(
                status_code=400, detail="Hash file parameter is required"
            )

        command = ["john"]

        if req.format:
            command.append(f"--format={req.format}")

        if req.wordlist:
            command.append(f"--wordlist={req.wordlist}")

        if req.additional_args:
            command += shlex.split(req.additional_args)

        command.append(req.hash_file)
        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/wpscan")
def wpscan(req: WpscanRequest):
    """Execute wpscan with the provided parameters."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="URL parameter is required")

        command = ["wpscan", "--url", req.url]

        if req.additional_args:
            command += shlex.split(req.additional_args)

        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.post("/api/tools/enum4linux")
def enum4linux(req: Enum4linuxRequest):
    """Execute enum4linux with the provided parameters."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="Target parameter is required")

        command = ["enum4linux"] + shlex.split(req.additional_args) + [req.target]
        return execute_command(command)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
