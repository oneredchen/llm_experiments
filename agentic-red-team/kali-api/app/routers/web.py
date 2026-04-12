"""Web application tool endpoints: gobuster, dirb, nikto, sqlmap, wpscan."""

import logging
import shlex
import traceback

from fastapi import APIRouter, HTTPException

from services.command_executor import execute_command
from routers.schemas import GobusterRequest, DirbRequest, NiktoRequest, SqlmapRequest, WpscanRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tools", tags=["web"])


@router.post("/gobuster")
def gobuster(req: GobusterRequest):
    """Run gobuster directory/DNS/vhost brute-forcing."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="url is required")
        if req.mode not in ("dir", "dns", "fuzz", "vhost"):
            raise HTTPException(status_code=400, detail=f"Invalid mode: {req.mode}")
        command = ["gobuster", req.mode, "-u", req.url, "-w", req.wordlist]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dirb")
def dirb(req: DirbRequest):
    """Run dirb web content scanner."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="url is required")
        command = ["dirb", req.url, req.wordlist]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nikto")
def nikto(req: NiktoRequest):
    """Run nikto web server vulnerability scanner."""
    try:
        if not req.target:
            raise HTTPException(status_code=400, detail="target is required")
        command = ["nikto", "-h", req.target]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sqlmap")
def sqlmap(req: SqlmapRequest):
    """Run sqlmap SQL injection scanner."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="url is required")
        command = ["sqlmap", "-u", req.url, "--batch"]
        if req.data:
            command += ["--data", req.data]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/wpscan")
def wpscan(req: WpscanRequest):
    """Run WPScan WordPress vulnerability scanner."""
    try:
        if not req.url:
            raise HTTPException(status_code=400, detail="url is required")
        command = ["wpscan", "--url", req.url]
        if req.additional_args:
            command += shlex.split(req.additional_args)
        return execute_command(command, timeout=req.timeout)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))