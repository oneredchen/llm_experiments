"""File management endpoints for loot, payloads, and tool output."""

import base64
import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import FileResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/files", tags=["files"])

LOOT_DIR = Path(os.environ.get("LOOT_DIR", "/tmp/kali-loot"))
LOOT_DIR.mkdir(parents=True, exist_ok=True)


def _safe_path(path: str) -> Path:
    """Resolve path and ensure it doesn't escape LOOT_DIR via traversal."""
    resolved = (LOOT_DIR / path).resolve()
    if not str(resolved).startswith(str(LOOT_DIR.resolve())):
        raise HTTPException(status_code=400, detail="Path outside loot directory")
    return resolved


@router.post("/upload")
async def upload_file(path: str = "", file: UploadFile = File(...)):
    """Upload a file to the loot directory.
    path: optional subdirectory within the loot directory (e.g. 'wordlists/custom.txt').
    """
    dest = _safe_path(path if path else file.filename)
    dest.parent.mkdir(parents=True, exist_ok=True)
    content = await file.read()
    dest.write_bytes(content)
    logger.info("Uploaded %s (%d bytes) to %s", file.filename, len(content), dest)
    return {"path": str(dest), "size": len(content)}


@router.get("/read")
def read_file(path: str):
    """Read a file from anywhere on the filesystem and return its content as text.
    For binary files, content is returned as base64.
    path: absolute path or relative to loot directory.
    """
    # Allow absolute paths (for reading Metasploit loot, /etc/passwd copies, etc.)
    resolved = Path(path).resolve() if path.startswith("/") else _safe_path(path)

    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {resolved}")
    if not resolved.is_file():
        raise HTTPException(status_code=400, detail=f"Not a file: {resolved}")

    try:
        content = resolved.read_text(encoding="utf-8", errors="strict")
        return {"path": str(resolved), "content": content, "encoding": "utf-8"}
    except UnicodeDecodeError:
        content = base64.b64encode(resolved.read_bytes()).decode("ascii")
        return {"path": str(resolved), "content": content, "encoding": "base64"}


@router.get("/list")
def list_files(path: str = ""):
    """List files and directories at a given path.
    path: absolute path or relative to loot directory (defaults to loot directory root).
    """
    resolved = Path(path).resolve() if path.startswith("/") else (
        _safe_path(path) if path else LOOT_DIR.resolve()
    )

    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {resolved}")
    if not resolved.is_dir():
        raise HTTPException(status_code=400, detail=f"Not a directory: {resolved}")

    entries = []
    for entry in sorted(resolved.iterdir()):
        entries.append({
            "name": entry.name,
            "path": str(entry),
            "type": "dir" if entry.is_dir() else "file",
            "size": entry.stat().st_size if entry.is_file() else None,
        })
    return {"path": str(resolved), "entries": entries}


@router.delete("")
def delete_file(path: str):
    """Delete a file from the loot directory."""
    resolved = _safe_path(path)
    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {resolved}")
    if resolved.is_dir():
        raise HTTPException(status_code=400, detail="Use a file path, not a directory")
    resolved.unlink()
    logger.info("Deleted %s", resolved)
    return {"deleted": str(resolved)}