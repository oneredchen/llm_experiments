"""Background job management endpoints."""

import logging

from fastapi import APIRouter, HTTPException

from services.job_manager import job_manager, JobResult
from routers.schemas import StartJobRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.post("", response_model=dict)
def start_job(req: StartJobRequest):
    """Start a command as a background job. Returns a job_id to poll with GET /api/jobs/{job_id}."""
    if not req.command.strip():
        raise HTTPException(status_code=400, detail="command is required")
    job_id = job_manager.start(req.command, timeout=req.timeout)
    logger.info("Started job %s: %s", job_id, req.command)
    return {"job_id": job_id, "status": "pending"}


@router.get("", response_model=list[JobResult])
def list_jobs():
    """List all jobs (pending, running, done, failed, cancelled)."""
    return job_manager.list_all()


@router.get("/{job_id}", response_model=JobResult)
def get_job(job_id: str):
    """Get status and output of a specific job."""
    job = job_manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@router.delete("/{job_id}", response_model=dict)
def cancel_job(job_id: str):
    """Cancel a running or pending job."""
    job = job_manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    cancelled = job_manager.cancel(job_id)
    if not cancelled:
        raise HTTPException(
            status_code=409,
            detail=f"Job {job_id} cannot be cancelled (status: {job.status})",
        )
    return {"job_id": job_id, "status": "cancelled"}