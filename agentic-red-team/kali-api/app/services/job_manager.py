"""Thread-safe background job manager for long-running tool commands."""

import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel


class JobResult(BaseModel):
    job_id: str
    status: str  # pending | running | done | failed | cancelled
    command: str
    stdout: str = ""
    stderr: str = ""
    return_code: Optional[int] = None
    timed_out: bool = False
    created_at: str
    completed_at: Optional[str] = None


class JobManager:
    def __init__(self):
        self._jobs: dict[str, JobResult] = {}
        self._processes: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

    def start(self, command: str, timeout: int = 300) -> str:
        job_id = uuid.uuid4().hex[:8]
        job = JobResult(
            job_id=job_id,
            status="pending",
            command=command,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        with self._lock:
            self._jobs[job_id] = job

        thread = threading.Thread(
            target=self._run, args=(job_id, command, timeout), daemon=True
        )
        thread.start()
        return job_id

    def get(self, job_id: str) -> Optional[JobResult]:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.model_copy() if job else None

    def list_all(self) -> list[JobResult]:
        with self._lock:
            return [j.model_copy() for j in self._jobs.values()]

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            process = self._processes.get(job_id)
            job = self._jobs.get(job_id)
        if not process or not job or job.status not in ("pending", "running"):
            return False
        process.terminate()
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = "cancelled"
                job.completed_at = datetime.now(timezone.utc).isoformat()
        return True

    def _run(self, job_id: str, command: str, timeout: int) -> None:
        with self._lock:
            self._jobs[job_id].status = "running"

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        timed_out = False
        return_code = None
        status = "done"

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            with self._lock:
                self._processes[job_id] = process

            def read_stdout():
                for line in iter(process.stdout.readline, ""):
                    stdout_lines.append(line)

            def read_stderr():
                for line in iter(process.stderr.readline, ""):
                    stderr_lines.append(line)

            t_out = threading.Thread(target=read_stdout, daemon=True)
            t_err = threading.Thread(target=read_stderr, daemon=True)
            t_out.start()
            t_err.start()

            try:
                return_code = process.wait(timeout=timeout)
                t_out.join()
                t_err.join()
            except subprocess.TimeoutExpired:
                timed_out = True
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                return_code = -1

        except Exception as e:
            stderr_lines.append(f"Job execution error: {e}")
            status = "failed"

        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status != "cancelled":
                job.status = status
                job.stdout = "".join(stdout_lines)
                job.stderr = "".join(stderr_lines)
                job.return_code = return_code
                job.timed_out = timed_out
                job.completed_at = datetime.now(timezone.utc).isoformat()
            self._processes.pop(job_id, None)


# Module-level singleton shared across all requests
job_manager = JobManager()