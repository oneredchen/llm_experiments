# Feature 2: Asynchronous Extraction Jobs with Live Progress

## Overview

Run the IOC extraction workflow as a background job with a pollable status endpoint and live
progress in the UI. Today `POST /cases/{case_id}/extract` (`backend/routers/workflow.py`) runs
the whole LangGraph workflow synchronously inside the request handler — with a local Ollama
model this can block for several minutes, ties up the browser request, gives no feedback, and
fails entirely on timeout. During an active incident, analysts paste notes continuously; they
cannot wait on a frozen spinner.

## Current state

- `backend/routers/workflow.py:20` — `extract_iocs` calls `ioc_extraction_agent_workflow()`
  inline and inserts results before responding.
- `backend/utils/ioc_extraction_workflow.py` — LangGraph graph: `triage` → parallel
  `extract_host` / `extract_network` / `extract_timeline`. Node boundaries are natural
  progress checkpoints.
- `frontend/components/extraction-panel.tsx` — fires the request and waits.

## Design

- In-process job manager (no Redis/Celery — the app is local-first, single user). A module-level
  `ThreadPoolExecutor(max_workers=1)` plus a jobs table for persistence across restarts.
- New `extraction_jobs` table in `backend/utils/database.py`:
  `id`, `job_id (uuid, unique)`, `case_id (FK)`, `status` (queued | running | succeeded | failed),
  `current_step` (triage | extract_host | extract_network | extract_timeline | saving),
  `llm_model`, `incident_description (Text)`, `error (Text)`, `counts_json (Text)`,
  `created_at`, `started_at`, `finished_at`.
- Progress reporting: pass a `progress_callback(step: str)` into the workflow; each LangGraph
  node calls it on entry. (Alternative considered: LangGraph `stream()` events — fine too, but a
  callback keeps `ioc_extraction_agent_workflow`'s public API simple.)

## Implementation tasks

### Backend

- [ ] Add the `ExtractionJob` model + helpers (`create_job`, `update_job`, `get_job`,
      `get_jobs_for_case`) in `backend/utils/database.py`.
- [ ] New module `backend/utils/job_manager.py`:
      - `submit_extraction(case_id, incident_description, llm_model) -> job_id`
      - Worker function: mark `running`, invoke workflow with progress callback, insert
        results (reuse the insert logic currently in `backend/routers/workflow.py`), mark
        `succeeded` with counts, or `failed` with the exception message.
      - On app startup, mark any orphaned `queued`/`running` jobs as `failed` ("server restarted").
- [ ] Modify `ioc_extraction_agent_workflow()` to accept an optional `progress_callback` and
      thread it through the LangGraph nodes (e.g. via `WorkflowState`).
- [ ] Rework `backend/routers/workflow.py`:
      - `POST /cases/{case_id}/extract` → validates the case exists, submits a job, returns
        `202 {"job_id": ...}` immediately.
      - `GET /jobs/{job_id}` → status, current_step, counts, error, timestamps.
      - `GET /cases/{case_id}/jobs` → job history for the case (most recent first).
      - Keep a `?sync=true` query param that preserves the old blocking behaviour so
        `tests/test_workflow.py` and any scripts keep working.
- [ ] Reject a new job for a case that already has one `queued`/`running` (409) to avoid
      duplicate inserts from double-clicks.

### Frontend

- [ ] `frontend/lib/api.ts`: `startExtraction` now returns `{ job_id }`; add `getJob(jobId)` and
      `getCaseJobs(caseId)`.
- [ ] `frontend/components/extraction-panel.tsx`:
      - After submit, poll `GET /jobs/{job_id}` every 2s.
      - Progress UI: stepper or progress bar showing Triage → Extract (host/network/timeline) →
        Saving, with elapsed time.
      - On `succeeded`: toast with counts, refresh case data, clear the textarea.
      - On `failed`: show the error inline with a Retry button.
      - The panel stays usable — analyst can navigate to other cases while a job runs; on
        returning to a case with a running job, resume polling (derive from `getCaseJobs`).
- [ ] Small job-history list (last 5 jobs: model, status, duration, counts) under the panel.

## Testing

- [ ] `tests/test_jobs.py` (pytest + TestClient):
      - Monkeypatch `ioc_extraction_agent_workflow` with a stub that sleeps briefly, calls the
        progress callback, and returns fixed objects → assert 202, status transitions
        queued→running→succeeded, counts persisted, artifacts inserted.
      - Stub that raises → job ends `failed` with error message; no partial inserts.
      - Second POST while a job is running → 409.
      - `?sync=true` still returns the old-shape 200 response.
      - `GET /jobs/{unknown}` → 404.
- [ ] Restart-recovery test: create a `running` row directly, call the startup hook, assert it
      becomes `failed`.
- [ ] Manual E2E with a real Ollama model on one of `cases/case_01.txt`–`case_20.txt`: verify
      live step updates and final counts match the sync path.

## Success criteria

1. `POST /extract` returns in < 500 ms; the browser is never blocked during extraction.
2. The UI shows which workflow step is running and total elapsed time, updating at least every 2 s.
3. A failed extraction surfaces the error and is retryable without losing the pasted text.
4. Killing/restarting the backend never leaves a job stuck in `running`.
5. Existing sync behaviour remains available and `tests/test_workflow.py` passes unmodified
   (aside from opting into `sync=true` if needed).
