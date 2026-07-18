# Feature 8: Evidence File Attachments with Hashing & Chain of Custody

## Overview

Let analysts attach evidence files to a case — log exports, triage collections, screenshots,
phishing emails, reports — with automatic SHA-256/SHA-1/MD5 hashing at upload time, immutable
storage, and a custody log recording who added what and when. Optionally, text-based evidence
can be fed straight into the extraction workflow. An incident notebook that can't hold the
evidence itself forces analysts to juggle a parallel folder structure and lose the linkage
between artifacts and conclusions; recorded hashes are what let anyone later verify the
evidence wasn't altered.

## Current state

- No file handling anywhere; the extraction input is pasted text only
  (`frontend/components/extraction-panel.tsx`, `backend/routers/workflow.py`).
- FastAPI supports `UploadFile` natively (needs `python-multipart`).
- `submitted_by` fields exist across tables — reuse that convention for custody entries.

## Design

- Storage: `evidence/{case_id}/{sha256[:2]}/{sha256}` on disk (content-addressed — dedupes
  identical uploads automatically, filename collisions impossible). Original filename kept in
  DB only. Configurable root via `EVIDENCE_DIR` env (default `./evidence`), added to `.gitignore`.
- New `evidence_files` table: `id`, `case_id (FK, CASCADE)`, `original_filename`,
  `content_type`, `size_bytes`, `sha256 (index)`, `sha1`, `md5`, `uploaded_by`,
  `uploaded_at`, `description (Text)`, `stored_path`.
- New `custody_log` table (append-only): `id`, `evidence_id (FK)`, `action`
  (uploaded | downloaded | hashed | verified | deleted), `actor`, `timestamp`, `details`.
  No update/delete endpoints for log rows.
- Files are immutable once uploaded (no re-upload over the same record). "Delete" removes the
  DB record's visibility and logs the action; the blob is removed only if no other record
  references that sha256.
- Upload limits: 200 MB per file (configurable), streamed hashing (never load whole file in RAM).
- Optional "Extract from this file" for `.txt`/`.log`/`.csv`/`.eml` under 1 MB of text: decode,
  then submit to the existing extraction endpoint (or job, with plan 2).

## Implementation tasks

### Backend

- [ ] `uv add python-multipart`.
- [ ] `EvidenceFile` + `CustodyLog` models and helpers in `backend/utils/database.py`.
- [ ] `backend/utils/evidence_store.py`: streamed save-with-hashing (read in 1 MB chunks,
      update all three hashers, write to a temp path, fsync, rename into the content-addressed
      location), `verify(evidence_id)` (re-hash from disk, compare to recorded sha256, log
      `verified` with pass/fail), safe path construction (no user input in paths).
- [ ] New router `backend/routers/evidence.py`:
      - `POST   /cases/{case_id}/evidence` (multipart: file, `uploaded_by`, `description`) →
        record with hashes; 413 over limit; logs `uploaded`.
      - `GET    /cases/{case_id}/evidence` → list with hashes and custody summary.
      - `GET    /evidence/{evidence_id}/download` → `FileResponse` with original filename;
        logs `downloaded`.
      - `POST   /evidence/{evidence_id}/verify` → integrity check result; logs `verified`.
      - `DELETE /evidence/{evidence_id}` (body: `actor`, `reason`) → soft-delete + log.
      - `GET    /evidence/{evidence_id}/custody` → full append-only log.
      - `POST   /evidence/{evidence_id}/extract` body `{llm_model}` → run extraction over
        decoded text content (guard: text types only, size cap).
- [ ] Cross-link: if an uploaded file's sha256 matches a `host_ioc` hash in any case, include
      that in the list response (`matches_ioc: [...]`) — evidence↔indicator linkage for free.

### Frontend

- [ ] **Evidence tab** on the case page: drag-and-drop upload zone (with `uploaded_by` +
      description fields), then a table: filename, size, sha256 (copy button, truncated
      display), uploaded by/at, actions (Download, Verify, Custody log, Extract, Delete-with-
      confirmation).
- [ ] Custody log drawer per file (timeline of actions).
- [ ] Verify shows green "Integrity OK" / red "HASH MISMATCH" state inline.
- [ ] "Extract IOCs from file" action for eligible text files feeding the existing
      extraction flow/panel.

## Testing

- [ ] `tests/test_evidence.py` (temp DB + `tmp_path` evidence root):
      - Upload a file → hashes match `hashlib` reference values; stored blob exists at the
        content-addressed path; custody log has `uploaded`.
      - Download returns identical bytes and original filename; logs `downloaded`.
      - Verify passes; corrupt the blob on disk → verify fails and logs the mismatch.
      - Duplicate upload (same bytes) in two cases → two records, one blob; deleting one record
        keeps the blob, deleting both removes it.
      - Oversize upload → 413, nothing stored. Path-traversal filename (`../../etc/passwd`) →
        stored safely, original name preserved only as metadata.
      - Custody log has no mutation endpoints (405/404).
      - Extract-from-file with a seeded `.txt` (monkeypatched workflow) → extraction invoked
        with the file's text; binary file → 400.
      - Case deletion cascades records + orphaned blobs.
- [ ] Manual: upload a 50 MB file, confirm memory stays flat (streamed) and UI stays responsive.

## Success criteria

1. Every uploaded file has SHA-256/SHA-1/MD5 recorded at ingest and can be integrity-verified
   on demand at any later time.
2. The custody log is append-only and captures upload, download, verify, and delete actions
   with actor and timestamp.
3. Byte-identical evidence is stored once on disk regardless of how many cases reference it.
4. A text log file can go from upload to extracted IOCs without leaving the app.
5. All automated tests pass; no endpoint reads an entire large file into memory.
