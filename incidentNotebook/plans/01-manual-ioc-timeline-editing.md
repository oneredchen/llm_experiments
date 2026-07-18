# Feature 1: Manual IOC & Timeline Editing (Add / Edit / Delete)

## Overview

Allow analysts to manually create, edit, and delete host IOCs, network IOCs, and timeline
events. Today the only way data enters a case is through the LLM extraction workflow
(`POST /cases/{case_id}/extract`), and once written it can never be corrected. LLM output
routinely contains wrong timestamps, mis-typed indicators, or hallucinated fields — an IR
tool whose record cannot be corrected is not usable for a real engagement.

## Current state

- `backend/routers/cases.py` — read-only endpoints for case data (`GET /cases/{case_id}/data`).
- `backend/routers/workflow.py` — the only write path for IOCs/timeline (extraction).
- `backend/utils/database.py` — `insert_iocs()` exists; no update/delete helpers. Rows have
  integer `id` primary keys that are currently not exposed in API responses
  (`backend/models.py` response models omit `id`).
- `frontend/components/ioc-tables.tsx`, `frontend/components/timeline-view.tsx` — display-only tables.

## Implementation tasks

### Backend

- [ ] **Expose row identity.** Add `id: int` (and `date_added`) to `TimelineEvent`, `HostIOC`,
      `NetworkIOC` response models in `backend/models.py` so the frontend can address rows.
- [ ] **Create request models.** Add `HostIOCCreate`, `NetworkIOCCreate`, `TimelineEventCreate`
      (same fields as response models minus `id`/`date_added`/`case_id`) and matching
      `...Update` models with all fields optional (PATCH semantics).
- [ ] **Database helpers** in `backend/utils/database.py`:
      - `update_record(model_class, record_id, fields: dict) -> bool`
      - `delete_record(model_class, record_id) -> bool`
      - `get_record(model_class, record_id)`
      All should verify the row belongs to the given `case_id` before acting.
- [ ] **New router** `backend/routers/artifacts.py` registered in `backend/main.py`:
      - `POST   /cases/{case_id}/host-iocs` → create (auto-generate `indicator_id` as `H-<uuid>` when absent, mirroring `backend/utils/ioc_extraction_workflow.py`)
      - `PATCH  /cases/{case_id}/host-iocs/{row_id}` → partial update
      - `DELETE /cases/{case_id}/host-iocs/{row_id}`
      - Same trio for `network-iocs` and `timeline-events`.
      - Return 404 when the row does not exist or belongs to another case; 400 on validation errors.
- [ ] **Touch the case.** On any successful mutation, set `cases.updated_at` for the parent case.

### Frontend

- [ ] Extend `frontend/lib/api.ts` with `createHostIOC`, `updateHostIOC`, `deleteHostIOC` (and the
      network/timeline equivalents), typed against the new models.
- [ ] **Row actions** in `frontend/components/ioc-tables.tsx` and `timeline-view.tsx`: an actions
      column with Edit and Delete. Delete shows a confirmation dialog (ShadCN `AlertDialog`).
- [ ] **Edit dialog**: a ShadCN `Dialog` + form (one shared `ArtifactForm` component driven by a
      field config per artifact type) used for both "Add entry" and "Edit". Required fields marked;
      dropdowns for constrained fields (`status`: Confirmed/Suspicious/Benign; `timestamp_type`;
      `indicator_type`).
- [ ] **Add buttons**: "Add Host IOC", "Add Network IOC", "Add Timeline Event" buttons above each
      table, opening the same form empty with `submitted_by` prefilled (e.g. "Analyst").
- [ ] Refresh the case data (re-fetch `getCaseData`) after every successful mutation; show
      success/error toasts.

## Testing

- [ ] New `tests/test_artifact_crud.py` using `pytest` + `fastapi.testclient.TestClient` with a
      temporary SQLite DB (point `DB_PATH` at a tmp dir via monkeypatch or env var — may require
      making `DB_PATH` overridable in `backend/utils/database.py`, a small prerequisite refactor):
      - Create case → POST each artifact type → GET data returns it with an `id`.
      - PATCH a field → GET reflects the change; untouched fields unchanged.
      - DELETE → row gone; second DELETE returns 404.
      - PATCH/DELETE with wrong `case_id` → 404 (no cross-case mutation).
      - POST with missing required field → 422.
      - Mutation updates the parent case's `updated_at`.
- [ ] Frontend manual test script: add, edit, delete one row of each type through the UI; verify
      table refresh and toasts.

## Success criteria

1. An analyst can add a fully manual IOC or timeline event without running the LLM workflow.
2. Any field of any extracted row can be corrected in ≤ 3 clicks from the case view.
3. Deleting requires explicit confirmation and cannot affect another case's rows.
4. All CRUD endpoints covered by automated tests; `pytest` passes.
5. Existing extraction flow is unchanged (regression: `tests/test_api_refactor.py` still passes).
