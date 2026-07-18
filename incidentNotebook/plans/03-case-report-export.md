# Feature 3: Case Report Export (XLSX Tracker, Markdown Report, Executive Summary)

## Overview

Generate deliverable-quality outputs from a case: (a) an Excel workbook matching the
CrowdStrike-style IR tracker already vendored in the repo
(`CrowdStrike-Incident-Response-Tracker-Template.xlsx`), (b) a Markdown incident report, and
(c) an optional LLM-written executive summary. Reporting is the deliverable of every IR
engagement; right now the only way to get data out of the app is reading the web UI or
querying SQLite by hand.

## Current state

- All case data available via `GET /cases/{case_id}/data` (`backend/routers/cases.py:67`).
- `CrowdStrike-Incident-Response-Tracker-Template.xlsx` sits unused at the repo root — the DB
  schema (`timeline`, `host_ioc`, `network_ioc` in `backend/utils/database.py`) visibly mirrors
  its sheet columns, so mapping is mostly 1:1.
- `pandas` is already a dependency; add `openpyxl` for templated XLSX writing.
- Ollama access pattern for the summary exists in `backend/utils/ioc_extraction_workflow.py`
  (`get_client`).

## Implementation tasks

### Backend

- [ ] **Inspect the template** and document the sheet names / header rows / column order in a
      mapping module `backend/utils/report_mappings.py` (dict per sheet: DB column → sheet column).
- [ ] New module `backend/utils/reporting.py`:
      - `export_xlsx(case_id) -> bytes`: load the template with `openpyxl`, fill the Timeline,
        Host IOC, and Network IOC sheets from the DB (preserving template formatting), plus a
        cover/summary sheet with case name, case_id, status, dates, and artifact counts.
        Timeline sorted by `timestamp_utc` ascending.
      - `export_markdown(case_id) -> str`: structured report — header (case metadata), executive
        summary placeholder, timeline table, host IOC table, network IOC table, appendix with
        notes fields. Use defanged indicators in the body (see plan 10; until then, simple
        `.`→`[.]` / `http`→`hxxp` helpers here).
      - `generate_executive_summary(case_id, llm_model) -> str`: prompt an Ollama model with the
        case's timeline + IOC data to write a 3–5 paragraph summary (what happened, scope,
        key indicators, current status). Clearly labeled as AI-generated in output.
- [ ] New router `backend/routers/export.py` (register in `backend/main.py`):
      - `GET /cases/{case_id}/export/xlsx` → `StreamingResponse` with
        `Content-Disposition: attachment; filename="{case_id}-tracker.xlsx"`.
      - `GET /cases/{case_id}/export/markdown` → text/markdown download.
      - `POST /cases/{case_id}/report/summary` body `{llm_model}` → `{summary: str}` (kept as a
        separate call because it is slow; the Markdown export accepts an optional
        `?include_summary=true&llm_model=...`).
      - 404 for unknown case; empty case still exports (empty tables, not an error).
- [ ] Add `openpyxl` to `pyproject.toml` via `uv add openpyxl`.

### Frontend

- [ ] "Export" dropdown button on the case page (`frontend/app/cases/[id]/`): items
      "Excel tracker (.xlsx)", "Markdown report (.md)", "Markdown + AI summary".
- [ ] `frontend/lib/api.ts`: export helpers that trigger a browser download (fetch → blob →
      object URL anchor click).
- [ ] For "Markdown + AI summary": show a spinner state on the menu item while generating
      (reuses the model selected in the extraction panel).

## Testing

- [ ] `tests/test_export.py` (pytest + TestClient, temp DB seeded with a case + 2 rows per table):
      - XLSX: response 200, correct content-type; re-open the bytes with `openpyxl` and assert
        sheet names, header rows, row counts, and one spot-checked cell per sheet.
      - XLSX for an empty case: valid workbook, zero data rows.
      - Markdown: contains case_id, all indicator values (defanged), timeline rows in
        chronological order.
      - Summary endpoint: monkeypatch the Ollama client to return a canned completion; assert
        it's embedded in the Markdown when requested and returned by the summary endpoint.
      - Unknown case → 404 on all three endpoints.
- [ ] Manual check: open the exported XLSX in Excel/Numbers next to the original template and
      confirm formatting/columns survive.

## Success criteria

1. One click produces an `.xlsx` that opens cleanly in Excel and matches the CrowdStrike
   tracker layout with all case data filled in.
2. The Markdown report is complete enough to paste into a ticket or wiki without editing
   structure, and all network indicators in it are defanged.
3. Executive summary generation works with any installed Ollama model and is clearly marked
   as AI-generated.
4. Exports are read-only operations — no DB writes occur (verified in tests).
5. All automated tests pass; export of a 500-row case completes in < 5 s (excluding LLM summary).
