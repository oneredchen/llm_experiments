# Feature 9: Global Search & Advanced Filtering

## Overview

A global search that answers "have we seen this before?" across every case — indicators,
timeline activity, hostnames, notes — plus rich in-case filtering (by type, status, system,
evidence source, date range). During triage, checking a new alert's IP/hash/hostname against
past incidents is one of the most common actions an IR team performs; today the app can only
display one case's tables with no search at all.

## Current state

- Data access loads entire tables into pandas and filters in Python
  (`backend/utils/database.py:load_database`, used by `backend/routers/cases.py`) — workable
  for search MVP but the search endpoint should query SQL directly with `LIKE`/FTS instead of
  loading everything.
- Frontend tables (`frontend/components/ioc-tables.tsx`, `timeline-view.tsx`) render all rows
  with no filter controls.
- SQLite supports FTS5 virtual tables — ideal here, no new dependency.

## Design

- **Phase 1 (LIKE-based MVP):** a `/search` endpoint doing indexed `LIKE '%term%'` over the
  relevant columns of `host_ioc` (indicator, full_path, sha256, sha1, md5, notes),
  `network_ioc` (indicator, initial_lead, details_comments, notes), `timeline` (system_name,
  activity, details_comments, notes, hash), and `cases` (name, case_id). Normalize the query
  with plan 10/6's `normalize_indicator` so a defanged search term (`evil[.]com`) still hits.
- **Phase 2 (FTS5):** an `artifact_search` FTS5 table (contentless, columns: `artifact_table`,
  `artifact_id`, `case_id`, `body`) kept in sync by the insert/update/delete helpers in
  `backend/utils/database.py`; rebuildable via `scripts/rebuild_search_index.py`. Gives
  ranked multi-term search and snippet highlighting.
- Results grouped by case, each hit tagged with artifact type and matched field.
- In-case filtering is client-side (the per-case row counts are small): filter state in the
  case page, applied to the already-fetched `CaseData`.

## Implementation tasks

### Backend

- [ ] New router `backend/routers/search.py`:
      - `GET /search?q=&types=&status=&case_status=&limit=` →
        `{query, normalized_query, total, results: [{case_id, case_name, artifact_table, artifact_id, matched_field, snippet, indicator_type?, status?, timestamp?}]}`.
      - Minimum query length 3 (except exact IP/hash-shaped queries); cap `limit` at 200.
      - Exact-match shortcut: if the query normalizes to a full hash/IP, do exact `match_key`
        lookup first (plan 6) and rank those hits above substring hits.
- [ ] SQL implementation with per-table `UNION`-style queries; add missing indexes if profiling
      shows need (`indicator` columns are the hot path).
- [ ] Phase 2: FTS5 table + sync hooks in `insert_iocs`/update/delete helpers +
      `scripts/rebuild_search_index.py`; `snippet()` for highlighted excerpts; feature-flag via
      env `SEARCH_BACKEND=like|fts` with automatic fallback to LIKE if the FTS table is missing.

### Frontend

- [ ] **Global search UI**: search input in `frontend/components/sidebar.tsx` header (or a
      `⌘K` command palette using ShadCN `Command`), debounced 300 ms, dropdown/page of results
      grouped by case; clicking a hit navigates to `/cases/{id}` and (stretch) scrolls to /
      highlights the matching row.
- [ ] `frontend/lib/api.ts`: `search(q, filters)` helper.
- [ ] **In-case filter bar** above the tables in `ioc-tables.tsx` / `timeline-view.tsx`:
      free-text filter, `indicator_type` multi-select, `status` multi-select; timeline
      additionally gets `system_name` select, `evidence_source` select, and a date-range
      picker on `timestamp_utc`. Show "n of m rows" and a clear-filters button.
- [ ] Filters and search results must handle defanged input (normalize before matching client-side too).

## Testing

- [ ] `tests/test_search.py` (temp DB seeded with 3 cases, overlapping + unique artifacts):
      - Search an IP present in 2 cases → both returned, grouped, correct artifact refs.
      - Defanged query `45[.]67[.]89[.]10` finds the refanged stored value and vice versa.
      - Full sha256 query → exact-match hit ranked first.
      - Substring in a timeline `activity` and a `notes` field → found with correct
        `matched_field`.
      - Type/status filters narrow correctly; `limit` respected; 2-char query → 422.
      - Empty result → `total: 0`, not an error.
- [ ] Phase 2: same suite green with `SEARCH_BACKEND=fts`; index rebuild script reproduces
      identical results; artifact edit/delete (plan 1) keeps the index in sync.
- [ ] Performance check: seed 10k artifacts (script), assert p95 search latency < 300 ms
      locally for both backends.
- [ ] Manual UI pass: ⌘K palette, navigation to hits, in-case filter combinations.

## Success criteria

1. An analyst can paste any indicator (fanged or defanged) into global search and see every
   case containing it in under a second.
2. Search covers indicators, paths, hashes, hostnames, activity text, and notes — verified by
   tests per field.
3. In-case tables are filterable by type, status, system, source, and time range without
   re-fetching.
4. Search never returns rows from deleted cases/artifacts (index stays in sync).
5. Full automated test suite passes with both search backends.
