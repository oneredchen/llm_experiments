# Feature 6: Cross-Case IOC Correlation & In-Case Deduplication

## Overview

Surface when an indicator in the current case has been seen in other cases ("this C2 IP also
appeared in CAS-0231-KX in March"), and stop duplicate rows from accumulating inside a case
when extraction runs multiple times over overlapping notes. Correlation turns a notebook into
institutional memory — repeated infrastructure across incidents is how campaigns and repeat
intrusions get spotted.

## Current state

- IOCs are stored per-case with no normalization or cross-case linkage
  (`backend/utils/database.py`: `host_ioc`, `network_ioc`).
- Nothing prevents duplicates: each extraction run inserts fresh rows with new
  `H-<uuid>`/`N-<uuid>` indicator IDs (`backend/utils/ioc_extraction_workflow.py`), so pasting
  overlapping notes twice doubles every IOC.
- Matching must be on a *normalized* indicator value (case-folded domains, refanged, hash
  lowercased) — normalization helpers are specified in plan 10; this plan can ship a minimal
  `normalize_indicator()` first and swap in plan 10's version.

## Design

- **Normalized match key** computed per IOC: `match_key = f"{kind}:{normalized_value}"` where
  kind ∈ {ip, domain, url, hash, filename, registry, process, other}. For host IOCs with
  hashes, additionally match on each hash value (sha256/sha1/md5) so the same file under
  different names correlates.
- Store `match_key` as a new indexed column on `host_ioc` and `network_ioc` (additive schema
  change + one-shot backfill script for the existing DB).
- **Dedup on insert** (within a case): before inserting extraction results, drop candidates
  whose `match_key` already exists in the case; report them as `skipped_duplicates` in the
  extraction response counts. Manual adds (plan 1) warn but allow override.
- **Correlation on read**: `GET /cases/{case_id}/correlations` groups by `match_key` across
  all *other* cases and returns hits.

## Implementation tasks

### Backend

- [ ] `backend/utils/normalize.py`: `normalize_indicator(kind, value) -> str` (lowercase,
      strip whitespace/trailing dots on domains, refang `[.]`/`hxxp`, lowercase hashes,
      normalize URL scheme/host casing). Keep pure and heavily unit-tested.
- [ ] Schema: add `match_key = Column(String(600), index=True)` to `HostIOC` and `NetworkIOC`;
      write `scripts/backfill_match_keys.py` that computes keys for existing rows in
      `db/incident_notebook.db` (run via `uv run python scripts/backfill_match_keys.py`).
      `insert_iocs()` computes `match_key` automatically when absent.
- [ ] **Dedup:** in `backend/routers/workflow.py` (or the job worker from plan 2), filter
      extraction results against existing case `match_key`s before insert; extend
      `ExtractionResponse.counts` with `skipped_duplicates`.
- [ ] New endpoints in `backend/routers/cases.py` (or a `correlation.py` router):
      - `GET /cases/{case_id}/correlations` →
        `[{match_key, indicator, kind, this_case_rows: [...], other_cases: [{case_id, name, status, count, first_seen}]}]`
        (only entries with ≥1 other-case hit).
      - `GET /indicators/{match_key}/occurrences` → every case/row containing it (drill-down,
        also powers plan 9's search detail view).
- [ ] Dedup within a single extraction batch too (the LLM often emits the same IOC twice).

### Frontend

- [ ] **"Seen in other cases" badge** on IOC rows in `frontend/components/ioc-tables.tsx`
      (e.g. `↔ 2 cases`); click opens a popover listing the other cases with links.
- [ ] **Correlations tab/panel** on the case page: table of all cross-case hits for this case,
      sorted by number of other cases descending.
- [ ] Show `skipped_duplicates` in the post-extraction toast ("Extracted 12 IOCs, 4 duplicates
      skipped").

## Testing

- [ ] `tests/test_normalize.py`: parametrized table —
      `EVIL.com.` ≡ `evil.com`, `hxxp://evil[.]com/a` ≡ `http://evil.com/a`, mixed-case
      sha256 ≡ lowercase, `192.168.001.005` handling, idempotence
      (`normalize(normalize(x)) == normalize(x)`).
- [ ] `tests/test_correlation.py` (temp DB):
      - Two cases sharing an IP (one defanged, one not) → correlation endpoint returns the link
        both ways.
      - Same file hash under different filenames across cases → correlates via hash key.
      - Case with no overlaps → empty list.
      - Extraction inserting an IOC whose key exists in the case → row not duplicated,
        `skipped_duplicates` incremented; same IOC in a *different* case → inserted normally.
      - Backfill script on a copy of a seeded legacy DB (rows with NULL `match_key`) →
        all rows keyed, correlations work.
- [ ] Regression: `tests/test_api_refactor.py` passes after schema change.

## Success criteria

1. Pasting the same incident notes twice into a case does not duplicate any IOC, and the UI
   tells the analyst how many duplicates were skipped.
2. An indicator shared between two cases is flagged on both case pages within one data refresh,
   including when one copy was defanged or differently cased.
3. Correlation lookup on a DB with 10k IOCs returns in < 1 s (indexed `match_key`).
4. Existing databases are upgraded by the backfill script without data loss.
5. All new unit and API tests pass.
