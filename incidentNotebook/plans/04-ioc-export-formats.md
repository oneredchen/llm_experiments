# Feature 4: IOC Export to STIX 2.1, MISP, CSV, and Blocklist Formats

## Overview

Export a case's IOCs in machine-readable formats that downstream security tooling actually
consumes: STIX 2.1 bundles (intel sharing, TIPs), MISP event JSON, flat CSV, and plain-text
blocklists (one indicator per line, split by type) for direct import into firewalls, DNS
sinkholes, and EDR blocklists. Plan 3 covers human-readable reporting; this plan covers the
machine-to-machine path, which is how IOC data creates defensive value.

## Current state

- Host IOCs carry `indicator_type` (file/process/registry), `indicator`, `sha256`/`sha1`/`md5`,
  `full_path`; network IOCs carry `indicator_type` (ip/domain/url) and `indicator`
  (`backend/utils/database.py`). `status` distinguishes Confirmed/Suspicious.
- No export code exists. No STIX/MISP libraries in `pyproject.toml`.

## Design decisions

- Use the OASIS `stix2` Python library for correct STIX 2.1 object generation rather than
  hand-writing JSON (pattern syntax is fiddly: `[file:hashes.'SHA-256' = '...']`,
  `[ipv4-addr:value = '...']`, `[domain-name:value = '...']`, `[url:value = '...']`).
- MISP export writes the MISP *event JSON format* directly (no PyMISP / live server needed —
  the file can be imported into any MISP instance). Map: ip → `ip-dst`, domain → `domain`,
  url → `url`, hashes → `sha256`/`sha1`/`md5`, file name → `filename`.
- Blocklists include **Confirmed IOCs by default**, with `?include_suspicious=true` opt-in —
  responders must not accidentally block on weak indicators.
- Indicator types that don't map cleanly (e.g. registry keys → `windows-registry-key`) get
  best-effort mapping; unmappable rows are listed in an export "skipped" report, never
  silently dropped.

## Implementation tasks

### Backend

- [ ] `uv add stix2`.
- [ ] New module `backend/utils/ioc_exporters.py`:
      - `to_stix_bundle(case_id, statuses) -> dict`: one `Identity` (the notebook), one
        `Indicator` per IOC (pattern per type, `valid_from` = `date_added` or
        `earliest_evidence_utc`, labels from `status` + `indicator_type`, description from
        `notes`), plus a `Report` object tying them to the case. Returns
        `(bundle_json, skipped: list[reason])`.
      - `to_misp_event(case_id, statuses) -> dict`: MISP event with `info` = case name,
        Attributes per IOC with `to_ids` true only for Confirmed.
      - `to_csv(case_id, kind) -> str`: `kind in {host, network, all}`; stable column order,
        UTF-8, header row.
      - `to_blocklists(case_id, statuses) -> dict[str, str]`: keys `ips`, `domains`, `urls`,
        `sha256`, `md5` → newline-separated unique values, refanged (see plan 10), sorted.
- [ ] Extend `backend/routers/export.py` (from plan 3, or create it here if built first):
      - `GET /cases/{case_id}/export/stix` → JSON download `{case_id}-stix.json`.
      - `GET /cases/{case_id}/export/misp` → JSON download.
      - `GET /cases/{case_id}/export/csv?kind=all|host|network`.
      - `GET /cases/{case_id}/export/blocklist?type=ips|domains|urls|hashes` → text/plain.
      - All accept `?include_suspicious=true`. Responses include an `X-Skipped-Count` header;
        `GET .../export/stix?dry_run=true` returns `{indicator_count, skipped}` for UI preview.
- [ ] Validation pass before export: drop obviously malformed indicators (empty, wrong hash
      length) into `skipped` with reasons (full validation arrives with plan 10; keep the
      hook shared so plan 10 slots in).

### Frontend

- [ ] Extend the case-page Export dropdown (plan 3) with a "Share / Blocklists…" item opening a
      dialog: format radio (STIX / MISP / CSV / Blocklist), blocklist type selector, "include
      Suspicious" checkbox, and a preview line ("42 indicators, 3 skipped") from `dry_run`.
- [ ] Download helpers in `frontend/lib/api.ts`.

## Testing

- [ ] `tests/test_ioc_exporters.py` with a seeded temp DB covering every indicator type +
      one malformed row:
      - STIX: parse output with `stix2.parse()` — bundle validates; correct pattern strings for
        an IP, domain, URL, sha256 file, and filename; Report references all indicators;
        malformed row appears in `skipped`.
      - MISP: JSON matches expected attribute types/categories; `to_ids` true only for Confirmed.
      - CSV: round-trip with `pandas.read_csv` — row count and key columns intact.
      - Blocklists: only Confirmed by default; `include_suspicious=true` adds the rest;
        values unique, refanged, no blank lines.
      - Unknown case → 404; empty case → valid empty bundle/CSV.
- [ ] Interop smoke test (manual, documented in the plan's PR): import the MISP JSON into a demo
      MISP instance or validate STIX with the `stix2-validator` CLI.

## Success criteria

1. STIX output passes `stix2` library validation and `stix2-validator` with no errors.
2. A generated blocklist can be pasted directly into a firewall/EDR blocklist without cleanup
   (no defanged values, no duplicates, no empty lines).
3. Suspicious indicators never enter a blocklist unless explicitly requested.
4. No indicator is ever silently dropped — every exclusion is reported with a reason.
5. Automated tests cover all four formats and pass in CI (`pytest`).
