# Feature 10: IOC Validation, Defang/Refang Normalization & Type Auto-Detection

## Overview

A validation and normalization layer for indicators: refang defanged input
(`hxxp://evil[.]com` → `http://evil.com`), validate formats (IP syntax, hash lengths/charsets,
domain/URL shape), auto-detect indicator types, and defang on display/report output. Real
intel arrives defanged by convention; LLM extraction mislabels types and emits malformed
values; and an IR tool must *display* indicators defanged so nobody click-hijacks themselves
from a case page. This is a small feature that raises the trustworthiness of every other one
(correlation, search, exports all depend on normalized values — plans 4, 6, 9 reference this
module).

## Current state

- No validation anywhere: extraction output goes straight into the DB
  (`backend/routers/workflow.py`), `indicator_type` is whatever the LLM said, and hash fields
  (`sha256 String(64)` etc. in `backend/utils/database.py`) accept any string.
- IOC tables render raw values as plain text (`frontend/components/ioc-tables.tsx`) — live
  URLs/domains displayed fanged.
- Plan 6 specifies a minimal `backend/utils/normalize.py`; this plan is its full version.

## Design

One pure-Python module, `backend/utils/indicators.py` (stdlib only: `ipaddress`, `re`,
`urllib.parse`):

- `refang(value) -> str`: `hxxp(s)`→`http(s)`, `[.]`/`(.)`/`{.}`/` [dot] `→`.`, `[:]`→`:`,
  `[@]`/`[at]`→`@`, strip zero-width chars. Idempotent.
- `defang(value, kind) -> str`: `.`→`[.]` in host parts, `http`→`hxxp`. `defang(refang(x))`
  stable.
- `detect_type(value) -> DetectedType`: ordered checks — sha256/sha1/md5 (hex length),
  IPv4/IPv6 (`ipaddress`), URL (scheme + host), email, domain (label rules, has a dot, TLD
  alpha), registry key (`HKLM\...`/`HKEY_`), windows path, filename-with-extension, else
  `unknown`. Returns `(kind, confidence)`.
- `validate(kind, value) -> ValidationResult`: `valid | fixable(normalized) | invalid(reason)`.
  Examples: 63-char "sha256" → invalid("expected 64 hex chars"); uppercase hash →
  fixable(lowercased); domain with trailing dot → fixable.
- `normalize_indicator(kind, value) -> str`: refang + validate + canonicalize (the function
  plans 4/6/9 import).

## Implementation tasks

### Backend

- [ ] Implement `backend/utils/indicators.py` as above, with an exhaustive docstring table of
      supported defang styles.
- [ ] **Ingest hook** (extraction + plan 1 manual create/edit): before insert —
      refang and canonicalize `indicator`; validate hash fields (invalid hash values moved to
      `notes` with a `[validation]` prefix rather than silently stored/dropped); if
      `detect_type()` confidently disagrees with the LLM's `indicator_type`, correct it and
      note the original in `notes`. Add per-run counts (`corrected_types`, `fixed_values`,
      `flagged_invalid`) to the extraction response.
- [ ] `POST /indicators/validate` endpoint (new or in `search.py` router): body
      `{value, kind?}` → `{refanged, detected_kind, confidence, validation, normalized}` —
      powers live form feedback.
- [ ] `scripts/normalize_existing_iocs.py`: one-shot cleanup of the current DB (report-only
      `--dry-run` mode first; prints a diff of proposed changes).

### Frontend

- [ ] **Defanged display**: render network indicators defanged in `ioc-tables.tsx` by default,
      with a copy button that copies the *fanged* value (analyst intent: paste into tooling)
      and a tooltip showing both forms. A per-table "Show fanged" toggle for when needed.
      Never render indicators as clickable links.
- [ ] **Validation feedback in forms** (plan 1's add/edit dialog): on blur of the indicator
      field call `/indicators/validate` — show detected type (auto-fill the type dropdown),
      green check for valid, amber "auto-fixed" note, red reason for invalid (submit allowed
      with confirmation, stored with the `[validation]` note).
- [ ] Badge invalid-flagged rows in the tables (amber warning icon with the reason tooltip).

## Testing

- [ ] `tests/test_indicators.py` — the bulk of this feature; parametrized tables:
      - Refang: `hxxps://evil[.]com/x`, `evil[.]com`, `1.2.3[.]4`, `user[@]evil.com`,
        `hXXp://…`, already-fanged input (unchanged), double-application idempotence.
      - Defang/refang round-trip stability for every kind.
      - detect_type: valid sha256/sha1/md5, 63-char hex → not sha256, IPv4, IPv6, URL,
        domain, email, `HKLM\Software\...`, `C:\Windows\evil.exe`, `evil.exe`, random text →
        unknown. Ambiguities pinned down: all-hex 32-char string → md5 (documented choice);
        `1.2.3.4` detected ip not domain.
      - validate: uppercase hash → fixable; wrong-length hash → invalid with reason;
        `999.1.1.1` → invalid ip; trailing-dot domain → fixable.
- [ ] `tests/test_ingest_validation.py` (temp DB, monkeypatched workflow returning dirty
      output: defanged IP typed as domain, bad sha256, uppercase md5) → stored rows are
      refanged/retyped/lowercased, bad hash flagged in notes, response counts correct.
- [ ] Cleanup-script test on a seeded dirty DB: `--dry-run` changes nothing; real run
      normalizes and is idempotent (second run reports zero changes).
- [ ] Manual UI pass: paste a defanged intel snippet through extraction; confirm defanged
      display, fanged copy, and form validation feedback.

## Success criteria

1. Defanged indicators in any common style are stored canonically fanged, and matched by
   search/correlation identically to fanged input.
2. The UI never displays a raw clickable malicious URL/domain — display is defanged by
   default while copy yields the working value.
3. No invalid value is silently stored or silently dropped: every auto-fix and rejection is
   visible (notes flag + extraction counts).
4. Type auto-detection corrects LLM mislabels for hashes, IPs, domains, and URLs (verified by
   the dirty-extraction test).
5. `tests/test_indicators.py` covers ≥ 40 parametrized cases and the full suite passes;
   plans 4, 6, and 9 import `normalize_indicator` from this module with no duplication.
