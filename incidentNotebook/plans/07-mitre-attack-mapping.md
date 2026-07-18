# Feature 7: MITRE ATT&CK Normalization & Coverage Matrix

## Overview

Turn the free-text `attack_alignment` field into validated MITRE ATT&CK technique references
(`T1059.001 — PowerShell`), and give each case an ATT&CK coverage view — a mini
Navigator-style matrix showing which tactics/techniques the incident touched. ATT&CK is the
lingua franca of IR reporting; normalized technique IDs make reports credible, enable
"which techniques do we keep seeing" analysis, and plug into plan 3's reports and plan 4's
STIX export (`attack-pattern` references).

## Current state

- `attack_alignment` exists on `timeline` and `network_ioc` as `String(128)` free text
  (`backend/utils/database.py:119,175`); the extraction prompt asks for a "concise MITRE
  tactic if clear" (`backend/utils/ioc_extraction_workflow.py`), so values are inconsistent:
  "Lateral Movement", "T1021", "psexec", null.
- No ATT&CK dataset in the repo.

## Design

- Vendor the enterprise ATT&CK STIX JSON (from `mitre-attack/attack-stix-data`) once into
  `backend/data/attack-enterprise.json` (checked in; ~40 MB raw — strip to a compact
  `attack-catalog.json` of `{technique_id, name, tactics: [...], url, deprecated}` at build
  time via a script, ~500 KB). No runtime network dependency — the app stays local-first.
- **Normalization service**: `resolve_attack(text) -> list[TechniqueRef]` matching, in order:
  exact technique ID (`T1059`, `t1059.001`), exact technique name, exact tactic name
  (→ tactic-level ref), fuzzy contains-match on names (single unambiguous hit only).
- Store normalized refs in a new `attack_refs` table (`id`, `artifact_table`, `artifact_id`,
  `technique_id`, `technique_name`, `tactic`) rather than overwriting analyst text — the raw
  `attack_alignment` string is preserved.
- **LLM prompt hardening**: update the extraction prompts to request technique IDs explicitly
  ("`attack_alignment` must be a MITRE ATT&CK technique ID like T1059.001 when clear, else null").

## Implementation tasks

### Backend

- [ ] `scripts/build_attack_catalog.py`: download/parse ATT&CK STIX → write
      `backend/data/attack-catalog.json`; document the refresh procedure in the script docstring.
      Check the generated catalog into git so runtime never needs the network.
- [ ] `backend/utils/attack.py`: catalog loader (lru_cache), `resolve_attack()`, and
      `get_technique(technique_id)`. Handle sub-techniques, deprecated/revoked techniques
      (resolve but flag), and tactic name ↔ shortname mapping.
- [ ] `AttackRef` model + helpers in `backend/utils/database.py` (additive table).
- [ ] **Normalization hook**: after extraction inserts (and on manual create/edit from plan 1),
      run `resolve_attack()` on `attack_alignment` and upsert `attack_refs` rows.
      `scripts/backfill_attack_refs.py` for existing data.
- [ ] Endpoints (new `backend/routers/attack.py`):
      - `GET /attack/techniques?q=` → typeahead search over the catalog (for plan 1's edit form
        so analysts pick valid techniques).
      - `GET /cases/{case_id}/attack-summary` →
        `{tactics: [{tactic, techniques: [{technique_id, name, count, sources: [artifact refs]}]}], unresolved: [raw strings]}`.
- [ ] Update the three extraction system prompts to demand technique IDs.
- [ ] Wire into plan 3 (report section "ATT&CK Techniques Observed") and plan 4
      (STIX `attack-pattern` relationships) when those land — note the hook points, don't block.

### Frontend

- [ ] **ATT&CK tab** on the case page: tactic columns (kill-chain order) with technique chips
      sized/badged by occurrence count; clicking a chip filters/lists the timeline events and
      IOCs that reference it; link out to `attack.mitre.org` technique pages.
- [ ] Show normalized chips (e.g. `T1021.002 SMB/Windows Admin Shares`) next to the raw
      `attack_alignment` text in `frontend/components/timeline-view.tsx`; amber "unresolved"
      chip when normalization failed, with a picker (typeahead endpoint) to fix it manually.
- [ ] Technique typeahead field in the plan-1 add/edit form (works standalone too).

## Testing

- [ ] `tests/test_attack.py`:
      - Catalog loads; known technique (`T1059.001`) resolves with correct name/tactic.
      - Resolution matrix (parametrized): `"T1021"`, `"t1566.001"`, `"Phishing"`,
        `"Lateral Movement"` (tactic-level), `"PowerShell"` (fuzzy→T1059.001), `"psexec stuff"`
        (ambiguous → unresolved), `""`/null → no ref, deprecated ID → resolved + flagged.
      - Idempotent upsert: re-running normalization doesn't duplicate `attack_refs`.
- [ ] `tests/test_attack_api.py` (temp DB): seed timeline rows with mixed alignment strings →
      `attack-summary` groups correctly by tactic, counts match, unresolved strings listed;
      typeahead returns ≤N ranked matches; unknown case → 404.
- [ ] Backfill script test against a seeded legacy DB copy.
- [ ] Manual: run extraction on `cases/case_01.txt` with the updated prompt; verify chips render
      and the matrix tab populates.

## Success criteria

1. ≥90% of extraction-produced `attack_alignment` values that reference a real technique/tactic
   resolve to a canonical ID automatically (measured on the 20 sample cases in `cases/`).
2. Nothing analyst-entered is ever overwritten — raw text is preserved alongside normalized refs.
3. The case ATT&CK tab renders tactics in kill-chain order and every chip drills down to its
   supporting evidence rows.
4. Works fully offline; catalog refresh is a documented one-command script.
5. All automated tests pass.
