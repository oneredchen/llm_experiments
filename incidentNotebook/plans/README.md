# Incident Notebook — Feature Plans

Ten proposed features to make Incident Notebook genuinely useful for incident responders,
each with a detailed implementation plan, testing strategy, and success criteria.

| # | Plan | Feature | Why it matters for IR |
|---|------|---------|-----------------------|
| 1 | [01-manual-ioc-timeline-editing.md](01-manual-ioc-timeline-editing.md) | Manual add / edit / delete of IOCs & timeline events | LLM output is never 100% right; analysts must be able to correct the record |
| 2 | [02-async-extraction-jobs.md](02-async-extraction-jobs.md) | Background extraction jobs with live progress | Extraction blocks the HTTP request for minutes today; analysts need to keep working |
| 3 | [03-case-report-export.md](03-case-report-export.md) | Case report export (XLSX tracker, Markdown, exec summary) | Reporting is a deliverable of every engagement; the XLSX tracker template is already in the repo |
| 4 | [04-ioc-export-formats.md](04-ioc-export-formats.md) | IOC export to STIX 2.1 / MISP / CSV / blocklists | IOCs must flow into EDR/SIEM/firewall tooling and intel-sharing communities |
| 5 | [05-ioc-enrichment.md](05-ioc-enrichment.md) | IOC enrichment (VirusTotal, AbuseIPDB, GeoIP, local cache) | Fast triage of which indicators are known-bad vs. noise |
| 6 | [06-cross-case-correlation.md](06-cross-case-correlation.md) | Cross-case IOC correlation & in-case dedup | Repeat indicators across cases reveal campaigns; duplicates pollute the record |
| 7 | [07-mitre-attack-mapping.md](07-mitre-attack-mapping.md) | MITRE ATT&CK normalization & coverage matrix | Free-text `attack_alignment` becomes validated technique IDs and a navigator-style view |
| 8 | [08-evidence-file-attachments.md](08-evidence-file-attachments.md) | Evidence file attachments with hashing (chain of custody) | Cases need the artifacts, not just notes about them; hashes preserve integrity |
| 9 | [09-global-search-filtering.md](09-global-search-filtering.md) | Global search & advanced filtering | "Have we seen 45.67.89.10 before?" must be answerable in seconds |
| 10 | [10-ioc-validation-defang.md](10-ioc-validation-defang.md) | IOC validation, defang/refang normalization | Real intel arrives defanged (`hxxp://`, `[.]`); hashes/IPs need format validation |
| 11 | [11-pydantic-ai-openai-migration.md](11-pydantic-ai-openai-migration.md) | Migrate LLM layer to Pydantic AI over the OpenAI v1 API | Provider-independent (Ollama, LM Studio, vLLM, …), typed structured outputs, offline-testable workflow |

## Suggested implementation order

0. **Platform migration:** #11 (Pydantic AI + OpenAI v1) — do this before features that add
   LLM calls (#3's exec summary, #7's prompt changes) so they're built on the new agent layer.
1. **Foundations first:** #1 (editing) and #10 (validation/defang) — small, high-value, and other features build on trustworthy data.
2. **Workflow quality of life:** #2 (async jobs) — removes the biggest current usability problem.
3. **Getting data out:** #3 (reports) and #4 (IOC formats) — make the tool's output usable downstream.
4. **Investigation power:** #9 (search), #6 (correlation), #5 (enrichment).
5. **Depth:** #7 (ATT&CK), #8 (evidence files).

## Conventions used in the plans

- File references use paths relative to the repo root (e.g. `backend/routers/cases.py`).
- All new Python code lives under `backend/`, all new UI under `frontend/`.
- Tests go in `tests/`; plans assume `pytest` + FastAPI `TestClient` for backend tests and the
  existing manual scripts remain untouched.
- Schema changes to `backend/utils/database.py` note migration handling for the existing
  `db/incident_notebook.db` (SQLite; plans use additive columns/tables or a one-shot migration script).
