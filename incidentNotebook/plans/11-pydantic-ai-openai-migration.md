# Feature 11: Migrate LLM Layer to Pydantic AI over the OpenAI v1 API

## Implementation status (2026-07-18)

**Implemented and verified offline:** all of Phases 1–4, the offline unit-test
suite, and the `/workflow/models` API tests. Success criteria 1, 3, 5, and 6 are
met. **Pending a live LLM server:** the 20-case quality regression eval
(criterion 4) and the two-server interop smoke test (criterion 2) — no server
was reachable in the dev environment at implementation time; run
`uv run python tests/test_workflow.py` once per output mode when one is.

Deviations / discoveries worth knowing:

- pydantic-ai 2.13 specifics: `FunctionModel` test doubles must return a
  `ModelResponse` (not plain dicts); non-object outputs such as `TriageDecision`
  are wrapped as `{"response": ...}` under both `NativeOutput` and
  `PromptedOutput`; `agent.override()` is contextvar-based and does **not**
  propagate across threads — since the LangGraph fan-out runs in thread pools,
  the offline tests monkeypatch the agent getters on `backend.utils.agents`
  instead of using `override()`.
- The extraction output models moved from `ioc_extraction_workflow.py` to
  `agents.py` (re-exported from the workflow module for compatibility) to avoid
  a circular import; `get_evaluation_agent` is cached per
  `(model_name, type_label)` because its instructions embed the label.
- `list_models()` uses `timeout=5s, max_retries=0`: the openai SDK defaults
  retried for minutes, hanging the UI dropdown; verified a stopped server now
  yields the 503 in ~5 s.
- `tests/test_api_refactor.py` needed no mock changes (it's a live-server
  script that never touched `ollama`); it and `tests/test_workflow.py` are
  excluded from default pytest collection via `addopts` in `pyproject.toml`,
  which also sets `pythonpath = ["."]` so `uv run pytest` works from the root.
- `tests/test_workflow.py` (eval script) was migrated to the `openai` SDK and
  the new `ioc_extraction_agent_workflow(llm_model, case_id, incident_description)`
  signature.

## Overview

Replace the `ollama` Python client with **Pydantic AI** agents that talk to any
OpenAI-v1-compatible endpoint (Ollama, LM Studio, vLLM, llama.cpp server, …). The app stops
being Ollama-specific: the backend is configured with a base URL + API key and works with any
local (or hosted) service that implements `POST /v1/chat/completions` and `GET /v1/models`.

LangGraph **stays** as the orchestrator (triage → parallel host/network/timeline fan-out,
re-adopted in commit `15562cf`); only the LLM-call layer inside the nodes changes. Dropping
LangGraph in favour of `pydantic-graph`/asyncio is explicitly out of scope (noted as a
possible follow-up).

## Why

- **Provider independence**: every local LLM service in use speaks OpenAI v1; the `ollama`
  SDK locks the app to one of them.
- **Less bespoke plumbing**: `_run_extraction_loop` in
  `backend/utils/ioc_extraction_workflow.py:242` hand-rolls schema injection
  (`json.dumps(model_json_schema())` appended to prompts), JSON parsing, Pydantic validation,
  and retry-on-parse-error. `Agent(model, output_type=...)` does all of that natively,
  including feeding validation errors back to the model for self-correction.
- **Typed control flow**: triage returns a free string matched with
  `"continue" in state.get("host_triage", "")` (`ioc_extraction_workflow.py:309`) and the
  evaluator is matched against the literal `"perfect"` — both become typed structured outputs.

## Current state (all Ollama touchpoints)

| Location | Usage |
|---|---|
| `backend/utils/ioc_extraction_workflow.py:132` | `get_client()` → `ollama.Client(host=...)` |
| `backend/utils/ioc_extraction_workflow.py:138` | `chat_completion()` → `client.chat(..., format="json", options={temperature, num_ctx: 8192})` |
| `backend/utils/ioc_extraction_workflow.py` | triage / evaluate / extraction-loop helpers built on `chat_completion` |
| `backend/routers/workflow.py:13` | `OLLAMA_HOST` from `.env`, passed into the workflow |
| `backend/routers/workflow.py:82` | `GET /workflow/models` → `client.list()` (Ollama-specific) |
| `.env.template` | `OLLAMA_HOST=http://192.168.50.21:11434` |
| `pyproject.toml` | `ollama>=0.2.1` dependency |

Frontend is unaffected: it selects a model name via `GET /workflow/models` and passes it in
`ExtractionRequest.llm_model` (`frontend/lib/api.ts`), which keeps working unchanged.

## Design decisions

1. **Configuration** — two env vars replace `OLLAMA_HOST`:
   - `LLM_BASE_URL` — e.g. `http://192.168.50.21:11434/v1` (Ollama), `http://localhost:1234/v1`
     (LM Studio), `http://localhost:8000/v1` (vLLM). Note the required `/v1` suffix.
   - `LLM_API_KEY` — default `"local"`; local services accept any non-empty key, and this also
     supports hosted OpenAI-compatible providers later.
   Model selection stays per-request (`llm_model` in the API), unchanged.

2. **One shared model factory**, new module `backend/utils/llm.py`:
   ```python
   def build_model(model_name: str) -> OpenAIChatModel:
       provider = OpenAIProvider(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)
       return OpenAIChatModel(model_name, provider=provider)
   ```
   All agents are built from this factory; nothing else in the codebase constructs clients.

3. **Structured-output mode**: use `NativeOutput` (OpenAI `response_format: json_schema`) for
   the extraction agents — Ollama, LM Studio, and vLLM all support it and it replaces the old
   `format="json"` + schema-in-prompt approach. Make the mode configurable
   (`LLM_OUTPUT_MODE=native|prompted`, default `native`) with `PromptedOutput` as fallback for
   servers/models that reject `json_schema` — this is the main interop risk across local
   services, so it must be a config switch, not a code change.

4. **Agents** (module-level, created per `llm_model` via a small `lru_cache` on model name):
   - `triage_host_agent` / `triage_network_agent` — `output_type=TriageDecision` where
     `TriageDecision = Literal["continue", "skip"]`. Prompt text unchanged apart from removing
     "respond with a single word" formatting instructions.
   - `host_extraction_agent` / `network_extraction_agent` / `timeline_extraction_agent` —
     `output_type=NativeOutput(HostIOCOutputList)` etc.; system prompts keep the SCOPE /
     REQUIREMENTS sections verbatim but **drop** the trailing
     `"Return a JSON object matching this schema: ..."` block (Pydantic AI supplies the schema).
     `retries=2` gives validation self-correction that the old loop only approximated.
   - `evaluation_agent` — `output_type=EvaluationResult`, a new model:
     ```python
     class EvaluationResult(BaseModel):
         verdict: Literal["perfect", "needs_improvement"]
         feedback: Optional[str]  # required when needs_improvement
     ```
     replacing the `"perfect"` string sentinel; the four QC criteria in the prompt are kept.
   - `model_settings=ModelSettings(temperature=0.2)` everywhere, matching today's setting.

5. **Keep the extract → evaluate → refine loop** (it's app logic, not plumbing): rewrite
   `_run_extraction_loop` to call `agent.run_sync()`, drop the manual `json.loads` /
   `model_validate` / parse-error-feedback branches (Pydantic AI raises only after its own
   retries are exhausted — catch, log, and feed a generic "previous attempt failed validation"
   feedback line to preserve the current max-3-attempts behaviour). Sync `run_sync` is correct
   here: LangGraph nodes and the FastAPI endpoint are sync (run in a threadpool), no running
   event loop.

6. **`num_ctx` has no OpenAI-API equivalent.** Today's `options={"num_ctx": 8192}` cannot be
   sent per-request through the v1 API. Handle server-side and document it: for Ollama set
   `OLLAMA_CONTEXT_LENGTH=8192` (or a Modelfile `num_ctx`); LM Studio/vLLM configure context
   at model load. Add this to README's prerequisites — silent truncation of long incident
   descriptions is the sneakiest regression this migration could introduce.

7. **Models endpoint** goes generic: `GET /workflow/models` calls `GET {LLM_BASE_URL}/models`
   via the `openai` SDK (`OpenAI(base_url=..., api_key=...).models.list()`) — the `openai`
   package arrives as a dependency of `pydantic-ai-slim[openai]`, no extra install.

## Implementation tasks

### Phase 1 — Dependencies & configuration

- [x] `uv add "pydantic-ai-slim[openai]"` ; `uv remove ollama`.
- [x] `.env.template`: replace `OLLAMA_HOST` with commented examples:
      ```
      LLM_BASE_URL=http://192.168.50.21:11434/v1   # Ollama (note /v1)
      # LLM_BASE_URL=http://localhost:1234/v1      # LM Studio
      LLM_API_KEY=local
      # LLM_OUTPUT_MODE=native                     # native | prompted
      ```
      Update local `.env` accordingly.
- [x] New `backend/utils/llm.py`: env loading (single place — remove `load_dotenv`/`OLLAMA_HOST`
      from `backend/routers/workflow.py`), `build_model()`, `get_output_mode()`, and a
      startup-time warning log if `LLM_BASE_URL` lacks a `/v1` path (the classic misconfig).

### Phase 2 — Agent layer

- [x] New `backend/utils/agents.py`: `TriageDecision`, `EvaluationResult`, the five agent
      builders (`get_triage_host_agent(model_name)` etc., `lru_cache`d), prompts migrated from
      `ioc_extraction_workflow.py` minus the schema-dump/single-word-format instructions,
      wrapped in `NativeOutput`/`PromptedOutput` per `LLM_OUTPUT_MODE`.

### Phase 3 — Rewrite workflow internals

- [x] `backend/utils/ioc_extraction_workflow.py`:
      - Delete `get_client`, `chat_completion`; imports of `ollama` and `json` (schema dumps) go.
      - `WorkflowState`: drop `ollama_host`; triage fields become `TriageDecision` values.
      - `_triage_host`/`_triage_network` → single `agent.run_sync(description).output` calls
        (keep the 2-worker `ThreadPoolExecutor` fan-out in `run_triage`).
      - `_evaluate` → evaluation agent; loop breaks on `verdict == "perfect"` or empty
        extraction (preserve the `no_iocs` short-circuit for empty lists *before* calling the
        evaluator, as today).
      - `_run_extraction_loop` per design decision 5; unchanged public behaviour: max 3
        attempts, returns last extraction on non-perfect exhaustion, `H-`/`N-` UUID
        `indicator_id` stamping stays in the nodes.
      - `ioc_extraction_agent_workflow(llm_model, case_id, incident_description)` — remove the
        `ollama_host` parameter (grep confirms `backend/routers/workflow.py` is the only caller).
- [x] `backend/routers/workflow.py`: drop `ollama_host` plumbing; rewrite `/workflow/models`
      using the `openai` SDK against `LLM_BASE_URL`; on connection failure return 503 with a
      hint naming the configured base URL (today's 500 with a raw exception is unhelpful when
      the local server is simply not running).

### Phase 4 — Docs & cleanup

- [x] README: prerequisites section rewritten — "any OpenAI-compatible local LLM server",
      per-server base-URL examples, the context-length note from design decision 6, updated
      env-var table. Remove stale Streamlit/`frontend-next` references while in there.
- [x] Optional (flag in PR, don't block): `streamlit` in `pyproject.toml` is a legacy
      dependency of the pre-Next.js UI — remove if `grep` confirms nothing imports it.

## Testing

- [x] **Offline unit tests** — the migration's biggest testing win: Pydantic AI's
      `TestModel`/`FunctionModel` let the whole graph run without any LLM server. New
      `tests/test_workflow_unit.py` (pytest, no network):
      - `Agent.override(model=FunctionModel(...))` per agent to script scenarios:
        - Both triages `continue` → all three extraction branches run, results merged, UUID
          prefixes (`H-`/`N-`) applied.
        - Host triage `skip` → `host_ioc_objects == []` and the host extraction agent is
          never invoked (assert via call-recording FunctionModel).
        - Evaluator returns `needs_improvement` with feedback twice, then `perfect` →
          3 extraction calls, feedback text appears in the 2nd/3rd prompts.
        - Evaluator never satisfied → loop stops at 3 attempts, last extraction returned.
        - Extraction output that fails schema validation on every retry → branch returns `[]`
          and the workflow still completes (no exception to the API layer).
      - `EvaluationResult`/`TriageDecision` validation edge cases.
- [x] **API tests**: update `tests/test_api_refactor.py` mocks if they touch `ollama`;
      add a `/workflow/models` test with the `openai` client mocked (respx or monkeypatch):
      success path returns model IDs; connection-refused path returns 503 with the base URL
      in the detail.
- [ ] **Quality regression eval** (the gate for merging): PENDING — no live LLM server was
      reachable at implementation time. Run `tests/test_workflow.py`
      against the 20 sample incidents in `cases/` on the same local models used for the
      existing baselines (`tests/test_results/test-NN-{gemma3_27b,qwen3_30b,llama3.1_8b}.json`),
      via Ollama's OpenAI endpoint. Compare per-case host/network/timeline counts and key
      indicator values against the baselines; investigate any case where counts drift by more
      than ±20%. Repeat the run once with `LLM_OUTPUT_MODE=prompted` to validate the fallback.
- [ ] **Interop smoke test** (manual, documented in PR): PENDING — needs two live servers.
      Point `LLM_BASE_URL` at at least two
      different servers (e.g. Ollama and LM Studio), run one extraction end-to-end through the
      UI on each, confirm `/workflow/models` populates the dropdown for both.

## Success criteria

1. `grep -r "ollama" backend/` returns nothing; `ollama` is gone from `pyproject.toml`/`uv.lock`.
2. Switching between two different local LLM servers requires only editing `LLM_BASE_URL` —
   no code changes — and both pass an end-to-end extraction through the UI.
3. The full workflow is unit-testable offline: `pytest tests/test_workflow_unit.py` passes
   with no LLM server running and covers triage-skip, refine-loop, and validation-failure paths.
4. Extraction quality is not degraded: the 20-case eval matches the recorded baselines within
   ±20% artifact counts per case on at least one reference model, in both output modes.
5. Frontend behaviour is unchanged (model dropdown, extraction flow) with zero frontend edits.
6. A stopped/unreachable LLM server produces a clear 503 ("Cannot reach LLM server at …")
   rather than an opaque 500.
