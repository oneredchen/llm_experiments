"""Offline unit tests for the IOC extraction workflow.

The whole LangGraph workflow runs without any LLM server: every Pydantic AI
agent is replaced by one backed by a ``FunctionModel`` scripted with canned
JSON responses. Covers triage-skip, the extract → evaluate → refine loop,
max-attempts behaviour, and validation-failure handling.

Run with: ``uv run pytest tests/test_workflow_unit.py``
"""

import json
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError
from pydantic_ai import Agent, NativeOutput
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from backend.utils import agents
from backend.utils.agents import (
    EvaluationResult,
    HostIOCOutputList,
    NetworkIOCOutputList,
    TimelineOutputList,
    TriageDecision,
)
from backend.utils.ioc_extraction_workflow import ioc_extraction_agent_workflow

MODEL = "test-model"

# ---------------------------------------------------------------------------
# Canned payloads
# ---------------------------------------------------------------------------

CONTINUE = {"response": "continue"}
SKIP = {"response": "skip"}
PERFECT = {"verdict": "perfect", "feedback": None}

HOST_IOC = {
    "submitted_by": "analyst",
    "source": "Sysmon",
    "status": "Confirmed",
    "indicator_id": "PENDING",
    "indicator_type": "file",
    "indicator": "evil.exe",
    "full_path": "C:\\Temp\\evil.exe",
    "sha256": "a" * 64,
    "sha1": None,
    "md5": None,
    "type_purpose": None,
    "size_bytes": 1024,
    "notes": None,
}

NETWORK_IOC = {
    "submitted_by": "analyst",
    "source": "Firewall",
    "status": "Suspicious",
    "indicator_id": "PENDING",
    "indicator_type": "ip",
    "indicator": "45.67.89.10",
    "initial_lead": None,
    "details_comments": None,
    "earliest_evidence_utc": None,
    "attack_alignment": None,
    "notes": None,
}

TIMELINE_EVENT = {
    "submitted_by": "analyst",
    "status_tag": "Confirmed",
    "system_name": "WS01",
    "timestamp_utc": "2024-03-01T12:00:00Z",
    "timestamp_type": "Execution Time",
    "activity": "psexec launched",
    "evidence_source": "Sysmon",
    "details_comments": None,
    "attack_alignment": None,
    "size_bytes": None,
    "hash": None,
    "notes": None,
}


def host_ioc(indicator: str) -> dict:
    return {**HOST_IOC, "indicator": indicator}


# ---------------------------------------------------------------------------
# Scripted FunctionModel plumbing
# ---------------------------------------------------------------------------

class ScriptedModel:
    """FunctionModel callable returning scripted JSON payloads, recording calls.

    Payloads are consumed one per call; once exhausted the last payload repeats.
    """

    def __init__(self, payloads: list[Any], name: str = "scripted_model"):
        self.payloads = list(payloads)
        self.calls: list[list] = []
        self.__name__ = name  # FunctionModel requires a __name__ on the callable

    def __call__(self, messages: list, info: AgentInfo) -> ModelResponse:
        self.calls.append(messages)
        payload = self.payloads[min(len(self.calls) - 1, len(self.payloads) - 1)]
        return ModelResponse(parts=[TextPart(content=json.dumps(payload))])

    def instructions(self, call_index: int) -> str:
        """Combined instructions string the model saw on the given call."""
        return "\n".join(
            m.instructions or ""
            for m in self.calls[call_index]
            if isinstance(m, ModelRequest)
        )


def _fake_agent(scripted: ScriptedModel, output_type: Any, name: str) -> Agent:
    return Agent(
        FunctionModel(scripted),
        output_type=NativeOutput(output_type),
        instructions=f"{name} base instructions",
        retries=1,
        name=name,
    )


@pytest.fixture
def scripted(monkeypatch):
    """Bind every workflow agent getter to a ScriptedModel.

    Tests adjust ``.payloads`` before invoking the workflow; call counts and
    seen instructions are asserted via the ScriptedModel instances.
    """
    models = {
        "triage_host": ScriptedModel([CONTINUE]),
        "triage_network": ScriptedModel([CONTINUE]),
        "host": ScriptedModel([{"iocs": [HOST_IOC]}]),
        "network": ScriptedModel([{"iocs": [NETWORK_IOC]}]),
        "timeline": ScriptedModel([{"iocs": [TIMELINE_EVENT]}]),
        "eval_host": ScriptedModel([PERFECT]),
        "eval_network": ScriptedModel([PERFECT]),
        "eval_timeline": ScriptedModel([PERFECT]),
    }

    agent_by_getter = {
        "get_triage_host_agent": _fake_agent(models["triage_host"], TriageDecision, "triage_host"),
        "get_triage_network_agent": _fake_agent(models["triage_network"], TriageDecision, "triage_network"),
        "get_host_extraction_agent": _fake_agent(models["host"], HostIOCOutputList, "extract_host"),
        "get_network_extraction_agent": _fake_agent(models["network"], NetworkIOCOutputList, "extract_network"),
        "get_timeline_extraction_agent": _fake_agent(models["timeline"], TimelineOutputList, "extract_timeline"),
    }
    for getter_name, agent in agent_by_getter.items():
        monkeypatch.setattr(agents, getter_name, lambda *a, _agent=agent, **k: _agent)

    eval_agents = {
        label: _fake_agent(models[f"eval_{label}"], EvaluationResult, f"eval_{label}")
        for label in ("host", "network", "timeline")
    }
    monkeypatch.setattr(
        agents, "get_evaluation_agent", lambda model, label: eval_agents[label]
    )

    return models


def run_workflow() -> dict:
    return ioc_extraction_agent_workflow(
        llm_model=MODEL, case_id="CASE-1", incident_description="Incident narrative."
    )


# ---------------------------------------------------------------------------
# Workflow scenarios
# ---------------------------------------------------------------------------

def test_all_branches_run_and_results_merged(scripted):
    result = run_workflow()

    assert [i.indicator for i in result["host_ioc_objects"]] == ["evil.exe"]
    assert [i.indicator for i in result["network_ioc_objects"]] == ["45.67.89.10"]
    assert [e.activity for e in result["timeline_objects"]] == ["psexec launched"]

    # UUID indicator_id stamping happens in the nodes
    assert result["host_ioc_objects"][0].indicator_id.startswith("H-")
    assert result["network_ioc_objects"][0].indicator_id.startswith("N-")

    # 'perfect' evaluation on the first attempt → exactly one extraction call each
    assert len(scripted["host"].calls) == 1
    assert len(scripted["network"].calls) == 1
    assert len(scripted["timeline"].calls) == 1


def test_host_triage_skip_never_invokes_extraction(scripted):
    scripted["triage_host"].payloads = [SKIP]

    result = run_workflow()

    assert result["host_ioc_objects"] == []
    assert len(scripted["host"].calls) == 0
    # Other branches are unaffected
    assert len(result["network_ioc_objects"]) == 1
    assert len(result["timeline_objects"]) == 1


def test_refine_loop_feeds_feedback_back_into_prompt(scripted):
    scripted["eval_host"].payloads = [
        {"verdict": "needs_improvement", "feedback": "MISSING: add evil.dll"},
        {"verdict": "needs_improvement", "feedback": "STILL MISSING: evil.dll"},
        PERFECT,
    ]

    result = run_workflow()

    assert len(scripted["host"].calls) == 3
    assert "MISSING" not in scripted["host"].instructions(0)
    assert "MISSING: add evil.dll" in scripted["host"].instructions(1)
    assert "STILL MISSING: evil.dll" in scripted["host"].instructions(2)
    assert len(result["host_ioc_objects"]) == 1


def test_never_satisfied_evaluator_stops_at_max_attempts(scripted):
    scripted["host"].payloads = [
        {"iocs": [host_ioc("a.exe")]},
        {"iocs": [host_ioc("b.exe")]},
        {"iocs": [host_ioc("c.exe")]},
    ]
    scripted["eval_host"].payloads = [
        {"verdict": "needs_improvement", "feedback": "not good enough"}
    ]

    result = run_workflow()

    assert len(scripted["host"].calls) == 3
    # The last extraction is returned on non-perfect exhaustion
    assert [i.indicator for i in result["host_ioc_objects"]] == ["c.exe"]


def test_validation_failure_every_attempt_returns_empty(scripted):
    # Payload missing the required 'iocs' key fails output validation on every retry
    scripted["host"].payloads = [{"definitely": "not the schema"}]

    result = run_workflow()

    # The workflow completes without raising and the branch yields nothing
    assert result["host_ioc_objects"] == []
    assert len(result["network_ioc_objects"]) == 1
    # 3 loop attempts, each with its internal validation retry
    assert len(scripted["host"].calls) >= 3


def test_empty_extraction_short_circuits_evaluator(scripted):
    scripted["host"].payloads = [{"iocs": []}]

    result = run_workflow()

    assert result["host_ioc_objects"] == []
    # Accepted on the first attempt without ever calling the evaluator
    assert len(scripted["host"].calls) == 1
    assert len(scripted["eval_host"].calls) == 0


# ---------------------------------------------------------------------------
# Control-flow model validation
# ---------------------------------------------------------------------------

def test_evaluation_result_validation():
    assert EvaluationResult(verdict="perfect").feedback is None
    assert EvaluationResult(verdict="needs_improvement", feedback="fix it").feedback == "fix it"
    with pytest.raises(ValidationError):
        EvaluationResult(verdict="bogus")


def test_triage_decision_validation():
    adapter = TypeAdapter(TriageDecision)
    assert adapter.validate_python("continue") == "continue"
    assert adapter.validate_python("skip") == "skip"
    with pytest.raises(ValidationError):
        adapter.validate_python("bogus")
