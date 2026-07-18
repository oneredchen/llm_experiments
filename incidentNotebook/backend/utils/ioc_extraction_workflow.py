"""LangGraph IOC extraction workflow.

Graph orchestration (triage → parallel host/network/timeline extraction fan-out)
lives here; every LLM call is delegated to the Pydantic AI agents in
``backend.utils.agents``, which work against any OpenAI-v1-compatible server.
"""

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic_ai import Agent

from backend.utils import agents
from backend.utils.agents import (
    EvaluationResult,
    HostIOCOutputFormat,
    HostIOCOutputList,
    NetworkIOCOutputFormat,
    NetworkIOCOutputList,
    TimelineOutputFormat,
    TimelineOutputList,
    TriageDecision,
)

# Re-exports for backward compatibility (these models used to be defined here).
__all__ = [
    "EvaluationResult",
    "HostIOCOutputFormat",
    "HostIOCOutputList",
    "NetworkIOCOutputFormat",
    "NetworkIOCOutputList",
    "TimelineOutputFormat",
    "TimelineOutputList",
    "TriageDecision",
    "WorkflowState",
    "ioc_extraction_agent_workflow",
]

logger = logging.getLogger(__name__)


# ==================================
# WORKFLOW STATE
# ==================================

class WorkflowState(TypedDict):
    incident_description: str
    llm_model: str
    case_id: str
    host_triage: Optional[TriageDecision]
    network_triage: Optional[TriageDecision]
    host_ioc_objects: List[Any]
    network_ioc_objects: List[Any]
    timeline_objects: List[Any]


# ==================================
# EVALUATION HELPER
# ==================================

def _evaluate(
    model: str,
    extracted: List[Any],
    type_label: str,
    original_description: str,
) -> Optional[EvaluationResult]:
    """Evaluates extraction quality against the original incident description.

    Returns ``None`` when there is nothing to evaluate (the 'no_iocs'
    short-circuit — the evaluator is never called on an empty extraction).
    """
    if not extracted:
        return None

    items_str = "\n".join(item.model_dump_json() for item in extracted)
    result = agents.run_agent_sync(
        agents.get_evaluation_agent(model, type_label),
        model,
        f"Original incident description:\n{original_description}\n\n"
        f"Extracted {type_label} data:\n{items_str}",
    )
    evaluation = result.output
    logger.info(
        f"{type_label} evaluation: verdict='{evaluation.verdict}' "
        f"feedback='{(evaluation.feedback or '')[:120]}'"
    )
    return evaluation


# ==================================
# EXTRACTION LOOP HELPER
# ==================================

def _run_extraction_loop(
    model: str,
    extraction_agent: Agent,
    description: str,
    type_label: str,
    max_attempts: int = 3,
) -> List[Any]:
    """Generic extract → evaluate → refine loop.

    Pydantic AI handles schema injection, JSON parsing, and validation retries
    internally; it raises only after its own retries are exhausted, in which
    case a generic validation-failure feedback line preserves the max-attempts
    behaviour.
    """
    feedback: Optional[str] = None
    last_extraction: List[Any] = []

    for attempt in range(max_attempts):
        logger.info(f"{type_label} extraction attempt {attempt + 1}/{max_attempts}")

        instructions = None
        if feedback:
            instructions = (
                "Your previous attempt had issues. Please improve based on this feedback:\n"
                f"{feedback}"
            )

        try:
            result = agents.run_agent_sync(
                extraction_agent,
                model,
                description,
                instructions=instructions,
            )
            last_extraction = result.output.iocs
        except Exception as e:
            logger.error(f"{type_label} extraction attempt {attempt + 1} failed: {e}")
            feedback = (
                "The previous attempt failed output validation. Ensure every item "
                "matches the required schema exactly."
            )
            continue

        try:
            evaluation = _evaluate(model, last_extraction, type_label, description)
        except Exception as e:
            # A schema-valid extraction is still useful if the optional quality
            # review exhausts its own retries or the provider fails mid-review.
            logger.error(
                f"{type_label} evaluation failed; returning the latest valid "
                f"extraction: {e}"
            )
            break

        if evaluation is None or evaluation.verdict == "perfect":
            logger.info(f"{type_label} extraction accepted after {attempt + 1} attempt(s).")
            break
        feedback = evaluation.feedback or (
            "Improve the extraction against the original incident description."
        )

    else:
        logger.warning(
            f"{type_label} extraction reached max attempts ({max_attempts}) without 'perfect' evaluation."
        )

    return last_extraction


# ==================================
# GRAPH NODES
# ==================================

def run_triage(state: WorkflowState) -> dict:
    """Runs host and network triage in parallel."""
    logger.info(f"[triage] Starting for case {state['case_id']}")
    model = state["llm_model"]
    description = state["incident_description"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        host_future = executor.submit(
            agents.run_agent_sync,
            agents.get_triage_host_agent(model),
            model,
            description,
        )
        network_future = executor.submit(
            agents.run_agent_sync,
            agents.get_triage_network_agent(model),
            model,
            description,
        )
        host_decision = host_future.result().output
        network_decision = network_future.result().output

    logger.info(f"Triage decisions — host: '{host_decision}', network: '{network_decision}'")
    return {"host_triage": host_decision, "network_triage": network_decision}


def run_host_extraction(state: WorkflowState) -> dict:
    """Extracts host IOCs. Skips if triage says so."""
    if state.get("host_triage") != "continue":
        logger.info("[extract_host] Skipping — triage decision was not 'continue'.")
        return {"host_ioc_objects": []}

    logger.info("[extract_host] Starting extraction.")
    iocs = _run_extraction_loop(
        state["llm_model"],
        agents.get_host_extraction_agent(state["llm_model"]),
        state["incident_description"],
        "host",
    )

    for ioc in iocs:
        ioc.indicator_id = f"H-{uuid.uuid4()}"

    logger.info(f"[extract_host] Extracted {len(iocs)} host IOC(s).")
    return {"host_ioc_objects": iocs}


def run_network_extraction(state: WorkflowState) -> dict:
    """Extracts network IOCs. Skips if triage says so."""
    if state.get("network_triage") != "continue":
        logger.info("[extract_network] Skipping — triage decision was not 'continue'.")
        return {"network_ioc_objects": []}

    logger.info("[extract_network] Starting extraction.")
    iocs = _run_extraction_loop(
        state["llm_model"],
        agents.get_network_extraction_agent(state["llm_model"]),
        state["incident_description"],
        "network",
    )

    for ioc in iocs:
        ioc.indicator_id = f"N-{uuid.uuid4()}"

    logger.info(f"[extract_network] Extracted {len(iocs)} network IOC(s).")
    return {"network_ioc_objects": iocs}


def run_timeline_extraction(state: WorkflowState) -> dict:
    """Extracts timeline events. Always runs."""
    logger.info("[extract_timeline] Starting extraction.")
    events = _run_extraction_loop(
        state["llm_model"],
        agents.get_timeline_extraction_agent(state["llm_model"]),
        state["incident_description"],
        "timeline",
    )

    logger.info(f"[extract_timeline] Extracted {len(events)} event(s).")
    return {"timeline_objects": events}


# ==================================
# GRAPH CONSTRUCTION
# ==================================

def _build_workflow():
    graph = StateGraph(WorkflowState)

    graph.add_node("triage", run_triage)
    graph.add_node("extract_host", run_host_extraction)
    graph.add_node("extract_network", run_network_extraction)
    graph.add_node("extract_timeline", run_timeline_extraction)

    graph.add_edge(START, "triage")

    # Fan-out: all three extraction nodes run in parallel after triage
    graph.add_edge("triage", "extract_host")
    graph.add_edge("triage", "extract_network")
    graph.add_edge("triage", "extract_timeline")

    # Fan-in: graph ends when all three branches complete
    graph.add_edge("extract_host", END)
    graph.add_edge("extract_network", END)
    graph.add_edge("extract_timeline", END)

    return graph.compile()


_workflow = _build_workflow()


# ==================================
# PUBLIC ENTRYPOINT
# ==================================

def ioc_extraction_agent_workflow(
    llm_model: str,
    case_id: str,
    incident_description: str,
) -> dict:
    logger.info(f"Starting IOC extraction workflow for case: {case_id}")

    initial_state: WorkflowState = {
        "incident_description": incident_description,
        "llm_model": llm_model,
        "case_id": case_id,
        "host_triage": None,
        "network_triage": None,
        "host_ioc_objects": [],
        "network_ioc_objects": [],
        "timeline_objects": [],
    }

    final_state = _workflow.invoke(initial_state)

    logger.info(
        f"Workflow complete for case {case_id} — "
        f"host: {len(final_state['host_ioc_objects'])}, "
        f"network: {len(final_state['network_ioc_objects'])}, "
        f"timeline: {len(final_state['timeline_objects'])}"
    )

    return {
        "host_ioc_objects": final_state["host_ioc_objects"],
        "network_ioc_objects": final_state["network_ioc_objects"],
        "timeline_objects": final_state["timeline_objects"],
    }
