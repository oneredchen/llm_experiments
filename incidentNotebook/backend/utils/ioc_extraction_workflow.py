from typing import TypedDict, Optional, List, Any
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Annotated
import logging
import uuid
import json
from concurrent.futures import ThreadPoolExecutor

import ollama
from langgraph.graph import StateGraph, START, END

logger = logging.getLogger(__name__)

# ==================================
# DATA MODELS
# ==================================

class TimelineOutputFormat(BaseModel):
    submitted_by: Annotated[
        str, Field(max_length=128, description="Analyst or system that submitted the entry.")
    ]
    status_tag: Annotated[
        str, Field(max_length=64, description="Status of the event (e.g., 'Confirmed', 'Suspicious').")
    ]
    system_name: Annotated[
        str, Field(max_length=256, description="Hostname or system where the event occurred.")
    ]
    timestamp_utc: datetime = Field(description="Timezone-aware timestamp of the event in UTC.")
    timestamp_type: Annotated[
        str, Field(max_length=64, description="Type of timestamp (e.g., 'Creation Time', 'Execution Time').")
    ]
    activity: Annotated[
        str, Field(max_length=512, description="Description of the activity that occurred.")
    ]
    evidence_source: Annotated[
        str, Field(max_length=256, description="Source of the evidence (e.g., 'Sysmon', 'MFT').")
    ]
    details_comments: Optional[str] = Field(default=None, description="Detailed comments about the event.")
    attack_alignment: Optional[str] = Field(default=None, max_length=128, description="MITRE ATT&CK alignment, if applicable.")
    size_bytes: Optional[int] = Field(default=None, description="Size of the artifact in bytes.")
    hash: Optional[str] = Field(default=None, max_length=128, description="Hash of the artifact, if applicable.")
    notes: Optional[str] = Field(default=None, description="General notes about the event.")


class TimelineOutputList(BaseModel):
    iocs: List[TimelineOutputFormat]


class HostIOCOutputFormat(BaseModel):
    submitted_by: Annotated[
        str, Field(max_length=128, description="Analyst or system that submitted the IOC.")
    ]
    source: Annotated[
        str, Field(max_length=128, description="Source of the IOC (e.g., 'EDR', 'Analyst Observation').")
    ]
    status: Annotated[
        str, Field(max_length=64, description="Status of the IOC (e.g., 'Confirmed', 'Suspicious').")
    ]
    indicator_id: Annotated[
        str, Field(max_length=256, description="Unique identifier for the IOC.")
    ]
    indicator_type: Annotated[
        str, Field(max_length=64, description="Type of IOC (e.g., 'file', 'process', 'registry').")
    ]
    indicator: Annotated[
        str, Field(max_length=512, description="The IOC itself (e.g., file name, registry key.")
    ]
    full_path: Optional[str] = Field(default=None, max_length=1024, description="Full path of the IOC, if applicable.")
    sha256: Optional[str] = Field(default=None, max_length=64, description="SHA256 hash of the IOC.")
    sha1: Optional[str] = Field(default=None, max_length=40, description="SHA1 hash of the IOC.")
    md5: Optional[str] = Field(default=None, max_length=32, description="MD5 hash of the IOC.")
    type_purpose: Optional[str] = Field(default=None, max_length=128, description="Purpose or context of the IOC type.")
    size_bytes: Optional[int] = Field(default=None, description="Size of the IOC in bytes.")
    notes: Optional[str] = Field(default=None, description="General notes about the IOC.")


class HostIOCOutputList(BaseModel):
    iocs: List[HostIOCOutputFormat]


class NetworkIOCOutputFormat(BaseModel):
    submitted_by: Annotated[
        str, Field(max_length=128, description="Analyst or system that submitted the IOC.")
    ]
    source: Annotated[
        str, Field(max_length=128, description="Source of the IOC (e.g., 'Firewall', 'Proxy Logs').")
    ]
    status: Annotated[
        str, Field(max_length=64, description="Status of the IOC (e.g., 'Confirmed', 'Suspicious').")
    ]
    indicator_id: Annotated[
        str, Field(max_length=256, description="Unique identifier for the IOC.")
    ]
    indicator_type: Annotated[
        str, Field(max_length=64, description="Type of IOC (e.g., 'ip', 'domain', 'url').")
    ]
    indicator: Annotated[
        str, Field(max_length=512, description="The IOC itself (e.g., IP address, domain name).")
    ]
    initial_lead: Optional[str] = Field(default=None, max_length=512, description="Initial lead or context for the IOC.")
    details_comments: Optional[str] = Field(default=None, description="Detailed comments about the IOC.")
    earliest_evidence_utc: Optional[datetime] = Field(default=None, description="Timezone-aware timestamp of the earliest evidence in UTC.")
    attack_alignment: Optional[str] = Field(default=None, max_length=128, description="MITRE ATT&CK alignment, if applicable.")
    notes: Optional[str] = Field(default=None, description="General notes about the IOC.")


class NetworkIOCOutputList(BaseModel):
    iocs: List[NetworkIOCOutputFormat]


# ==================================
# WORKFLOW STATE
# ==================================

class WorkflowState(TypedDict):
    incident_description: str
    llm_model: str
    case_id: str
    ollama_host: Optional[str]
    host_triage: str
    network_triage: str
    host_ioc_objects: List[Any]
    network_ioc_objects: List[Any]
    timeline_objects: List[Any]


# ==================================
# OLLAMA CLIENT HELPERS
# ==================================

def get_client(host: str | None = None):
    if host:
        return ollama.Client(host=host)
    return ollama


def chat_completion(
    client,
    model: str,
    messages: List[dict],
    use_json: bool = False,
    temperature: float = 0.2,
) -> str:
    options = {"temperature": temperature, "num_ctx": 8192, "num_predict": -1}
    kwargs: dict = dict(model=model, messages=messages, options=options)
    if use_json:
        kwargs["format"] = "json"
    response = client.chat(**kwargs)
    return response["message"]["content"]


# ==================================
# TRIAGE HELPERS
# ==================================

def _triage_host(client, model: str, description: str) -> str:
    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity analyst triage expert. Determine if the incident "
                "description contains any potential host-based IOCs (files, processes, registry keys, etc.).\n\n"
                "Respond with a single word:\n"
                "- 'continue' if host-based IOCs are likely present.\n"
                "- 'skip' if only network IOCs or no IOCs are present.\n\n"
                "Do not provide any explanation or other text."
            ),
        },
        {"role": "user", "content": description},
    ]
    decision = chat_completion(client, model, messages).strip().lower()
    logger.info(f"Host triage decision: '{decision}'")
    return decision


def _triage_network(client, model: str, description: str) -> str:
    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity analyst triage expert. Determine if the incident "
                "description contains any potential network-based IOCs (IPs, domains, URLs, etc.).\n\n"
                "Respond with a single word:\n"
                "- 'continue' if network-based IOCs are likely present.\n"
                "- 'skip' if only host-based IOCs or no IOCs are present.\n\n"
                "Do not provide any explanation or other text."
            ),
        },
        {"role": "user", "content": description},
    ]
    decision = chat_completion(client, model, messages).strip().lower()
    logger.info(f"Network triage decision: '{decision}'")
    return decision


# ==================================
# EVALUATION HELPER
# ==================================

def _evaluate(
    client,
    model: str,
    extracted: List[Any],
    type_label: str,
    original_description: str,
) -> str:
    """Evaluates extraction quality against the original incident description."""
    if not extracted:
        return "no_iocs"

    items_str = "\n".join(item.model_dump_json() for item in extracted)
    messages = [
        {
            "role": "system",
            "content": (
                f"You are a senior cybersecurity analyst doing quality control on {type_label} IOC extraction.\n\n"
                "Review the extracted items against the original incident description. Check for:\n"
                "1. Correctness — are the extracted values accurate?\n"
                "2. Completeness — were any indicators missed from the description?\n"
                "3. Schema adherence — are required fields populated correctly?\n"
                "4. Scope — are out-of-scope indicators incorrectly included?\n\n"
                "If the extraction is complete and correct, respond with the single word 'perfect'.\n"
                "Otherwise, provide brief actionable feedback on what to fix or add.\n"
                "Do not attempt to fix the data yourself."
            ),
        },
        {
            "role": "user",
            "content": f"Original incident description:\n{original_description}\n\nExtracted {type_label} data:\n{items_str}",
        },
    ]
    result = chat_completion(client, model, messages).strip()
    logger.info(f"{type_label} evaluation: '{result[:120]}'")
    return result


# ==================================
# EXTRACTION LOOP HELPER
# ==================================

def _run_extraction_loop(
    client,
    model: str,
    description: str,
    base_system_prompt: str,
    output_list_class,
    type_label: str,
    max_attempts: int = 3,
) -> List[Any]:
    """Generic extract → evaluate → refine loop."""
    feedback = None
    last_extraction: List[Any] = []

    for attempt in range(max_attempts):
        logger.info(f"{type_label} extraction attempt {attempt + 1}/{max_attempts}")

        system_prompt = base_system_prompt
        if feedback:
            system_prompt += f"\n\nYour previous attempt had issues. Please improve based on this feedback:\n{feedback}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": description},
        ]

        try:
            response_str = chat_completion(client, model, messages, use_json=True)
            response_json = json.loads(response_str)
            parsed = output_list_class.model_validate(response_json)
            last_extraction = parsed.iocs

            evaluation = _evaluate(client, model, last_extraction, type_label, description)
            if evaluation in ("perfect", "no_iocs"):
                logger.info(f"{type_label} extraction accepted after {attempt + 1} attempt(s).")
                break
            feedback = evaluation

        except Exception as e:
            logger.error(f"{type_label} extraction attempt {attempt + 1} failed: {e}")
            feedback = f"A parsing error occurred: {e}. Ensure the output is valid JSON matching the schema exactly."

    else:
        logger.warning(f"{type_label} extraction reached max attempts ({max_attempts}) without 'perfect' evaluation.")

    return last_extraction


# ==================================
# GRAPH NODES
# ==================================

def run_triage(state: WorkflowState) -> dict:
    """Runs host and network triage in parallel."""
    logger.info(f"[triage] Starting for case {state['case_id']}")
    client = get_client(state.get("ollama_host"))

    with ThreadPoolExecutor(max_workers=2) as executor:
        host_future = executor.submit(_triage_host, client, state["llm_model"], state["incident_description"])
        network_future = executor.submit(_triage_network, client, state["llm_model"], state["incident_description"])
        host_result = host_future.result()
        network_result = network_future.result()

    return {"host_triage": host_result, "network_triage": network_result}


def run_host_extraction(state: WorkflowState) -> dict:
    """Extracts host IOCs. Skips if triage says so."""
    if "continue" not in state.get("host_triage", ""):
        logger.info("[extract_host] Skipping — triage decision was not 'continue'.")
        return {"host_ioc_objects": []}

    logger.info("[extract_host] Starting extraction.")
    client = get_client(state.get("ollama_host"))

    system_prompt = (
        "You are a cybersecurity analyst. Extract ONLY host-based IOCs from the incident narrative "
        "and produce a JSON object with a list of items conforming to the schema.\n\n"
        "HOST_IOC_SCOPE (allowed):\n"
        "- Files, processes, services, drivers, DLLs, local executables\n"
        "- Registry keys/values\n"
        "- Local file paths\n"
        "- Scheduled tasks\n"
        "- Local user/host artifacts\n\n"
        "OUT OF SCOPE (exclude completely):\n"
        "- IP addresses, domains, FQDNs, URLs, URIs, ports, beacons\n"
        "- Pure network telemetry\n\n"
        "REQUIREMENTS:\n"
        "- `indicator_type` must be one of: 'file','process','registry','service','driver','scheduled_task'\n"
        "- `submitted_by`, `source`, and `status` must be short human labels (e.g., 'analyst','Sysmon','Confirmed')\n"
        "- `size_bytes` must be an integer or null\n"
        "- Use null for hash fields if not present\n"
        "- `full_path` can be null if unavailable\n"
        "- Truncate `notes` to <= 800 characters\n\n"
        "Return a JSON object matching this schema:\n"
        + json.dumps(HostIOCOutputList.model_json_schema())
    )

    iocs = _run_extraction_loop(
        client, state["llm_model"], state["incident_description"],
        system_prompt, HostIOCOutputList, "host",
    )

    for ioc in iocs:
        ioc.indicator_id = f"H-{uuid.uuid4()}"

    logger.info(f"[extract_host] Extracted {len(iocs)} host IOC(s).")
    return {"host_ioc_objects": iocs}


def run_network_extraction(state: WorkflowState) -> dict:
    """Extracts network IOCs. Skips if triage says so."""
    if "continue" not in state.get("network_triage", ""):
        logger.info("[extract_network] Skipping — triage decision was not 'continue'.")
        return {"network_ioc_objects": []}

    logger.info("[extract_network] Starting extraction.")
    client = get_client(state.get("ollama_host"))

    system_prompt = (
        "You are a cybersecurity analyst. Extract ONLY network-based IOCs from the incident narrative "
        "and produce a JSON object with a list of items conforming to the schema.\n\n"
        "NETWORK_IOC_SCOPE (allowed):\n"
        "- IP addresses (v4/v6), domains, FQDNs, URLs/URIs\n"
        "- Ports if strongly bound to the indicator\n"
        "- JA3/JA3S fingerprints if explicitly present\n"
        "- C2/beaconing endpoints from proxy/firewall/EDR logs\n\n"
        "OUT OF SCOPE (exclude completely):\n"
        "- File names/paths, processes, registry, scheduled tasks, host-side artifacts\n"
        "- Generic events without a network indicator\n\n"
        "REQUIREMENTS:\n"
        "- `indicator_type` must be one of: 'ip','domain','fqdn','url','uri','ja3','ja3s'\n"
        "- Normalize domains to lowercase; preserve URLs as seen\n"
        "- `submitted_by`, `source`, `status` should be concise labels\n"
        "- `earliest_evidence_utc` must be ISO-8601 with Z if present; else null\n"
        "- Keep `attack_alignment` concise (MITRE style) if clearly implied; else null\n"
        "- Truncate `notes` to <= 800 chars\n\n"
        "Return a JSON object matching this schema:\n"
        + json.dumps(NetworkIOCOutputList.model_json_schema())
    )

    iocs = _run_extraction_loop(
        client, state["llm_model"], state["incident_description"],
        system_prompt, NetworkIOCOutputList, "network",
    )

    for ioc in iocs:
        ioc.indicator_id = f"N-{uuid.uuid4()}"

    logger.info(f"[extract_network] Extracted {len(iocs)} network IOC(s).")
    return {"network_ioc_objects": iocs}


def run_timeline_extraction(state: WorkflowState) -> dict:
    """Extracts timeline events. Always runs."""
    logger.info("[extract_timeline] Starting extraction.")
    client = get_client(state.get("ollama_host"))

    system_prompt = (
        "You are a cybersecurity analyst. Extract timeline events (not raw IOCs) from the incident narrative "
        "and produce a JSON object with a list of items conforming to the schema.\n\n"
        "TIMELINE_SCOPE (include):\n"
        "- Discrete activities with timestamps or clear temporal ordering\n"
        "- Actor/tool behaviors (e.g., 'psexec launched', 'credential dump'), hostnames, and sources\n"
        "- Evidence sources (e.g., 'Sysmon', 'MFT', 'Firewall')\n\n"
        "OUT OF SCOPE:\n"
        "- Pure indicators without an event context\n"
        "- Free-floating IOCs with no time semantics\n\n"
        "REQUIREMENTS:\n"
        "- `timestamp_utc` must be the event time, ISO-8601 with Z\n"
        "- `timestamp_type` from {'Creation Time','Execution Time','Event Time','Discovery Time'}\n"
        "- `status_tag` from {'Confirmed','Suspicious','Benign'}\n"
        "- `system_name` must NOT be null — use 'Unknown' if no hostname is available\n"
        "- `attack_alignment` concise MITRE tactic if clear; else null\n"
        "- `size_bytes` integer or null; `hash` string or null\n"
        "- Truncate `details_comments`/`notes` to <= 1000 chars\n\n"
        "Return a JSON object matching this schema:\n"
        + json.dumps(TimelineOutputList.model_json_schema())
    )

    events = _run_extraction_loop(
        client, state["llm_model"], state["incident_description"],
        system_prompt, TimelineOutputList, "timeline",
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
# PUBLIC ENTRYPOINT (same API as before)
# ==================================

def ioc_extraction_agent_workflow(
    llm_model: str,
    case_id: str,
    incident_description: str,
    ollama_host: str | None = None,
) -> dict:
    logger.info(f"Starting IOC extraction workflow for case: {case_id}")

    initial_state: WorkflowState = {
        "incident_description": incident_description,
        "llm_model": llm_model,
        "case_id": case_id,
        "ollama_host": ollama_host,
        "host_triage": "",
        "network_triage": "",
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
