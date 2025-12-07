from typing import Annotated, List, Optional
from typing_extensions import TypedDict
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import logging
import uuid

from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_ollama import ChatOllama


from .database import get_database_dialect

logger = logging.getLogger(__name__)


class TimelineOutputFormat(BaseModel):
    submitted_by: Annotated[
        str,
        Field(
            max_length=128, description="Analyst or system that submitted the entry."
        ),
    ]
    status_tag: Annotated[
        str,
        Field(
            max_length=64,
            description="Status of the event (e.g., 'Confirmed', 'Suspicious').",
        ),
    ]
    system_name: Annotated[
        str,
        Field(
            max_length=256, description="Hostname or system where the event occurred."
        ),
    ]
    timestamp_utc: datetime = Field(
        description="Timezone-aware timestamp of the event in UTC."
    )
    timestamp_type: Annotated[
        str,
        Field(
            max_length=64,
            description="Type of timestamp (e.g., 'Creation Time', 'Execution Time').",
        ),
    ]
    activity: Annotated[
        str,
        Field(max_length=512, description="Description of the activity that occurred."),
    ]
    evidence_source: Annotated[
        str,
        Field(
            max_length=256,
            description="Source of the evidence (e.g., 'Sysmon', 'MFT').",
        ),
    ]

    # Optional fields
    details_comments: Optional[str] = Field(
        default=None, description="Detailed comments about the event."
    )
    attack_alignment: Optional[str] = Field(
        default=None,
        max_length=128,
        description="MITRE ATT&CK alignment, if applicable.",
    )
    size_bytes: Optional[int] = Field(
        default=None, description="Size of the artifact in bytes."
    )
    hash: Optional[str] = Field(
        default=None, max_length=128, description="Hash of the artifact, if applicable."
    )
    notes: Optional[str] = Field(
        default=None, description="General notes about the event."
    )


class TimelineOutputList(BaseModel):
    iocs: List[TimelineOutputFormat]


class HostIOCOutputFormat(BaseModel):
    submitted_by: Annotated[
        str,
        Field(max_length=128, description="Analyst or system that submitted the IOC."),
    ]
    source: Annotated[
        str,
        Field(
            max_length=128,
            description="Source of the IOC (e.g., 'EDR', 'Analyst Observation').",
        ),
    ]
    status: Annotated[
        str,
        Field(
            max_length=64,
            description="Status of the IOC (e.g., 'Confirmed', 'Suspicious').",
        ),
    ]
    indicator_id: Annotated[
        str, Field(max_length=256, description="Unique identifier for the IOC.")
    ]
    indicator_type: Annotated[
        str,
        Field(
            max_length=64,
            description="Type of IOC (e.g., 'file', 'process', 'registry').",
        ),
    ]
    indicator: Annotated[
        str,
        Field(
            max_length=512,
            description="The IOC itself (e.g., file name, registry key.",
        ),
    ]

    # Optional fields
    full_path: Optional[str] = Field(
        default=None,
        max_length=1024,
        description="Full path of the IOC, if applicable.",
    )
    sha256: Optional[str] = Field(
        default=None, max_length=64, description="SHA256 hash of the IOC."
    )
    sha1: Optional[str] = Field(
        default=None, max_length=40, description="SHA1 hash of the IOC."
    )
    md5: Optional[str] = Field(
        default=None, max_length=32, description="MD5 hash of the IOC."
    )
    type_purpose: Optional[str] = Field(
        default=None, max_length=128, description="Purpose or context of the IOC type."
    )
    size_bytes: Optional[int] = Field(
        default=None, description="Size of the IOC in bytes."
    )
    notes: Optional[str] = Field(
        default=None, description="General notes about the IOC."
    )


class HostIOCOutputList(BaseModel):
    iocs: List[HostIOCOutputFormat]


class NetworkIOCOutputFormat(BaseModel):
    # Required (nullable=False in DB)
    submitted_by: Annotated[
        str,
        Field(max_length=128, description="Analyst or system that submitted the IOC."),
    ]
    source: Annotated[
        str,
        Field(
            max_length=128,
            description="Source of the IOC (e.g., 'Firewall', 'Proxy Logs').",
        ),
    ]
    status: Annotated[
        str,
        Field(
            max_length=64,
            description="Status of the IOC (e.g., 'Confirmed', 'Suspicious').",
        ),
    ]
    indicator_id: Annotated[
        str, Field(max_length=256, description="Unique identifier for the IOC.")
    ]
    indicator_type: Annotated[
        str,
        Field(max_length=64, description="Type of IOC (e.g., 'ip', 'domain', 'url')."),
    ]
    indicator: Annotated[
        str,
        Field(
            max_length=512,
            description="The IOC itself (e.g., IP address, domain name).",
        ),
    ]

    # Optional (nullable in DB)
    initial_lead: Optional[str] = Field(
        default=None, max_length=512, description="Initial lead or context for the IOC."
    )
    details_comments: Optional[str] = Field(
        default=None, description="Detailed comments about the IOC."
    )
    earliest_evidence_utc: Optional[datetime] = Field(
        default=None,
        description="Timezone-aware timestamp of the earliest evidence in UTC.",
    )
    attack_alignment: Optional[str] = Field(
        default=None,
        max_length=128,
        description="MITRE ATT&CK alignment, if applicable.",
    )
    notes: Optional[str] = Field(
        default=None, description="General notes about the IOC."
    )


class NetworkIOCOutputList(BaseModel):
    iocs: List[NetworkIOCOutputFormat]


class IOCExtractionState(TypedDict):
    messages: Annotated[list, add_messages]
    llm: ChatOllama
    case_id: str
    host_ioc_decision: str | None
    network_ioc_decision: str | None
    host_ioc_objects: List[HostIOCOutputFormat] | None
    network_ioc_objects: List[NetworkIOCOutputFormat] | None
    timeline_objects: List[TimelineOutputFormat] | None
    result: dict[str, list] | None
    database_dialect: str | None

    # For evaluation loops
    host_ioc_feedback: str | None
    host_retry_count: int
    network_ioc_feedback: str | None
    network_retry_count: int
    timeline_feedback: str | None
    timeline_retry_count: int


# ==================================
# AGENT PROMPTS & LOGIC
# ==================================


def triage_host_iocs(state: IOCExtractionState):
    """
    Determines whether to extract host-based IOCs and stores the decision.
    """
    logger.info("Triage: Checking for host-based IOCs.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    messages = [
        {
            "role": "system",
            "content": """You are a cybersecurity analyst triage expert. Your task is to determine if the provided incident description contains any potential **host-based** Indicators of Compromise (IOCs).

            Respond with a single word:
            - 'continue' if host-based IOCs (files, processes, registry keys, etc.) are likely present.
            - 'skip' if the description contains ONLY network IOCs (IPs, domains) or no IOCs at all.

            Do not provide any explanation or other text.""",
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.invoke(messages)
    decision = response.content.strip().lower()
    logger.info(f"Host-based IOC triage decision: '{decision}'")
    return {"host_ioc_decision": decision}


def decide_host_ioc_path(state: IOCExtractionState):
    """
    Reads the triage decision from the state and returns the next node.
    """
    if "continue" in state.get("host_ioc_decision", "skip"):
        return "host_ioc_extractor"
    return "skip_host_ioc_extraction"


def skip_host_ioc_extraction(state: IOCExtractionState):
    """
    No-op node that skips host IOC extraction.
    """
    logger.info("Skipping host IOC extraction as per triage decision.")
    return {"host_ioc_objects": []}


def triage_network_iocs(state: IOCExtractionState):
    """
    Determines whether to extract network-based IOCs and stores the decision.
    """
    logger.info("Triage: Checking for network-based IOCs.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    messages = [
        {
            "role": "system",
            "content": """You are a cybersecurity analyst triage expert. Your task is to determine if the provided incident description contains any potential **network-based** Indicators of Compromise (IOCs).

            Respond with a single word:
            - 'continue' if network-based IOCs (IPs, domains, URLs, etc.) are likely present.
            - 'skip' if the description contains ONLY host-based IOCs or no IOCs at all.

            Do not provide any explanation or other text.""",
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.invoke(messages)
    decision = response.content.strip().lower()
    logger.info(f"Network-based IOC triage decision: '{decision}'")
    return {"network_ioc_decision": decision}


def decide_network_ioc_path(state: IOCExtractionState):
    """
    Reads the triage decision from the state and returns the next node.
    """
    if "continue" in state.get("network_ioc_decision", "skip"):
        return "network_ioc_extractor"
    return "skip_network_ioc_extraction"


def skip_network_ioc_extraction(state: IOCExtractionState):
    """
    No-op node that skips network IOC extraction.
    """
    logger.info("Skipping network IOC extraction as per triage decision.")
    return {"network_ioc_objects": []}


def host_ioc_agent(state: IOCExtractionState):
    """
    Agent for extracting host IOCs as a list of structured objects.
    """
    logger.info("Host IOC agent started.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    feedback = state.get("host_ioc_feedback")
    retry_count = state.get("host_retry_count", 0)

    system_prompt = """You are a cybersecurity analyst. Extract ONLY **host-based** IOCs from the incident narrative and produce a list of JSON objects conforming to the HostIOCOutputFormat.

        HOST_IOC_SCOPE (allowed):
        - Files, processes, services, drivers, DLLs, local executables
        - Registry keys/values
        - Local file paths
        - Scheduled tasks
        - Local user/host artifacts (NOT network identifiers)

        OUT OF SCOPE (exclude completely):
        - Any IP addresses (v4/v6), domains, FQDNs, URLs, URIs, ports, beacons
        - Pure network telemetry (flows, DNS-only data)
        - High-level events without a host artifact

        REQUIREMENTS:
        - `indicator_type` must be one of: 'file','process','registry','service','driver','scheduled_task'
        - `submitted_by`, `source`, and `status` must be short, human labels (e.g., 'analyst1','Sysmon','Confirmed').
        - `size_bytes` must be an integer or NULL.
        - If hashes are absent, use NULL for that field(s).
        - `indicator_id` must be unique within output and follow: 'H-{{001..}}' (zero-padded sequence based on occurrence order in your output).
        - `full_path` can be NULL if it is not available.
        - Truncate `notes` to <= 800 characters.

        OUTPUT:
        - Only a Python list of HostIOCOutputFormat objects (no commentary).
        - If no host IOCs exist, return an empty list [].
        """
    if feedback:
        system_prompt += f"\n\nYour previous attempt was not perfect. Please improve it based on this feedback: {feedback}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(HostIOCOutputList).invoke(messages)
    for ioc in response.iocs:
        ioc.indicator_id = f"H-{uuid.uuid4()}"
    logger.info(f"Host IOC agent completed. Found {len(response.iocs)} objects.")
    return {"host_ioc_objects": response.iocs, "host_retry_count": retry_count + 1}


def evaluate_host_iocs(state: IOCExtractionState):
    """
    Evaluates the extracted host IOCs and provides feedback.
    """
    logger.info("Evaluating extracted host IOCs.")
    llm = state["llm"]
    host_iocs = state.get("host_ioc_objects")

    if not host_iocs:
        logger.info("No host IOCs to evaluate.")
        return {"host_ioc_feedback": "no_iocs"}

    iocs_str = "\n".join([ioc.model_dump_json() for ioc in host_iocs])
    messages = [
        {
            "role": "system",
            "content": f"""You are a senior cybersecurity analyst responsible for quality control.
            Review the following JSON objects representing host-based IOCs extracted from an incident description.

            Your task is to:
            1.  Check for correctness, completeness, and adherence to the required format.
            2.  Identify any obvious errors, omissions, or areas for improvement.
            3.  Provide concise feedback.

            If the IOCs are good quality and need no changes, respond with the single word "perfect".
            Otherwise, provide a brief, actionable feedback on what to improve (e.g., "Missing indicator_id for some items.", "Indicator_type is incorrect for process IOCs.").
            Do not try to fix the IOCs yourself. Just provide feedback.

            Extracted IOCs:
            {iocs_str}
            """,
        },
    ]
    response = llm.invoke(messages)
    evaluation = response.content.strip()
    logger.info(f"Host IOC evaluation result: '{evaluation}'")
    return {"host_ioc_feedback": evaluation}


def decide_host_loop(state: IOCExtractionState):
    """
    Decides whether to re-run the host IOC extractor.
    """
    feedback = state.get("host_ioc_feedback")
    retry_count = state.get("host_retry_count", 0)
    if feedback and feedback != "perfect" and feedback != "no_iocs" and retry_count < 3:
        return "host_ioc_extractor"
    return "timeline_ioc_extractor"


def network_ioc_agent(state: IOCExtractionState):
    """
    Agent for extracting only network-based IOCs as a list of structured objects.
    """
    logger.info("Network IOC agent started.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    feedback = state.get("network_ioc_feedback")
    retry_count = state.get("network_retry_count", 0)

    system_prompt = """You are a cybersecurity analyst. Extract ONLY **network-based** IOCs from the incident narrative and produce a list of JSON objects conforming to the NetworkIOCOutputFormat.

        NETWORK_IOC_SCOPE (allowed):
        - IP addresses (v4/v6), domains, FQDNs, URLs/URIs
        - Ports if strongly bound to the indicator/lead
        - JA3/JA3S fingerprints if explicitly present
        - C2 / beaconing endpoints from proxy/firewall/EDR logs

        OUT OF SCOPE (exclude completely):
        - File names/paths, processes, registry, scheduled tasks, host-side artifacts
        - Generic events without a network indicator

        REQUIREMENTS:
        - `indicator_type` must be one of: 'ip','domain','fqdn','url','uri','ja3','ja3s'.
        - Normalize domains to lowercase; preserve URLs as seen.
        - `submitted_by`, `source`, `status` should be concise labels.
        - `earliest_evidence_utc` must be ISO-8601 with Z if present; else NULL.
        - `indicator_id` must be unique in output and follow: 'N-{{001..}}'.
        - Keep `attack_alignment` concise (MITRE style) if clearly implied; else NULL.
        - Truncate `notes` to <= 800 chars.

        OUTPUT:
        - Only a Python list of NetworkIOCOutputFormat objects (no commentary).
        - If no network IOCs exist, return an empty list [].
        """
    if feedback:
        system_prompt += f"\n\nYour previous attempt was not perfect. Please improve it based on this feedback: {feedback}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(NetworkIOCOutputList).invoke(messages)
    for ioc in response.iocs:
        ioc.indicator_id = f"N-{uuid.uuid4()}"
    logger.info(f"Network IOC agent completed. Found {len(response.iocs)} objects.")
    return {
        "network_ioc_objects": response.iocs,
        "network_retry_count": retry_count + 1,
    }


def evaluate_network_iocs(state: IOCExtractionState):
    """
    Evaluates the extracted network IOCs and provides feedback.
    """
    logger.info("Evaluating extracted network IOCs.")
    llm = state["llm"]
    network_iocs = state.get("network_ioc_objects")

    if not network_iocs:
        logger.info("No network IOCs to evaluate.")
        return {"network_ioc_feedback": "no_iocs"}

    iocs_str = "\n".join([ioc.model_dump_json() for ioc in network_iocs])
    messages = [
        {
            "role": "system",
            "content": f"""You are a senior cybersecurity analyst responsible for quality control.
            Review the following JSON objects representing network-based IOCs extracted from an incident description.

            Your task is to:
            1.  Check for correctness, completeness, and adherence to the required format.
            2.  Identify any obvious errors, omissions, or areas for improvement.
            3.  Provide concise feedback.

            If the IOCs are good quality and need no changes, respond with the single word "perfect".
            Otherwise, provide a brief, actionable feedback on what to improve (e.g., "Missing indicator_id for some items.", "Indicator_type is incorrect for IP IOCs.").
            Do not try to fix the IOCs yourself. Just provide feedback.

            Extracted IOCs:
            {iocs_str}
            """,
        },
    ]
    response = llm.invoke(messages)
    evaluation = response.content.strip()
    logger.info(f"Network IOC evaluation result: '{evaluation}'")
    return {"network_ioc_feedback": evaluation}


def decide_network_loop(state: IOCExtractionState):
    """
    Decides whether to re-run the network IOC extractor.
    """
    feedback = state.get("network_ioc_feedback")
    retry_count = state.get("network_retry_count", 0)
    if feedback and feedback != "perfect" and feedback != "no_iocs" and retry_count < 3:
        return "network_ioc_extractor"
    return "timeline_ioc_extractor"


def timeline_ioc_agent(state: IOCExtractionState):
    """Agent for extracting timeline-based IOCs as a list of structured objects."""
    logger.info("Timeline IOC agent started.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    feedback = state.get("timeline_feedback")
    retry_count = state.get("timeline_retry_count", 0)

    system_prompt = """You are a cybersecurity analyst. Extract **timeline events** (not raw IOCs) from the incident narrative and produce a list of JSON objects conforming to the TimelineOutputFormat.

        TIMELINE_SCOPE (include):
        - Discrete activities with timestamps or clear temporal ordering
        - Actor/tool behaviors (e.g., 'psexec launched', 'credential dump'), hostnames, and sources
        - Evidence sources (e.g., 'Sysmon', 'MFT', 'Firewall')

        OUT OF SCOPE:
        - Pure indicators without an “event” context
        - Free-floating IOCs with no time semantics

        REQUIREMENTS:
        - `timestamp_utc` must be the time the event occurred (or best specific time), ISO-8601 with Z.
        - `timestamp_type` from {{'Creation Time','Execution Time','Event Time','Discovery Time'}}.
        - `status_tag` from {{'Confirmed','Suspicious','Benign'}}.
        - `system_name` must NOT be NULL. If a hostname/asset label is present, use it; otherwise use the literal 'Unknown'.
        - `attack_alignment` concise MITRE tactic if clear; else NULL.
        - `size_bytes` integer or NULL; `hash` string or NULL.
        - Truncate `details_comments`/`notes` to <= 1000 chars.

        OUTPUT:
        - Only a Python list of TimelineOutputFormat objects (no commentary).
        - If no timeline events exist, return an empty list [].
        """
    if feedback:
        system_prompt += f"\n\nYour previous attempt was not perfect. Please improve it based on this feedback: {feedback}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(TimelineOutputList).invoke(messages)
    logger.info(f"Timeline IOC agent completed. Found {len(response.iocs)} objects.")
    return {"timeline_objects": response.iocs, "timeline_retry_count": retry_count + 1}


def evaluate_timeline_iocs(state: IOCExtractionState):
    """
    Evaluates the extracted timeline IOCs and provides feedback.
    """
    logger.info("Evaluating extracted timeline IOCs.")
    llm = state["llm"]
    timeline_iocs = state.get("timeline_objects")

    if not timeline_iocs:
        logger.info("No timeline IOCs to evaluate.")
        return {"timeline_feedback": "no_iocs"}

    iocs_str = "\n".join([ioc.model_dump_json() for ioc in timeline_iocs])
    messages = [
        {
            "role": "system",
            "content": f"""You are a senior cybersecurity analyst responsible for quality control.
            Review the following JSON objects representing timeline events extracted from an incident description.

            Your task is to:
            1.  Check for correctness, completeness, and adherence to the required format.
            2.  Identify any obvious errors, omissions, or areas for improvement.
            3.  Provide concise feedback.

            If the IOCs are good quality and need no changes, respond with the single word "perfect".
            Otherwise, provide a brief, actionable feedback on what to improve (e.g., "Missing system_name for some items.", "Timestamp format is incorrect.").
            Do not try to fix the IOCs yourself. Just provide feedback.

            Extracted IOCs:
            {iocs_str}
            """,
        },
    ]
    response = llm.invoke(messages)
    evaluation = response.content.strip()
    logger.info(f"Timeline IOC evaluation result: '{evaluation}'")
    return {"timeline_feedback": evaluation}


def decide_timeline_loop(state: IOCExtractionState):
    """
    Decides whether to re-run the timeline IOC extractor.
    """
    feedback = state.get("timeline_feedback")
    retry_count = state.get("timeline_retry_count", 0)
    if feedback and feedback != "perfect" and feedback != "no_iocs" and retry_count < 3:
        return "timeline_ioc_extractor"
    return "ioc_result_aggregator"


def ioc_result_aggregator(state: IOCExtractionState):
    """Aggregates the results from the IOC extraction agents."""
    logger.info("IOC result aggregator started.")
    combined_result = {
        "host_ioc_objects": state.get("host_ioc_objects", []),
        "network_ioc_objects": state.get("network_ioc_objects", []),
        "timeline_objects": state.get("timeline_objects", []),
    }
    logger.info("IOC result aggregator completed.")
    return {"result": combined_result}


# ==================================
# GRAPH CONSTRUCTION
# ==================================


def ioc_extraction_graph_builder():
    graph_builder = StateGraph(IOCExtractionState)

    # Triage nodes
    graph_builder.add_node("triage_host_iocs", triage_host_iocs)
    graph_builder.add_node("triage_network_iocs", triage_network_iocs)

    # Host branch
    graph_builder.add_node("host_ioc_extractor", host_ioc_agent)
    graph_builder.add_node("skip_host_ioc_extraction", skip_host_ioc_extraction)
    graph_builder.add_node("evaluate_host_iocs", evaluate_host_iocs)

    # Network branch
    graph_builder.add_node("network_ioc_extractor", network_ioc_agent)
    graph_builder.add_node("skip_network_ioc_extraction", skip_network_ioc_extraction)
    graph_builder.add_node("evaluate_network_iocs", evaluate_network_iocs)

    # Timeline branch
    graph_builder.add_node("timeline_ioc_extractor", timeline_ioc_agent)
    graph_builder.add_node("evaluate_timeline_iocs", evaluate_timeline_iocs)

    # Aggregator
    graph_builder.add_node("ioc_result_aggregator", ioc_result_aggregator)

    # Start
    graph_builder.add_edge(START, "triage_host_iocs")
    graph_builder.add_edge(START, "triage_network_iocs")

    # Host triage
    graph_builder.add_conditional_edges(
        "triage_host_iocs",
        decide_host_ioc_path,
        {
            "host_ioc_extractor": "host_ioc_extractor",
            "skip_host_ioc_extraction": "timeline_ioc_extractor",
        },
    )

    # Network triage
    graph_builder.add_conditional_edges(
        "triage_network_iocs",
        decide_network_ioc_path,
        {
            "network_ioc_extractor": "network_ioc_extractor",
            "skip_network_ioc_extraction": "timeline_ioc_extractor",
        },
    )

    # Host loop
    graph_builder.add_edge("host_ioc_extractor", "evaluate_host_iocs")
    graph_builder.add_conditional_edges(
        "evaluate_host_iocs",
        decide_host_loop,
        {
            "host_ioc_extractor": "host_ioc_extractor",
            "timeline_ioc_extractor": "timeline_ioc_extractor",
        },
    )

    # Network loop
    graph_builder.add_edge("network_ioc_extractor", "evaluate_network_iocs")
    graph_builder.add_conditional_edges(
        "evaluate_network_iocs",
        decide_network_loop,
        {
            "network_ioc_extractor": "network_ioc_extractor",
            "timeline_ioc_extractor": "timeline_ioc_extractor",
        },
    )

    # Timeline loop
    graph_builder.add_edge("timeline_ioc_extractor", "evaluate_timeline_iocs")
    graph_builder.add_conditional_edges(
        "evaluate_timeline_iocs",
        decide_timeline_loop,
        {
            "timeline_ioc_extractor": "timeline_ioc_extractor",
            "ioc_result_aggregator": "ioc_result_aggregator",
        },
    )

    # End
    graph_builder.add_edge("ioc_result_aggregator", END)

    return graph_builder.compile()


# ==================================
# WORKFLOW ENTRYPOINT
# ==================================


def ioc_extraction_agent_workflow(
    llm_model: str,
    case_id: str,
    incident_description: str,
    ollama_host: str | None = None,
):
    """Workflow for IOC extraction agent."""
    logger.info(f"Starting IOC extraction workflow for case: {case_id}")
    logger.debug(f"LLM Model: {llm_model}")
    logger.debug(f"Incident Description: {incident_description}")

    llm_params = {
        "model": llm_model,
        "temperature": 0.2,  # Lower temperature for more deterministic output
        "num_predict": -2,
        "num_ctx": 8192,
    }
    if ollama_host:
        llm_params["base_url"] = ollama_host

    llm = ChatOllama(**llm_params)
    initial_message = {
        "role": "user",
        "content": f"Incident Description: {incident_description}",
    }
    graph = ioc_extraction_graph_builder()
    state = {
        "messages": [initial_message],
        "llm": llm,
        "case_id": case_id,
        "database_dialect": get_database_dialect(),
        "host_retry_count": 0,
        "network_retry_count": 0,
        "timeline_retry_count": 0,
    }
    logger.info("Invoking IOC extraction graph.")
    result_state = graph.invoke(state)
    logger.info(f"IOC extraction workflow completed for case: {case_id}")
    return result_state.get("result", {})
