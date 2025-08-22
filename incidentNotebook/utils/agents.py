from typing import Annotated, List, Literal
from datetime import datetime, timezone
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field
from typing_extensions import TypedDict
from .database import get_database_dialect
import logging

logger = logging.getLogger(__name__)

class SQLStatementList(BaseModel):
    sql_statements: List[str] = Field(
        ..., description="A list of valid SQL statements, each as a string."
    )


class IOCPresence(BaseModel):
    """Schema for indicating the presence of different IOC types."""
    has_host_iocs: bool = Field(..., description="True if host-based IOCs are present.")
    has_network_iocs: bool = Field(..., description="True if network-based IOCs are present.")
    has_timeline_events: bool = Field(..., description="True if timeline events are present.")


class IOCExtractionState(TypedDict):
    messages: Annotated[list, add_messages]
    llm: ChatOllama
    case_id: str
    ioc_presence: IOCPresence | None
    host_ioc_sql_stmts: list[str] | None
    network_ioc_sql_stmts: list[str] | None
    timeline_sql_stmts: list[str] | None
    result: dict[str, list[str]] | None
    database_dialect: str | None


# ==================================
# AGENT PROMPTS & LOGIC
# ==================================

def triage_agent(state: IOCExtractionState):
    """Determine which types of IOCs are present in the incident description."""
    logger.info("Triage agent started.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    messages = [
        {
            "role": "system",
            "content": """You are a senior cybersecurity analyst. Your task is to triage an incident description and determine if it contains host-based IOCs, network-based IOCs, or timeline events. Respond with a structured JSON object indicating the presence of each type.""",
        },
        {"role": "user", "content": last_message.content},
    ]
    response = llm.with_structured_output(IOCPresence).invoke(messages)
    logger.info(f"Triage agent completed. IOC presence: {response}")
    return {"ioc_presence": response}


def host_ioc_agent(state: IOCExtractionState):

    """
    Agent for extracting host IOCs as SQL statements.
    The LLM will generate INSERT statements that match the host_ioc table schema.
    """
    logger.info("Host IOC agent started.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    dialect = state["database_dialect"]
    case_id = state["case_id"]
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    messages = [
        {
            "role": "system",
            "content": f"""You are a cybersecurity analyst and SQL expert. Extract ONLY **host-based** IOCs from the incident narrative and produce valid {dialect} (SQLite) INSERT statements for the `host_ioc` table.

            **CRITICAL: You MUST use the case_id '{case_id}' for all records.**

            SQLITE_RULES:
            - Dialect: SQLite.
            - Always INSERT into the specified table only. Do not emit any other SQL type.
            - Always include an explicit column list in INSERT.
            - Strings must be single-quoted; escape internal quotes by doubling them (e.g., O'Brien -> 'O''Brien').
            - Use NULL (unquoted) when a field is unknown rather than an empty string.
            - Datetimes must be UTC ISO-8601 with Z suffix, e.g., '2025-08-17T04:21:00Z'.
            - Integers must be unquoted (e.g., size_bytes).
            - Limit output to a maximum of 20 INSERT statements.
            - Deduplicate rows by semantic equivalence (case-insensitive for strings, normalized for paths/hosts).
            - Never repeat indicator_id values within the same output list.
            - Use the provided case_id for every row.

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

            TABLE & COLUMNS (complete list, keep order):
            INSERT INTO host_ioc (
            case_id, submitted_by, date_added, source, status,
            indicator_id, indicator_type, indicator, full_path,
            sha256, sha1, md5, type_purpose, size_bytes, notes
            )
            VALUES (...);

            REQUIREMENTS:
            - `indicator_type` must be one of: 'file','process','registry','service','driver','scheduled_task'
            - `submitted_by`, `source`, and `status` must be short, human labels (e.g., 'analyst1','Sysmon','Confirmed').
            - `date_added` must be exactly '{now_utc}'.
            - `size_bytes` must be an integer or NULL.
            - If hashes are absent, use NULL for that field(s).
            - `indicator_id` must be unique within output and follow: '{case_id}-H-{{001..}}' (zero-padded sequence based on occurrence order in your output).
            - Do not invent file paths; if unknown, use NULL for `full_path`.
            - Truncate `notes` to <= 800 characters.

            OUTPUT:
            - Only a Python list of INSERT statements as strings (no commentary).
            - If no host IOCs exist, return [].
            """,
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(SQLStatementList).invoke(messages)
    logger.info(f"Host IOC agent completed. Found {len(response.sql_statements)} statements.")
    print(f"Host IOC SQL Statements: {response.sql_statements}")
    return {"host_ioc_sql_stmts": response.sql_statements}

def network_ioc_agent(state: IOCExtractionState):
    """
    Agent for extracting only network-based IOCs as SQL statements.
    The LLM will ignore non-network IOCs and return an empty list if none are found.
    """
    logger.info("Network IOC agent started.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    dialect = state["database_dialect"]
    case_id = state["case_id"]
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    messages = [
        {
            "role": "system",
            "content": f"""You are a cybersecurity analyst and SQL expert. Extract ONLY **network-based** IOCs from the incident narrative and produce valid {dialect} (SQLite) INSERT statements for the `network_ioc` table.

                **CRITICAL: You MUST use the case_id '{case_id}' for all records.**

                SQLITE_RULES:
                - Dialect: SQLite.
                - Always INSERT into the specified table only. Do not emit any other SQL type.
                - Always include an explicit column list in INSERT.
                - Strings must be single-quoted; escape internal quotes by doubling them (e.g., O'Brien -> 'O''Brien').
                - Use NULL (unquoted) when a field is unknown rather than an empty string.
                - Datetimes must be UTC ISO-8601 with Z suffix, e.g., '2025-08-17T04:21:00Z'.
                - Integers must be unquoted.
                - Limit output to a maximum of 20 INSERT statements.
                - Deduplicate indicators (case-insensitive for domains; canonicalize IPs).
                - Never repeat indicator_id values within the same output list.
                - Use the provided case_id for every row.

                NETWORK_IOC_SCOPE (allowed):
                - IP addresses (v4/v6), domains, FQDNs, URLs/URIs
                - Ports if strongly bound to the indicator/lead
                - JA3/JA3S fingerprints if explicitly present
                - C2 / beaconing endpoints from proxy/firewall/EDR logs

                OUT OF SCOPE (exclude completely):
                - File names/paths, processes, registry, scheduled tasks, host-side artifacts
                - Generic events without a network indicator

                TABLE & COLUMNS (complete list, keep order):
                INSERT INTO network_ioc (
                case_id, submitted_by, date_added, source, status,
                indicator_id, indicator_type, indicator,
                initial_lead, details_comments, earliest_evidence_utc,
                attack_alignment, notes
                )
                VALUES (...);

                REQUIREMENTS:
                - `indicator_type` must be one of: 'ip','domain','fqdn','url','uri','ja3','ja3s'.
                - Normalize domains to lowercase; preserve URLs as seen.
                - `submitted_by`, `source`, `status` should be concise labels.
                - `date_added` must be exactly '{now_utc}'.
                - `earliest_evidence_utc` must be ISO-8601 with Z if present; else NULL.
                - `indicator_id` must be unique in output and follow: '{case_id}-N-{{001..}}'.
                - Keep `attack_alignment` concise (MITRE style) if clearly implied; else NULL.
                - Truncate `notes` to <= 800 chars.

                OUTPUT:
                - Only a Python list of INSERT statements as strings (no commentary).
                - If no network IOCs exist, return [].
                """,
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(SQLStatementList).invoke(messages)
    logger.info(f"Network IOC agent completed. Found {len(response.sql_statements)} statements.")
    print(f"Network IOC SQL Statements: {response.sql_statements}")
    return {"network_ioc_sql_stmts": response.sql_statements}

def timeline_ioc_agent(state: IOCExtractionState):
    """Agent for extracting timeline-based IOCs as SQL INSERT statements.
    The LLM will generate entries based on the 'timeline' table schema.
    """
    logger.info("Timeline IOC agent started.")
    last_message = state["messages"][-1]
    llm = state["llm"]
    dialect = state["database_dialect"]
    case_id = state["case_id"]
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    messages = [
        {
            "role": "system",
            "content": f"""You are a cybersecurity analyst and SQL expert. Extract **timeline events** (not raw IOCs) from the incident narrative and produce valid {dialect} (SQLite) INSERT statements for the `timeline` table.

                **CRITICAL: You MUST use the case_id '{case_id}' for all records.**

                SQLITE_RULES:
                - Dialect: SQLite.
                - Always INSERT into the specified table only. Do not emit any other SQL type.
                - Always include an explicit column list in INSERT.
                - Strings must be single-quoted; escape internal quotes by doubling them.
                - Use NULL (unquoted) when a field is unknown rather than an empty string.
                - Datetimes must be UTC ISO-8601 with Z suffix.
                - Integers must be unquoted.
                - Limit output to a maximum of 20 INSERT statements.
                - Use the provided case_id for every row.

                TIMELINE_SCOPE (include):
                - Discrete activities with timestamps or clear temporal ordering
                - Actor/tool behaviors (e.g., 'psexec launched', 'credential dump'), hostnames, and sources
                - Evidence sources (e.g., 'Sysmon', 'MFT', 'Firewall')

                OUT OF SCOPE:
                - Pure indicators without an “event” context
                - Free-floating IOCs with no time semantics

                TABLE & COLUMNS (complete list, keep order):
                INSERT INTO timeline (
                case_id, submitted_by, date_added, status_tag, system_name,
                timestamp_utc, timestamp_type, activity, evidence_source,
                details_comments, attack_alignment, size_bytes, hash, notes
                )
                VALUES (...);

                REQUIREMENTS:
                - `timestamp_utc` must be the time the event occurred (or best specific time), ISO-8601 with Z.
                - `timestamp_type` from {{'Creation Time','Execution Time','Event Time','Discovery Time'}}.
                - `status_tag` from {{'Confirmed','Suspicious','Benign'}}.
                - `system_name` must NOT be NULL. If a hostname/asset label is present, use it; otherwise use the literal 'Unknown'.
                - `attack_alignment` concise MITRE tactic if clear; else NULL.
                - `size_bytes` integer or NULL; `hash` string or NULL.
                - `date_added` must be exactly '{now_utc}'.
                - Truncate `details_comments`/`notes` to <= 1000 chars.

                OUTPUT:
                - Only a Python list of INSERT statements as strings (no commentary).
                - If no timeline events exist, return [].
                """,
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(SQLStatementList).invoke(messages)
    logger.info(f"Timeline IOC agent completed. Found {len(response.sql_statements)} statements.")
    return {"timeline_sql_stmts": response.sql_statements}

def sql_quality_check_agent(state: IOCExtractionState):
    """Agent to check and correct generated SQL statements."""
    logger.info("SQL quality check agent started.")
    # This is a placeholder for a more sophisticated quality check.
    # For now, it just passes the statements through.
    logger.info("SQL quality check agent completed.")
    return {
        "host_ioc_sql_stmts": state.get("host_ioc_sql_stmts", []),
        "network_ioc_sql_stmts": state.get("network_ioc_sql_stmts", []),
        "timeline_sql_stmts": state.get("timeline_sql_stmts", []),
    }

def ioc_result_aggregator(state: IOCExtractionState):
    """Aggregates the results from the IOC extraction agents."""
    logger.info("IOC result aggregator started.")
    combined_result = {
        "host_ioc_sql_stmts": state.get("host_ioc_sql_stmts", []),
        "network_ioc_sql_stmts": state.get("network_ioc_sql_stmts", []),
        "timeline_sql_stmts": state.get("timeline_sql_stmts", []),
    }
    logger.info("IOC result aggregator completed.")
    return {"result": combined_result}


# ==================================
# CONDITIONAL EDGES
# ==================================

def should_run_host_agent(state: IOCExtractionState) -> Literal["host_ioc_extractor", "sql_quality_checker"]:
    logger.info(f"Checking for host IOCs. Presence: {state["ioc_presence"].has_host_iocs}")
    return "host_ioc_extractor" if state["ioc_presence"].has_host_iocs else "sql_quality_checker"

def should_run_network_agent(state: IOCExtractionState) -> Literal["network_ioc_extractor", "sql_quality_checker"]:
    logger.info(f"Checking for network IOCs. Presence: {state["ioc_presence"].has_network_iocs}")
    return "network_ioc_extractor" if state["ioc_presence"].has_network_iocs else "sql_quality_checker"

def should_run_timeline_agent(state: IOCExtractionState) -> Literal["timeline_ioc_extractor", "sql_quality_checker"]:
    logger.info(f"Checking for timeline events. Presence: {state["ioc_presence"].has_timeline_events}")
    return "timeline_ioc_extractor" if state["ioc_presence"].has_timeline_events else "sql_quality_checker"


# ==================================
# GRAPH CONSTRUCTION
# ==================================

def ioc_extraction_graph_builder():
    graph_builder = StateGraph(IOCExtractionState)

    # Add nodes
    graph_builder.add_node("triage_agent", triage_agent)
    graph_builder.add_node("host_ioc_extractor", host_ioc_agent)
    graph_builder.add_node("network_ioc_extractor", network_ioc_agent)
    graph_builder.add_node("timeline_ioc_extractor", timeline_ioc_agent)
    graph_builder.add_node("sql_quality_checker", sql_quality_check_agent)
    graph_builder.add_node("ioc_result_aggregator", ioc_result_aggregator)

    # Define workflow
    graph_builder.add_edge(START, "triage_agent")

    # Conditional branching from triage
    graph_builder.add_conditional_edges(
        "triage_agent",
        should_run_host_agent,
        {
            "host_ioc_extractor": "host_ioc_extractor",
            "sql_quality_checker": "sql_quality_checker",
        },
    )
    graph_builder.add_conditional_edges(
        "triage_agent",
        should_run_network_agent,
        {
            "network_ioc_extractor": "network_ioc_extractor",
            "sql_quality_checker": "sql_quality_checker",
        },
    )
    graph_builder.add_conditional_edges(
        "triage_agent",
        should_run_timeline_agent,
        {
            "timeline_ioc_extractor": "timeline_ioc_extractor",
            "sql_quality_checker": "sql_quality_checker",
        },
    )

    # Connect extractors to quality checker
    graph_builder.add_edge("host_ioc_extractor", "sql_quality_checker")
    graph_builder.add_edge("network_ioc_extractor", "sql_quality_checker")
    graph_builder.add_edge("timeline_ioc_extractor", "sql_quality_checker")

    # Connect quality checker to aggregator
    graph_builder.add_edge("sql_quality_checker", "ioc_result_aggregator")
    graph_builder.add_edge("ioc_result_aggregator", END)

    return graph_builder.compile()


# ==================================
# WORKFLOW ENTRYPOINT
# ==================================

def ioc_extraction_agent_workflow(
    llm_model: str,
    case_id: str,
    incident_description: str
):
    """Workflow for IOC extraction agent."""
    logger.info(f"Starting IOC extraction workflow for case: {case_id}")
    llm = ChatOllama(
        model=llm_model,
        temperature=0.2,  # Lower temperature for more deterministic output
        num_predict=-2,
        num_ctx=8192,
    )
    initial_message = {
        "role": "user",
        "content": f"Case ID: {case_id}\nIncident Description: {incident_description}",
    }
    graph = ioc_extraction_graph_builder()
    state = {
        "messages": [initial_message],
        "llm": llm,
        "case_id": case_id,
        "database_dialect": get_database_dialect(),
    }
    result_state = graph.invoke(state)
    logger.info(f"IOC extraction workflow completed for case: {case_id}")
    return result_state.get("result", {})