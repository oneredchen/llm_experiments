from typing import Annotated, List, Optional, Dict, Any, Type
from datetime import datetime
from pydantic import BaseModel, Field
import logging
import uuid
import json
import ollama

logger = logging.getLogger(__name__)

# ==================================
# DATA MODELS
# ==================================

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


# ==================================
# OLLAMA CLIENT HELPER
# ==================================

def get_client(host: str | None = None):
    if host:
        return ollama.Client(host=host)
    return ollama

def chat_completion(client, model: str, messages: List[Dict], format: str = None, temperature: float = 0.2):
    options = {
        "temperature": temperature,
        "num_ctx": 8192,
        "num_predict": -2
    }
    response = client.chat(model=model, messages=messages, format=format, options=options)
    return response['message']['content']

# ==================================
# TRIAGE LOGIC
# ==================================

def triage_host_iocs(client, model: str, description: str) -> str:
    """Determines whether to extract host-based IOCs."""
    logger.info("Triage: Checking for host-based IOCs.")
    messages = [
        {
            "role": "system",
            "content": """You are a cybersecurity analyst triage expert. Your task is to determine if the provided incident description contains any potential **host-based** Indicators of Compromise (IOCs).

            Respond with a single word:
            - 'continue' if host-based IOCs (files, processes, registry keys, etc.) are likely present.
            - 'skip' if the description contains ONLY network IOCs (IPs, domains) or no IOCs at all.

            Do not provide any explanation or other text.""",
        },
        {"role": "user", "content": description},
    ]
    response = chat_completion(client, model, messages)
    decision = response.strip().lower()
    logger.info(f"Host-based IOC triage decision: '{decision}'")
    return decision

def triage_network_iocs(client, model: str, description: str) -> str:
    """Determines whether to extract network-based IOCs."""
    logger.info("Triage: Checking for network-based IOCs.")
    messages = [
        {
            "role": "system",
            "content": """You are a cybersecurity analyst triage expert. Your task is to determine if the provided incident description contains any potential **network-based** Indicators of Compromise (IOCs).

            Respond with a single word:
            - 'continue' if network-based IOCs (IPs, domains, URLs, etc.) are likely present.
            - 'skip' if the description contains ONLY host-based IOCs or no IOCs at all.

            Do not provide any explanation or other text.""",
        },
        {"role": "user", "content": description},
    ]
    response = chat_completion(client, model, messages)
    decision = response.strip().lower()
    logger.info(f"Network-based IOC triage decision: '{decision}'")
    return decision

# ==================================
# EXTRACTION & EVALUATION LOGIC
# ==================================

def extract_host_iocs(client, model: str, description: str) -> List[HostIOCOutputFormat]:
    """Extracts host IOCs with refinement loop."""
    logger.info("Starting Host IOC extraction loop.")
    
    feedback = None
    last_extraction = []
    
    for attempt in range(3):
        logger.info(f"Host IOC extraction attempt {attempt + 1}")
        
        system_prompt = """You are a cybersecurity analyst. Extract ONLY **host-based** IOCs from the incident narrative and produce a JSON object with a list of items conforming to the schema.

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
        
        Return JSON object matching this schema:
        """ + json.dumps(HostIOCOutputList.model_json_schema())

        if feedback:
            system_prompt += f"\n\nYour previous attempt was not perfect. Please improve it based on this feedback: {feedback}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": description},
        ]
        
        try:
            response_str = chat_completion(client, model, messages, format='json')
            response_json = json.loads(response_str)
            parsed_result = HostIOCOutputList.model_validate(response_json)
            last_extraction = parsed_result.iocs
            
            # Evaluate
            evaluation = evaluate_extraction(client, model, last_extraction, "host")
            if evaluation == "perfect" or evaluation == "no_iocs":
                break
            feedback = evaluation
            
        except Exception as e:
            logger.error(f"Error in Host extraction attempt {attempt + 1}: {e}")
            feedback = f"Encountered error: {str(e)}. Please ensure valid JSON output matching the schema."
            
    # Post-process to ensure UUIDs if needed (though prompt asks for H-001, code might want UUIDs)
    # The original code overwrote indicator_id with UUIDs. Let's do that to match behavior.
    for ioc in last_extraction:
        ioc.indicator_id = f"H-{uuid.uuid4()}"
        
    return last_extraction

def extract_network_iocs(client, model: str, description: str) -> List[NetworkIOCOutputFormat]:
    """Extracts network IOCs with refinement loop."""
    logger.info("Starting Network IOC extraction loop.")
    
    feedback = None
    last_extraction = []
    
    for attempt in range(3):
        logger.info(f"Network IOC extraction attempt {attempt + 1}")
        
        system_prompt = """You are a cybersecurity analyst. Extract ONLY **network-based** IOCs from the incident narrative and produce a JSON object with a list of items conforming to the schema.

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
        
        Return JSON object matching this schema:
        """ + json.dumps(NetworkIOCOutputList.model_json_schema())

        if feedback:
            system_prompt += f"\n\nYour previous attempt was not perfect. Please improve it based on this feedback: {feedback}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": description},
        ]
        
        try:
            response_str = chat_completion(client, model, messages, format='json')
            response_json = json.loads(response_str)
            parsed_result = NetworkIOCOutputList.model_validate(response_json)
            last_extraction = parsed_result.iocs
            
            # Evaluate
            evaluation = evaluate_extraction(client, model, last_extraction, "network")
            if evaluation == "perfect" or evaluation == "no_iocs":
                break
            feedback = evaluation
            
        except Exception as e:
            logger.error(f"Error in Network extraction attempt {attempt + 1}: {e}")
            feedback = f"Encountered error: {str(e)}. Please ensure valid JSON output matching the schema."

    # Post-process UUIDs
    for ioc in last_extraction:
        ioc.indicator_id = f"N-{uuid.uuid4()}"
        
    return last_extraction

def extract_timeline_events(client, model: str, description: str) -> List[TimelineOutputFormat]:
    """Extracts timeline events with refinement loop."""
    logger.info("Starting Timeline extraction loop.")
    
    feedback = None
    last_extraction = []
    
    for attempt in range(3):
        logger.info(f"Timeline extraction attempt {attempt + 1}")
        
        system_prompt = """You are a cybersecurity analyst. Extract **timeline events** (not raw IOCs) from the incident narrative and produce a JSON object with a list of items conforming to the schema.

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
        
        Return JSON object matching this schema:
        """ + json.dumps(TimelineOutputList.model_json_schema())

        if feedback:
            system_prompt += f"\n\nYour previous attempt was not perfect. Please improve it based on this feedback: {feedback}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": description},
        ]
        
        try:
            response_str = chat_completion(client, model, messages, format='json')
            response_json = json.loads(response_str)
            parsed_result = TimelineOutputList.model_validate(response_json)
            last_extraction = parsed_result.iocs
            
            # Evaluate
            evaluation = evaluate_extraction(client, model, last_extraction, "timeline")
            if evaluation == "perfect" or evaluation == "no_iocs":
                break
            feedback = evaluation
            
        except Exception as e:
            logger.error(f"Error in Timeline extraction attempt {attempt + 1}: {e}")
            feedback = f"Encountered error: {str(e)}. Please ensure valid JSON output matching the schema."

    return last_extraction

def evaluate_extraction(client, model: str, extracted_data: List[Any], type_label: str) -> str:
    """Evaluates the extracted data and provides feedback."""
    if not extracted_data:
        return "no_iocs"

    iocs_str = "\n".join([item.model_dump_json() for item in extracted_data])
    
    system_prompt = f"""You are a senior cybersecurity analyst responsible for quality control.
    Review the following JSON objects representing {type_label} data extracted from an incident description.

    Your task is to:
    1.  Check for correctness, completeness, and adherence to the required format.
    2.  Identify any obvious errors, omissions, or areas for improvement.
    3.  Provide concise feedback.

    If the data is good quality and need no changes, respond with the single word "perfect".
    Otherwise, provide a brief, actionable feedback on what to improve.
    Do not try to fix the data yourself. Just provide feedback.
    """
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Extracted Data:\n{iocs_str}"}
    ]
    
    response = chat_completion(client, model, messages)
    evaluation = response.strip()
    logger.info(f"{type_label.capitalize()} evaluation result: '{evaluation}'")
    return evaluation

# ==================================
# WORKFLOW ENTRYPOINT
# ==================================

def ioc_extraction_agent_workflow(
    llm_model: str,
    case_id: str,
    incident_description: str,
    ollama_host: str | None = None,
):
    """Workflow for IOC extraction agent (Replaces LangGraph implementation)."""
    logger.info(f"Starting IOC extraction workflow for case: {case_id}")
    
    client = get_client(ollama_host)
    
    results = {
        "host_ioc_objects": [],
        "network_ioc_objects": [],
        "timeline_objects": []
    }

    # 1. Triage & Extract Host IOCs
    host_decision = triage_host_iocs(client, llm_model, incident_description)
    if "continue" in host_decision:
        results["host_ioc_objects"] = extract_host_iocs(client, llm_model, incident_description)
    else:
        logger.info("Skipping Host IOC extraction.")

    # 2. Triage & Extract Network IOCs
    network_decision = triage_network_iocs(client, llm_model, incident_description)
    if "continue" in network_decision:
        results["network_ioc_objects"] = extract_network_iocs(client, llm_model, incident_description)
    else:
        logger.info("Skipping Network IOC extraction.")

    # 3. Extract Timeline Events (Always runs in original flow)
    results["timeline_objects"] = extract_timeline_events(client, llm_model, incident_description)

    logger.info(f"IOC extraction workflow completed for case: {case_id}")
    return results