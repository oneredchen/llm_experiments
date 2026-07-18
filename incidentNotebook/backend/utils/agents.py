"""Pydantic AI agents for the IOC extraction workflow.

All LLM calls in the workflow go through the agents defined here. Agents are
built per model name (cached) on top of the shared model factory in
``backend.utils.llm``, so they work against any OpenAI-v1-compatible server.

Structured output uses ``NativeOutput`` (OpenAI ``json_schema`` response
format) by default, switchable to ``PromptedOutput`` via ``LLM_OUTPUT_MODE``
for servers/models that reject ``json_schema``.
"""

import asyncio
import logging
from datetime import datetime
from functools import lru_cache
from typing import Annotated, Any, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator
from pydantic_ai import Agent, NativeOutput, PromptedOutput
from pydantic_ai.settings import ModelSettings

from backend.utils.llm import build_model, get_output_mode

logger = logging.getLogger(__name__)

# ==================================
# EXTRACTION OUTPUT MODELS
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
# CONTROL-FLOW OUTPUT MODELS
# ==================================

TriageDecision = Literal["continue", "skip"]


class EvaluationResult(BaseModel):
    """Quality-control verdict for one extraction branch."""

    verdict: Literal["perfect", "needs_improvement"] = Field(
        description="'perfect' when the extraction is complete and correct, else 'needs_improvement'."
    )
    feedback: Optional[str] = Field(
        default=None,
        description="Brief actionable feedback on what to fix or add. Required when verdict is 'needs_improvement'.",
    )

    @model_validator(mode="after")
    def require_improvement_feedback(self) -> "EvaluationResult":
        """A refinement verdict is only useful when it says what to refine."""
        if self.verdict == "needs_improvement" and not (
            self.feedback and self.feedback.strip()
        ):
            raise ValueError(
                "feedback must be non-empty when verdict is 'needs_improvement'"
            )
        return self


# ==================================
# PROMPTS (migrated from ioc_extraction_workflow; schema-dump and
# single-word-format instructions removed — Pydantic AI supplies the schema)
# ==================================

TRIAGE_HOST_INSTRUCTIONS = (
    "You are a cybersecurity analyst triage expert. Determine if the incident "
    "description contains any potential host-based IOCs (files, processes, registry keys, etc.).\n\n"
    "- 'continue' if host-based IOCs are likely present.\n"
    "- 'skip' if only network IOCs or no IOCs are present."
)

TRIAGE_NETWORK_INSTRUCTIONS = (
    "You are a cybersecurity analyst triage expert. Determine if the incident "
    "description contains any potential network-based IOCs (IPs, domains, URLs, etc.).\n\n"
    "- 'continue' if network-based IOCs are likely present.\n"
    "- 'skip' if only host-based IOCs or no IOCs are present."
)

HOST_EXTRACTION_INSTRUCTIONS = (
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
    "- Truncate `notes` to <= 800 characters"
)

NETWORK_EXTRACTION_INSTRUCTIONS = (
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
    "- Truncate `notes` to <= 800 chars"
)

TIMELINE_EXTRACTION_INSTRUCTIONS = (
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
    "- Truncate `details_comments`/`notes` to <= 1000 chars"
)


def evaluation_instructions(type_label: str) -> str:
    """QC prompt for one extraction branch; the four criteria are unchanged."""
    return (
        f"You are a senior cybersecurity analyst doing quality control on {type_label} IOC extraction.\n\n"
        "Review the extracted items against the original incident description. Check for:\n"
        "1. Correctness — are the extracted values accurate?\n"
        "2. Completeness — were any indicators missed from the description?\n"
        "3. Schema adherence — are required fields populated correctly?\n"
        "4. Scope — are out-of-scope indicators incorrectly included?\n\n"
        "If the extraction is complete and correct, set verdict to 'perfect'. "
        "Otherwise set verdict to 'needs_improvement' and provide brief actionable "
        "feedback on what to fix or add.\n"
        "Do not attempt to fix the data yourself."
    )


# ==================================
# AGENT BUILDERS (cached per model name)
# ==================================

_MODEL_SETTINGS = ModelSettings(temperature=0.2)
_AGENT_CACHE_SIZE = 32


def _structured(output_type):
    """Wrap an output type in the configured structured-output mode."""
    if get_output_mode() == "prompted":
        return PromptedOutput(output_type)
    return NativeOutput(output_type)


def run_agent_sync(
    agent: Agent,
    model_name: str,
    user_prompt: str,
    *,
    instructions: Optional[str] = None,
) -> Any:
    """Run an agent with a request-scoped model/client.

    Pydantic AI's OpenAI models contain an async HTTP client. The workflow is
    synchronous and executes cached agents from several worker threads, so
    caching a model-bound agent can reuse one async client across different
    event loops. Build and close the model inside the event loop for each call
    while keeping the model-free agent definition cached.

    A model already attached to an agent is retained for offline test doubles
    and explicit caller overrides.
    """

    async def run():
        if agent.model is not None:
            return await agent.run(user_prompt, instructions=instructions)

        model = build_model(model_name)
        async with model:
            return await agent.run(
                user_prompt,
                model=model,
                instructions=instructions,
            )

    return asyncio.run(run())


@lru_cache(maxsize=_AGENT_CACHE_SIZE)
def get_triage_host_agent(model_name: str) -> Agent:
    return Agent(
        None,
        output_type=_structured(TriageDecision),
        instructions=TRIAGE_HOST_INSTRUCTIONS,
        model_settings=_MODEL_SETTINGS,
        retries=2,
        name="triage_host",
    )


@lru_cache(maxsize=_AGENT_CACHE_SIZE)
def get_triage_network_agent(model_name: str) -> Agent:
    return Agent(
        None,
        output_type=_structured(TriageDecision),
        instructions=TRIAGE_NETWORK_INSTRUCTIONS,
        model_settings=_MODEL_SETTINGS,
        retries=2,
        name="triage_network",
    )


@lru_cache(maxsize=_AGENT_CACHE_SIZE)
def get_host_extraction_agent(model_name: str) -> Agent:
    return Agent(
        None,
        output_type=_structured(HostIOCOutputList),
        instructions=HOST_EXTRACTION_INSTRUCTIONS,
        model_settings=_MODEL_SETTINGS,
        retries=2,
        name="extract_host",
    )


@lru_cache(maxsize=_AGENT_CACHE_SIZE)
def get_network_extraction_agent(model_name: str) -> Agent:
    return Agent(
        None,
        output_type=_structured(NetworkIOCOutputList),
        instructions=NETWORK_EXTRACTION_INSTRUCTIONS,
        model_settings=_MODEL_SETTINGS,
        retries=2,
        name="extract_network",
    )


@lru_cache(maxsize=_AGENT_CACHE_SIZE)
def get_timeline_extraction_agent(model_name: str) -> Agent:
    return Agent(
        None,
        output_type=_structured(TimelineOutputList),
        instructions=TIMELINE_EXTRACTION_INSTRUCTIONS,
        model_settings=_MODEL_SETTINGS,
        retries=2,
        name="extract_timeline",
    )


@lru_cache(maxsize=_AGENT_CACHE_SIZE)
def get_evaluation_agent(model_name: str, type_label: str) -> Agent:
    return Agent(
        None,
        output_type=_structured(EvaluationResult),
        instructions=evaluation_instructions(type_label),
        model_settings=_MODEL_SETTINGS,
        retries=2,
        name=f"evaluate_{type_label}",
    )
