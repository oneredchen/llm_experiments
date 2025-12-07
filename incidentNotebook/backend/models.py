from typing import List, Optional, Annotated
from pydantic import BaseModel, Field
from datetime import datetime

# Case Models
class CaseCreateRequest(BaseModel):
    name: str

class CaseResponse(BaseModel):
    id: int
    case_id: str
    name: str
    status: str
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# IOC Models matching utils/ioc_extraction_workflow.py
# We duplicate the fields here to ensure the API docs match the extraction format.
# We also add DB-specific fields (id, date_added, case_id) as optional or included.

class TimelineEvent(BaseModel):
    # Fields from TimelineOutputFormat
    submitted_by: Annotated[
        str,
        Field(max_length=128, description="Analyst or system that submitted the entry.")
    ]
    status_tag: Annotated[
        str,
        Field(max_length=64, description="Status of the event (e.g., 'Confirmed', 'Suspicious').")
    ]
    system_name: Annotated[
        str,
        Field(max_length=256, description="Hostname or system where the event occurred.")
    ]
    timestamp_utc: datetime = Field(
        description="Timezone-aware timestamp of the event in UTC."
    )
    timestamp_type: Annotated[
        str,
        Field(max_length=64, description="Type of timestamp (e.g., 'Creation Time', 'Execution Time').")
    ]
    activity: Annotated[
        str,
        Field(max_length=512, description="Description of the activity that occurred.")
    ]
    evidence_source: Annotated[
        str,
        Field(max_length=256, description="Source of the evidence (e.g., 'Sysmon', 'MFT').")
    ]
    # Optional fields
    details_comments: Optional[str] = Field(
        default=None, description="Detailed comments about the event."
    )
    attack_alignment: Optional[str] = Field(
        default=None, max_length=128, description="MITRE ATT&CK alignment, if applicable."
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

class HostIOC(BaseModel):
    # Fields from HostIOCOutputFormat
    submitted_by: Annotated[
        str,
        Field(max_length=128, description="Analyst or system that submitted the IOC.")
    ]
    source: Annotated[
        str,
        Field(max_length=128, description="Source of the IOC (e.g., 'EDR', 'Analyst Observation').")
    ]
    status: Annotated[
        str,
        Field(max_length=64, description="Status of the IOC (e.g., 'Confirmed', 'Suspicious').")
    ]
    indicator_id: Annotated[
        str, Field(max_length=256, description="Unique identifier for the IOC.")
    ]
    indicator_type: Annotated[
        str,
        Field(max_length=64, description="Type of IOC (e.g., 'file', 'process', 'registry').")
    ]
    indicator: Annotated[
        str,
        Field(max_length=512, description="The IOC itself (e.g., file name, registry key.")
    ]
    # Optional fields
    full_path: Optional[str] = Field(
        default=None, max_length=1024, description="Full path of the IOC, if applicable."
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

class NetworkIOC(BaseModel):
    # Fields from NetworkIOCOutputFormat
    submitted_by: Annotated[
        str,
        Field(max_length=128, description="Analyst or system that submitted the IOC.")
    ]
    source: Annotated[
        str,
        Field(max_length=128, description="Source of the IOC (e.g., 'Firewall', 'Proxy Logs').")
    ]
    status: Annotated[
        str,
        Field(max_length=64, description="Status of the IOC (e.g., 'Confirmed', 'Suspicious').")
    ]
    indicator_id: Annotated[
        str, Field(max_length=256, description="Unique identifier for the IOC.")
    ]
    indicator_type: Annotated[
        str,
        Field(max_length=64, description="Type of IOC (e.g., 'ip', 'domain', 'url').")
    ]
    indicator: Annotated[
        str,
        Field(max_length=512, description="The IOC itself (e.g., IP address, domain name).")
    ]
    # Optional fields
    initial_lead: Optional[str] = Field(
        default=None, max_length=512, description="Initial lead or context for the IOC."
    )
    details_comments: Optional[str] = Field(
        default=None, description="Detailed comments about the IOC."
    )
    earliest_evidence_utc: Optional[datetime] = Field(
        default=None, description="Timezone-aware timestamp of the earliest evidence in UTC."
    )
    attack_alignment: Optional[str] = Field(
        default=None, max_length=128, description="MITRE ATT&CK alignment, if applicable."
    )
    notes: Optional[str] = Field(
        default=None, description="General notes about the IOC."
    )

class CaseDataResponse(BaseModel):
    host_iocs: List[HostIOC]
    network_iocs: List[NetworkIOC]
    timeline_events: List[TimelineEvent]

# Workflow Models
class ExtractionRequest(BaseModel):
    incident_description: str
    llm_model: str

class ExtractionResponse(BaseModel):
    status: str
    message: str
    counts: dict
