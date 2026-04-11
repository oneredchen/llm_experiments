from typing import Literal
from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str = Field(description="e.g. FINDING-001")
    title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    cvss_score: str | None = None
    cves: list[str] = Field(default_factory=list)
    affected_component: str
    discovered_in_phase: int
    description: str
    evidence: str
    impact: str
    remediation: str


class AttackPathStep(BaseModel):
    step_number: int
    title: str
    description: str
    mitre_tactic: str | None = None


class RemediationItem(BaseModel):
    finding_id: str
    finding_title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    effort: Literal["Low", "Medium", "High"]
    priority: Literal["P1", "P2", "P3", "P4"]
    recommended_owner: str


class CredentialCaptured(BaseModel):
    type: str
    value: str
    source: str
    privilege_level: str


class MethodologyPhase(BaseModel):
    phase_number: int
    phase_name: str
    description: str


class PenTestReport(BaseModel):
    # Cover / metadata
    title: str
    target: str
    assessment_type: str
    classification: str
    prepared_by: str
    generated_on: str
    risk_rating: Literal["Critical", "High", "Medium", "Low"]

    # Executive Summary
    executive_summary: str
    justification: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    foothold_obtained: bool
    highest_privilege: str
    top_recommendations: list[str]

    # Scope
    phases_executed: list[str]
    tools_used: list[str]

    # Methodology
    methodology: list[MethodologyPhase]

    # Technical Findings
    findings: list[Finding]

    # Attack Path
    attack_path: list[AttackPathStep]

    # Credentials
    credentials_captured: list[CredentialCaptured]

    # Remediation
    remediation_roadmap: list[RemediationItem]

    # Appendices (raw text from each phase)
    appendix_recon: str
    appendix_scan: str
    appendix_vulns: str
    appendix_exploitation: str
    appendix_post_exploitation: str