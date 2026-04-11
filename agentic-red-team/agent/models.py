"""Pydantic decision models for phase boundary flow control.

These are lightweight objects the workflow inspects to decide branching,
skipping, and feedback loops. They are NOT full findings — just decisions
extracted from findings text via a follow-up LLM call.
"""

from typing import Literal

from pydantic import BaseModel, Field


class DiscoveredService(BaseModel):
    """One entry per open port/service discovered in Phase 2."""

    port: int
    protocol: str = "tcp"
    service: str
    version: str = ""


class Phase2Decision(BaseModel):
    """Emitted after Phase 2 scanning & enumeration."""

    services: list[DiscoveredService] = Field(default_factory=list)
    os_guess: str = ""
    skip_phase3: bool = Field(
        default=False,
        description="True if zero services were found — skip ahead to reporting",
    )


class PrioritizedVuln(BaseModel):
    """One entry per vulnerability, ranked for exploitation."""

    id: str = Field(description="CVE ID or descriptive name (e.g. 'anon-ftp')")
    service: str
    port: int
    severity: Literal["Critical", "High", "Medium", "Low"]
    exploit_approach: str = Field(
        description="One-line description: tool and method to exploit"
    )


class Phase3Decision(BaseModel):
    """Emitted after Phase 3 vulnerability identification."""

    vulns: list[PrioritizedVuln] = Field(default_factory=list)
    skip_phase4: bool = Field(
        default=False,
        description="True if no exploitable vulnerabilities were found",
    )


class Phase4Decision(BaseModel):
    """Emitted after Phase 4 exploitation."""

    foothold_obtained: bool = False
    access_level: str = Field(
        default="",
        description="e.g. 'root shell', 'www-data', 'meterpreter session', or empty",
    )
    credentials_found: list[dict] = Field(
        default_factory=list,
        description="List of {user, password, service} dicts discovered during exploitation",
    )
    needs_reenumeration: bool = Field(
        default=False,
        description="True if new credentials or network info warrants re-scanning",
    )
    reenumeration_context: str = Field(
        default="",
        description="Free text: what to re-scan and why (e.g. 'Found SSH creds admin:admin123, re-enumerate with authenticated access')",
    )
    skip_phase5: bool = Field(
        default=False,
        description="True if no foothold was obtained — skip post-exploitation",
    )
