"""LLM phase modules package.

Re-exports the core factory functions and phase modules so the workflow
can import everything from ``agent.llm``.
"""

from agent.llm._base import create_llm, create_phase_agent, extract_decision
from agent.llm import (
    phase1_recon,
    phase2_scanning,
    phase3_vulns,
    phase4_exploit,
    phase5_postexploit,
    phase6_report,
)

__all__ = [
    "create_llm",
    "create_phase_agent",
    "extract_decision",
    "phase1_recon",
    "phase2_scanning",
    "phase3_vulns",
    "phase4_exploit",
    "phase5_postexploit",
    "phase6_report",
]
