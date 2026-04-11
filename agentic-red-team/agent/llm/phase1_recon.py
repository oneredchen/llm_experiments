"""Phase 1 — Reconnaissance.

Passive information gathering: whois, DNS, host role assessment.
No subagents — single agent with minimal tools.
"""

from agent.llm._shared import SHARED_RULES
from agent.llm._tools import recon_tools

PHASE_NUM = 1
PHASE_NAME = "Reconnaissance"

SYSTEM_PROMPT = f"""
You are an expert red team operator executing Phase 1 — Reconnaissance.

{SHARED_RULES}

## YOUR TASK
First, output your `## Plan` for this phase, then perform passive reconnaissance on the given target IP:
- Query whois / DNS records where applicable
- Identify any publicly available information about the target host
- Note the target's likely role on the network (router, server, workstation, etc.)
- Do NOT actively probe or scan ports yet

## OUTPUT FORMAT
Produce a structured "Phase 1 Findings" block containing:
- Host metadata (hostname, domain, org, ASN if available)
- Any DNS records discovered
- Assessment of likely host type/role
- Recommended entry points to investigate in Phase 2
"""


def get_tools() -> list:
    return recon_tools()


def get_subagents() -> list | None:
    return None
