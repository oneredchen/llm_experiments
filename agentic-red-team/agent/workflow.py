import logging

from agent.callbacks import ToolCallLogger
from agent.llm import create_phase_agent
from agent.prompts import (
    PHASE1_SYSTEM_PROMPT,
    PHASE2_SYSTEM_PROMPT,
    PHASE3_SYSTEM_PROMPT,
    PHASE4_SYSTEM_PROMPT,
    PHASE5_SYSTEM_PROMPT,
    PHASE6_SYSTEM_PROMPT,
)
from agent.tools.kali_mcp import get_tools

logger = logging.getLogger("agent.workflow")

_PHASE_CONFIGS = [
    (1, "Reconnaissance", PHASE1_SYSTEM_PROMPT),
    (2, "Scanning & Enumeration", PHASE2_SYSTEM_PROMPT),
    (3, "Vulnerability Identification", PHASE3_SYSTEM_PROMPT),
    (4, "Exploitation", PHASE4_SYSTEM_PROMPT),
    (5, "Post-Exploitation", PHASE5_SYSTEM_PROMPT),
    (6, "Reporting", PHASE6_SYSTEM_PROMPT),
]

_callback = ToolCallLogger()


def _build_prompt(
    phase_num: int, phase_name: str, target: str, findings: dict[int, str]
) -> str:
    """Construct the user message for a phase agent, injecting only the previous phase's findings."""
    lines = [f"Target: {target}", ""]

    prev = phase_num - 1
    if prev in findings:
        lines.append(f"## Phase {prev} Findings\n{findings[prev]}")
        lines.append("")

    lines.append(f"Execute Phase {phase_num} — {phase_name} now.")
    return "\n".join(lines)


async def run_workflow(target: str) -> str:
    """
    Run all 6 phases sequentially using prompt chaining.
    Each phase agent receives the target plus all findings produced so far.
    Returns the final Phase 6 report.
    """
    tools = await get_tools()
    findings: dict[int, str] = {}

    for phase_num, phase_name, system_prompt in _PHASE_CONFIGS:
        logger.info("=== Starting Phase %d — %s ===", phase_num, phase_name)

        # Phase 6 (Reporting) is synthesis-only — no tools needed
        phase_tools = [] if phase_num == 6 else tools

        agent = create_phase_agent(system_prompt, phase_tools)
        prompt = _build_prompt(phase_num, phase_name, target, findings)

        logger.info("Phase %d prompt:\n%s", phase_num, prompt)

        response = await agent.ainvoke(
            {"messages": [{"role": "user", "content": prompt}]},
            config={"callbacks": [_callback]},
        )

        output = response["messages"][-1].content
        findings[phase_num] = output

        logger.info("Phase %d output:\n%s", phase_num, output)
        print(
            f"\n{'=' * 60}\nPhase {phase_num} — {phase_name} complete\n{'=' * 60}\n{output}\n"
        )

    return findings[6]
