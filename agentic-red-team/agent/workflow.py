import json
import logging
import re
from pathlib import Path
from pydantic import BaseModel, Field
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
from agent.tools.kali_api import get_tools

logger = logging.getLogger("agent.workflow")

_PHASE_CONFIGS = [
    (1, "Reconnaissance", PHASE1_SYSTEM_PROMPT),
    (2, "Scanning & Enumeration", PHASE2_SYSTEM_PROMPT),
    (3, "Vulnerability Identification", PHASE3_SYSTEM_PROMPT),
    (4, "Exploitation", PHASE4_SYSTEM_PROMPT),
    (5, "Post-Exploitation", PHASE5_SYSTEM_PROMPT),
    (6, "Reporting", PHASE6_SYSTEM_PROMPT),
]

_STATE_DIR = Path(__file__).parent / "state"
_callback = ToolCallLogger()


# State Management
class WorkflowState(BaseModel):
    target: str = Field(..., description="Target IP address or hostname")
    completion_status: bool = Field(
        ..., description="Completion status of the workflow"
    )
    findings: dict[int, str] = Field(..., description="Findings from each phase")
    current_phase: int = Field(..., description="Current phase of the workflow")


def _state_path(target: str) -> Path:
    safe = re.sub(r"[^\w.\-]", "_", target)
    return _STATE_DIR / f"{safe}.json"


def _save_state(state: WorkflowState) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = _state_path(state.target)
    path.write_text(state.model_dump_json(indent=2))
    logger.info("State saved to %s", path)


def _load_state(target: str) -> WorkflowState | None:
    path = _state_path(target)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        # stored findings keys are strings; convert back to int
        data["findings"] = {int(k): v for k, v in data["findings"].items()}
        state = WorkflowState(**data)
        logger.info("Resuming from saved state: phase %d", state.current_phase)
        return state
    except Exception:
        logger.warning("Failed to load state from %s — starting fresh", path, exc_info=True)
        return None


# Prompt building
def _build_prompt(
    phase_num: int, phase_name: str, target: str, findings: dict[int, str]
) -> str:
    """Construct the user message for a phase agent.

    Phases 1–5 receive only the immediately preceding phase's findings.
    Phase 6 (Reporting) receives all prior phases' findings so the report
    can synthesise the complete engagement.
    """
    lines = [f"Target: {target}", ""]

    if phase_num == 6:
        # Inject all prior phases in order
        for prev in range(1, 6):
            if prev in findings:
                lines.append(f"## Phase {prev} Findings\n{findings[prev]}")
                lines.append("")
    else:
        prev = phase_num - 1
        if prev in findings:
            lines.append(f"## Phase {prev} Findings\n{findings[prev]}")
            lines.append("")

    lines.append(f"Execute Phase {phase_num} — {phase_name} now.")
    return "\n".join(lines)


# Workflow Execution
async def run_workflow(target: str) -> str:
    """
    Run all 6 phases sequentially using prompt chaining.
    Resumes from saved state if a previous run was interrupted.
    Returns the final Phase 6 report.
    """
    saved = _load_state(target)
    if saved and saved.completion_status:
        logger.info("Workflow already complete for %s — returning cached report", target)
        return saved.findings[6]

    findings: dict[int, str] = saved.findings if saved else {}
    state = saved or WorkflowState(
        target=target,
        completion_status=False,
        findings=findings,
        current_phase=1,
    )

    tools = get_tools()

    for phase_num, phase_name, system_prompt in _PHASE_CONFIGS:
        if phase_num in findings:
            logger.info("Skipping Phase %d — %s (already completed)", phase_num, phase_name)
            continue

        state.current_phase = phase_num
        _save_state(state)

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
        state.findings = findings

        logger.info("Phase %d output:\n%s", phase_num, output)
        print(
            f"\n{'=' * 60}\nPhase {phase_num} — {phase_name} complete\n{'=' * 60}\n{output}\n"
        )

        _save_state(state)

    state.completion_status = True
    _save_state(state)

    return findings[6]
