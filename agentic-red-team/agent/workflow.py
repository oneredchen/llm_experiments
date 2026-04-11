import json
import logging
import re
from pathlib import Path
from pydantic import BaseModel, Field
from langchain_core.messages import AIMessage
from agent.callbacks import ToolCallLogger
from agent.llm import create_llm, create_phase_agent
from agent.prompts import (
    PHASE1_SYSTEM_PROMPT,
    PHASE2_SYSTEM_PROMPT,
    PHASE3_SYSTEM_PROMPT,
    PHASE4_SYSTEM_PROMPT,
    PHASE5_SYSTEM_PROMPT,
    PHASE6_SYSTEM_PROMPT,
)
from agent.report import PenTestReport
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

_MIN_OUTPUT_CHARS = 100
_MAX_RETRIES = 2

_UTILITY_TOOLS = frozenset({
    "run_command", "start_job", "get_job", "cancel_job",
    "list_jobs", "read_file", "list_files",
})

_PHASE_TOOLS: dict[int, frozenset[str]] = {
    1: frozenset(),  # passive recon — utility tools only
    2: frozenset({"nmap", "masscan", "whatweb", "sslscan", "gobuster", "dirb", "nikto", "wpscan", "enum4linux"}),
    3: frozenset({"searchsploit", "nikto", "nmap", "sslscan"}),
    4: frozenset({"metasploit", "msfvenom", "hydra", "sqlmap", "crackmapexec", "smbclient"}),
    5: frozenset({"metasploit", "crackmapexec", "impacket", "john", "hashcat", "smbclient", "linpeas"}),
    6: frozenset(),  # reporting — no tools
}

# Which prior phases to inject into each phase's prompt.
# Phase 6 is handled separately (gets all phases).
_PHASE_CONTEXT: dict[int, list[int]] = {
    1: [],
    2: [1],
    3: [2],
    4: [2, 3],  # needs service table from Phase 2 + vulns from Phase 3
    5: [4],
}


def _tools_for_phase(phase_num: int, all_tools: list) -> list:
    """Return only the tools relevant to a given phase."""
    if phase_num == 6:
        return []
    allowed = _PHASE_TOOLS[phase_num] | _UTILITY_TOOLS
    return [t for t in all_tools if t.name in allowed]

_STATE_DIR = Path(__file__).parent / "state"
_ONGOING_DIR = _STATE_DIR / "ongoing"
_COMPLETED_DIR = _STATE_DIR / "completed"
_callback = ToolCallLogger()


# State Management
class WorkflowState(BaseModel):
    target: str = Field(..., description="Target IP address or hostname")
    completion_status: bool = Field(
        ..., description="Completion status of the workflow"
    )
    findings: dict[int, str] = Field(..., description="Findings from each phase")
    current_phase: int = Field(..., description="Current phase of the workflow")


def _safe_name(target: str) -> str:
    return re.sub(r"[^\w.\-]", "_", target) + ".json"


def _save_state(state: WorkflowState) -> None:
    if state.completion_status:
        dest_dir = _COMPLETED_DIR
        # Remove from ongoing if it was there
        ongoing = _ONGOING_DIR / _safe_name(state.target)
        if ongoing.exists():
            ongoing.unlink()
    else:
        dest_dir = _ONGOING_DIR

    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / _safe_name(state.target)
    path.write_text(state.model_dump_json(indent=2))
    logger.info("State saved to %s", path)


def _load_state(target: str) -> WorkflowState | None:
    name = _safe_name(target)
    # Check completed first (already done), then ongoing (resume)
    for directory in (_COMPLETED_DIR, _ONGOING_DIR):
        path = directory / name
        if path.exists():
            try:
                data = json.loads(path.read_text())
                data["findings"] = {int(k): v for k, v in data["findings"].items()}
                state = WorkflowState(**data)
                logger.info(
                    "Loaded state from %s: phase %d, complete=%s",
                    path, state.current_phase, state.completion_status,
                )
                return state
            except Exception:
                logger.warning("Failed to load state from %s — starting fresh", path, exc_info=True)
                return None
    return None


# Prompt building
def _build_prompt(
    phase_num: int, phase_name: str, target: str, findings: dict[int, str]
) -> str:
    """Construct the user message for a phase agent.

    Each phase receives the prior phases defined in _PHASE_CONTEXT.
    Phase 6 (Reporting) receives all prior phases' findings so the report
    can synthesise the complete engagement.
    """
    lines = [f"Target: {target}", ""]

    if phase_num == 6:
        for prev in range(1, 6):
            if prev in findings:
                lines.append(f"## Phase {prev} Findings\n{findings[prev]}")
                lines.append("")
    else:
        for prev in _PHASE_CONTEXT.get(phase_num, []):
            if prev in findings:
                lines.append(f"## Phase {prev} Findings\n{findings[prev]}")
                lines.append("")

    lines.append(f"Execute Phase {phase_num} — {phase_name} now.")
    return "\n".join(lines)


def _extract_output(messages: list) -> str:
    """Return the last non-empty AIMessage content from the agent response.

    Agents frequently end their message list with ToolMessages or empty AIMessages
    (e.g. when the final step was a tool call). Scanning backwards avoids picking
    up an empty placeholder as the phase output.
    """
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content and msg.content.strip():
            return msg.content
    # Fallback: return whatever the last message has, even if empty
    return messages[-1].content if messages else ""


def _sanitize_json(text: str) -> str:
    """Escape literal control characters found inside JSON string values.

    LLMs sometimes emit bare newlines/tabs within string values instead of
    the required \\n/\\t escape sequences, which makes JSON parsers reject
    the output with a 'control character found' error.
    """
    result: list[str] = []
    in_string = False
    escape_next = False
    for ch in text:
        if escape_next:
            result.append(ch)
            escape_next = False
        elif ch == "\\" and in_string:
            result.append(ch)
            escape_next = True
        elif ch == '"':
            in_string = not in_string
            result.append(ch)
        elif in_string and ord(ch) < 0x20:
            result.append(f"\\u{ord(ch):04x}")
        else:
            result.append(ch)
    return "".join(result)


def _parse_report(raw: str) -> PenTestReport:
    """Extract and parse the JSON report from Phase 6 output."""
    text = raw.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text.strip())
    text = _sanitize_json(text.strip())
    return PenTestReport.model_validate_json(text)


# Workflow Execution
async def run_workflow(target: str) -> PenTestReport:
    """
    Run all 6 phases sequentially using prompt chaining.
    Resumes from saved state if a previous run was interrupted.
    Returns the final Phase 6 report as a PenTestReport.
    """
    saved = _load_state(target)
    if saved and saved.completion_status:
        logger.info("Workflow already complete for %s — returning cached report", target)
        return _parse_report(saved.findings[6])

    findings: dict[int, str] = saved.findings if saved else {}
    state = saved or WorkflowState(
        target=target,
        completion_status=False,
        findings=findings,
        current_phase=1,
    )

    all_tools = get_tools()
    llm = create_llm()

    for phase_num, phase_name, system_prompt in _PHASE_CONFIGS:
        if phase_num in findings:
            logger.info("Skipping Phase %d — %s (already completed)", phase_num, phase_name)
            continue

        state.current_phase = phase_num
        _save_state(state)

        logger.info("=== Starting Phase %d — %s ===", phase_num, phase_name)

        phase_tools = _tools_for_phase(phase_num, all_tools)
        agent = create_phase_agent(system_prompt, phase_tools, llm=llm)
        prompt = _build_prompt(phase_num, phase_name, target, findings)

        logger.info("Phase %d prompt:\n%s", phase_num, prompt)
        logger.info("Phase %d tools: %s", phase_num, [t.name for t in phase_tools])

        output = ""
        for attempt in range(1, _MAX_RETRIES + 2):
            # On retry, nudge the agent about the failed attempt
            if attempt > 1:
                retry_prompt = (
                    f"{prompt}\n\n"
                    f"NOTE: Your previous attempt produced an insufficient response "
                    f"({len(output.strip())} chars). You MUST provide a complete, "
                    f"detailed structured output for this phase."
                )
            else:
                retry_prompt = prompt

            response = await agent.ainvoke(
                {"messages": [{"role": "user", "content": retry_prompt}]},
                config={"callbacks": [_callback]},
            )
            output = _extract_output(response["messages"])
            if len(output.strip()) >= _MIN_OUTPUT_CHARS:
                break
            logger.warning(
                "Phase %d attempt %d produced insufficient output (%d chars) — retrying",
                phase_num, attempt, len(output.strip()),
            )

        if len(output.strip()) < _MIN_OUTPUT_CHARS:
            logger.error(
                "Phase %d produced insufficient output after %d attempts — saving anyway",
                phase_num, _MAX_RETRIES + 1,
            )

        findings[phase_num] = output
        state.findings = findings

        logger.info("Phase %d output:\n%s", phase_num, output)
        print(
            f"\n{'=' * 60}\nPhase {phase_num} — {phase_name} complete\n{'=' * 60}\n{output}\n"
        )

        _save_state(state)

    state.completion_status = True
    _save_state(state)

    return _parse_report(findings[6])
