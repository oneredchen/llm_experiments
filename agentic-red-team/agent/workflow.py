"""Pentest workflow orchestrator with subagents and feedback loop.

Runs 6 phases with adaptive branching:
  Phase 1 → Phase 2 (subagents) → Phase 3 → Phase 4 (subagents) → Phase 5 → Phase 6
                                                  ↑                    |
                                                  └── feedback loop ───┘
                                                    (max 2 iterations)

Pydantic decision models at phase boundaries control skip/loop logic.
"""

import json
import logging
import re
from datetime import date
from pathlib import Path
from types import ModuleType

from pydantic import BaseModel, Field
from langchain_core.messages import AIMessage

from agent.callbacks import ToolCallLogger
from agent.llm import create_llm, create_phase_agent, extract_decision
from agent.llm import phase1_recon, phase2_scanning, phase3_vulns
from agent.llm import phase4_exploit, phase5_postexploit, phase6_report
from agent.models import Phase2Decision, Phase3Decision, Phase4Decision
from agent.report import PenTestReport

logger = logging.getLogger("agent.workflow")

_MAX_RETRIES = 2
_MAX_FEEDBACK_LOOPS = 2
_MAX_PHASE2_RETRIES = 3

# Patterns that indicate Phase 2 produced actual scan results, not just a plan.
_PHASE2_SCAN_EVIDENCE = re.compile(
    r"(\d+/(tcp|udp)\s+(open|closed|filtered))"  # nmap port line: 80/tcp open
    r"|(\bopen\s+port\b)"                         # "open port" phrase with data
    r"|(PORT\s+STATE\s+SERVICE)"                   # nmap table header
    r"|(\bHost is up\b)"                           # nmap host-up line
    r"|(Discovered open port)",                    # masscan output
    re.IGNORECASE,
)

# Which prior phases to inject into each phase's prompt.
_PHASE_CONTEXT: dict[int, list[int]] = {
    1: [],
    2: [1],
    3: [2],
    4: [1, 2, 3],
    5: [2, 3, 4],
}

_STATE_DIR = Path(__file__).parent / "state"
_ONGOING_DIR = _STATE_DIR / "ongoing"
_COMPLETED_DIR = _STATE_DIR / "completed"
_callback = ToolCallLogger()


# ── State Management ───────────────────────────────────────────────

class WorkflowState(BaseModel):
    target: str = Field(..., description="Target IP address or hostname")
    completion_status: bool = Field(
        ..., description="Completion status of the workflow"
    )
    findings: dict[int, str] = Field(..., description="Findings from each phase")
    current_phase: int = Field(..., description="Current phase of the workflow")
    feedback_loop_count: int = Field(
        default=0, description="Number of feedback loops completed"
    )


def _safe_name(target: str) -> str:
    return re.sub(r"[^\w.\-]", "_", target) + ".json"


def _save_state(state: WorkflowState) -> None:
    if state.completion_status:
        dest_dir = _COMPLETED_DIR
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
                logger.warning(
                    "Failed to load state from %s — starting fresh",
                    path, exc_info=True,
                )
                return None
    return None


# ── Output validation ──────────────────────────────────────────────

def _output_looks_valid(phase_num: int, text: str) -> bool:  # noqa: ARG001
    """Check that the phase produced non-empty output."""
    return bool(text and text.strip())


def _phase2_has_scan_results(text: str) -> bool:
    """Check that Phase 2 output contains actual scan data, not just a plan."""
    return bool(text and _PHASE2_SCAN_EVIDENCE.search(text))


def _extract_output(messages: list) -> str:
    """Return the best AIMessage content from the agent response."""
    ai_messages: list[str] = []
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content and msg.content.strip():
            ai_messages.append(msg.content.strip())

    if not ai_messages:
        return messages[-1].content if messages else ""

    for text in ai_messages:
        if "## Phase" in text or "## " in text or text.startswith("{"):
            return text

    return max(ai_messages, key=len)


# ── Prompt building ────────────────────────────────────────────────

def _build_prompt(
    phase_num: int, phase_name: str, target: str, findings: dict[int, str]
) -> str:
    """Construct the user message for a phase agent."""
    lines = [
        f"You are authorized to test the following target: {target}",
        f"Use {target} as the target IP/hostname for all tool calls in this phase.",
        "",
    ]

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

    lines.append(f"Execute Phase {phase_num} — {phase_name} on {target} now.")
    return "\n".join(lines)


# ── JSON parsing (fallback for Phase 6) ────────────────────────────

def _sanitize_json(text: str) -> str:
    """Escape literal control characters inside JSON string values."""
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
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text.strip())
    text = _sanitize_json(text.strip())
    return PenTestReport.model_validate_json(text)


# ── Phase execution ────────────────────────────────────────────────

async def _run_phase(
    phase_module: ModuleType,
    llm,
    target: str,
    findings: dict[int, str],
) -> str:
    """Build and run a phase agent from its module, with retries."""
    phase_num = phase_module.PHASE_NUM
    phase_name = phase_module.PHASE_NAME

    tools = phase_module.get_tools()
    subagents = phase_module.get_subagents()

    resolved_prompt = phase_module.SYSTEM_PROMPT.replace(
        "{{current_date}}", date.today().isoformat()
    )

    agent = create_phase_agent(
        resolved_prompt,
        tools,
        llm=llm,
        subagents=subagents,
    )

    prompt = _build_prompt(phase_num, phase_name, target, findings)
    logger.info("Phase %d prompt:\n%s", phase_num, prompt)
    logger.info("Phase %d tools: %s", phase_num, [t.name for t in tools])
    if subagents:
        logger.info(
            "Phase %d subagents: %s",
            phase_num, [s["name"] for s in subagents],
        )

    output = ""
    messages = [{"role": "user", "content": prompt}]
    for attempt in range(1, _MAX_RETRIES + 2):
        response = await agent.ainvoke(
            {"messages": messages},
            config={"callbacks": [_callback]},
        )
        output = _extract_output(response["messages"])

        if _output_looks_valid(phase_num, output):
            break

        logger.warning(
            "Phase %d attempt %d produced insufficient output (%d chars) — retrying",
            phase_num, attempt, len(output.strip()),
        )

        retry_msg = (
            f"Your Phase {phase_num} output is incomplete. "
            f"Call the appropriate tools now and produce the full "
            f"structured findings block."
        )

        messages = response["messages"] + [
            {"role": "user", "content": retry_msg}
        ]

    if not _output_looks_valid(phase_num, output):
        logger.error(
            "Phase %d produced insufficient output after %d attempts — saving anyway",
            phase_num, _MAX_RETRIES + 1,
        )

    logger.info("Phase %d output:\n%s", phase_num, output)
    print(
        f"\n{'=' * 60}\nPhase {phase_num} — {phase_name} complete\n{'=' * 60}\n{output}\n"
    )
    return output


async def _run_targeted_reenum(
    llm,
    target: str,
    findings: dict[int, str],
    reenum_context: str,
) -> str:
    """Run a targeted re-enumeration using Phase 2 infrastructure.

    Appends to existing Phase 2 findings rather than replacing them.
    """
    tools = phase2_scanning.get_tools()
    subagents = phase2_scanning.get_subagents()

    resolved_prompt = phase2_scanning.SYSTEM_PROMPT.replace(
        "{{current_date}}", date.today().isoformat()
    )

    agent = create_phase_agent(
        resolved_prompt, tools, llm=llm, subagents=subagents
    )

    prompt = (
        f"Target: {target}\n\n"
        f"## Previous Phase 2 Findings\n{findings[2]}\n\n"
        f"## Re-enumeration Directive\n{reenum_context}\n\n"
        f"Perform TARGETED re-enumeration based on the new information above. "
        f"Do NOT repeat the full port scan. Focus only on the services and "
        f"access methods indicated by the new context. Use subagents as needed."
    )

    logger.info("Targeted re-enumeration prompt:\n%s", prompt)

    response = await agent.ainvoke(
        {"messages": [{"role": "user", "content": prompt}]},
        config={"callbacks": [_callback]},
    )

    new_findings = _extract_output(response["messages"])
    combined = findings[2] + f"\n\n## Re-enumeration Findings\n{new_findings}"

    logger.info("Re-enumeration output:\n%s", new_findings)
    print(
        f"\n{'=' * 60}\nRe-enumeration complete\n{'=' * 60}\n{new_findings}\n"
    )
    return combined


async def _run_report(
    llm, target: str, findings: dict[int, str]
) -> PenTestReport:
    """Run Phase 6 with structured output and return a PenTestReport."""
    resolved_prompt = phase6_report.SYSTEM_PROMPT.replace(
        "{{current_date}}", date.today().isoformat()
    )

    agent = create_phase_agent(
        resolved_prompt,
        tools=[],
        llm=llm,
        response_format=PenTestReport,
    )

    prompt = _build_prompt(6, phase6_report.PHASE_NAME, target, findings)
    logger.info("Phase 6 prompt:\n%s", prompt)

    response = await agent.ainvoke(
        {"messages": [{"role": "user", "content": prompt}]},
        config={"callbacks": [_callback]},
    )

    if response.get("structured_response"):
        report = response["structured_response"]
        output = report.model_dump_json(indent=2)
    else:
        output = _extract_output(response["messages"])
        report = _parse_report(output)

    findings[6] = output
    logger.info("Phase 6 output:\n%s", output)
    print(f"\n{'=' * 60}\nPhase 6 — Reporting complete\n{'=' * 60}\n{output}\n")
    return report


# ── Main workflow ──────────────────────────────────────────────────

def _validate_target(target: str) -> str:
    """Validate and normalize the target string.

    Accepts IPv4 addresses and hostnames/FQDNs. Rejects obviously invalid
    targets that would waste LLM calls.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty")

    # Reject common argparse/placeholder mistakes
    _INVALID_TARGETS = {"targets", "target", "hosts", "host", "ip", "ips", "none", "null", "test", "example"}
    if target.lower() in _INVALID_TARGETS:
        raise ValueError(
            f"'{target}' looks like a placeholder, not a real target. "
            f"Pass an IP address or hostname (e.g. 192.168.1.1 or host.example.com)."
        )

    return target


async def run_workflow(target: str) -> PenTestReport:
    """Run the pentest workflow with adaptive branching and feedback loop.

    Flow:
      Phase 1 → Phase 2 → [decision] → Phase 3 → [decision] → Phase 4
      → [decision: feedback loop?] → Phase 5 → Phase 6

    Resumes from saved state if a previous run was interrupted.
    """
    target = _validate_target(target)
    saved = _load_state(target)
    if saved and saved.completion_status:
        logger.info(
            "Workflow already complete for %s — returning cached report", target
        )
        return _parse_report(saved.findings[6])

    findings: dict[int, str] = saved.findings if saved else {}
    state = saved or WorkflowState(
        target=target,
        completion_status=False,
        findings=findings,
        current_phase=1,
    )

    llm = create_llm()

    # ── Phase 1: Reconnaissance ────────────────────────────────────
    if 1 not in findings:
        state.current_phase = 1
        _save_state(state)
        findings[1] = await _run_phase(phase1_recon, llm, target, findings)
        state.findings = findings
        _save_state(state)

    # ── Phase 2: Scanning & Enumeration (with subagents) ───────────
    if 2 not in findings:
        state.current_phase = 2
        _save_state(state)
        findings[2] = await _run_phase(phase2_scanning, llm, target, findings)
        state.findings = findings
        _save_state(state)

    # Validate Phase 2 produced actual scan results, not just a plan.
    # Retry with progressively more direct prompts if needed.
    phase2_retry = 0
    while not _phase2_has_scan_results(findings[2]) and phase2_retry < _MAX_PHASE2_RETRIES:
        phase2_retry += 1
        logger.warning(
            "Phase 2 output lacks scan evidence (attempt %d/%d) — re-running",
            phase2_retry, _MAX_PHASE2_RETRIES,
        )
        del findings[2]
        state.current_phase = 2
        _save_state(state)
        findings[2] = await _run_phase(phase2_scanning, llm, target, findings)
        state.findings = findings
        _save_state(state)

    if not _phase2_has_scan_results(findings[2]):
        logger.error(
            "Phase 2 failed to produce scan results after %d retries",
            _MAX_PHASE2_RETRIES,
        )

    # Extract Phase 2 decision
    logger.info("Extracting Phase 2 decision...")
    p2_decision = await extract_decision(llm, findings[2], Phase2Decision)
    logger.info(
        "Phase 2 decision: %d services, skip_phase3=%s",
        len(p2_decision.services), p2_decision.skip_phase3,
    )

    if p2_decision.skip_phase3:
        # Only skip if Phase 2 actually ran a scan and found nothing.
        # If Phase 2 never produced real scan data, this is a failure, not
        # a legitimate "no services" result.
        if _phase2_has_scan_results(findings[2]):
            logger.info("Scan completed — no services found. Skipping to report.")
        else:
            logger.warning(
                "Phase 2 never produced real scan data but decision says skip. "
                "Proceeding to report with incomplete results."
            )
        findings.setdefault(3, "No services discovered. Phase 3 skipped.")
        findings.setdefault(4, "No vulnerabilities to exploit. Phase 4 skipped.")
        findings.setdefault(5, "No foothold obtained. Phase 5 skipped.")
        state.findings = findings
        state.completion_status = True
        _save_state(state)
        return await _run_report(llm, target, findings)

    # ── Phase 3: Vulnerability Identification ──────────────────────
    if 3 not in findings:
        state.current_phase = 3
        _save_state(state)
        findings[3] = await _run_phase(phase3_vulns, llm, target, findings)
        state.findings = findings
        _save_state(state)

    # Detect if Phase 3 explicitly says it lacks Phase 2 data — this means
    # the pipeline is broken, not that there are no vulns.
    _phase3_missing_data = any(
        phrase in findings[3].lower()
        for phrase in ["don't have the phase 2", "no phase 2", "missing phase 2", "need the", "could you provide"]
    )

    # Extract Phase 3 decision
    logger.info("Extracting Phase 3 decision...")
    p3_decision = await extract_decision(llm, findings[3], Phase3Decision)
    logger.info(
        "Phase 3 decision: %d vulns, skip_phase4=%s, missing_data=%s",
        len(p3_decision.vulns), p3_decision.skip_phase4, _phase3_missing_data,
    )

    if p3_decision.skip_phase4:
        if _phase3_missing_data:
            logger.warning(
                "Phase 3 says skip but it also reported missing Phase 2 data. "
                "This is a pipeline failure, not a clean skip."
            )
        findings.setdefault(4, "No exploitable vulnerabilities found. Phase 4 skipped.")
        findings.setdefault(5, "No foothold obtained. Phase 5 skipped.")
        state.findings = findings
        state.completion_status = True
        _save_state(state)
        return await _run_report(llm, target, findings)

    # ── Phase 4: Exploitation (with subagents + feedback loop) ─────
    p4_decision = None
    for loop_i in range(state.feedback_loop_count, _MAX_FEEDBACK_LOOPS + 1):
        if 4 not in findings or loop_i > 0:
            state.current_phase = 4
            _save_state(state)
            findings[4] = await _run_phase(
                phase4_exploit, llm, target, findings
            )
            state.findings = findings
            _save_state(state)

        # Extract Phase 4 decision
        logger.info("Extracting Phase 4 decision...")
        p4_decision = await extract_decision(llm, findings[4], Phase4Decision)
        logger.info(
            "Phase 4 decision: foothold=%s, access=%s, reenum=%s (loop %d/%d)",
            p4_decision.foothold_obtained,
            p4_decision.access_level,
            p4_decision.needs_reenumeration,
            loop_i,
            _MAX_FEEDBACK_LOOPS,
        )

        if not p4_decision.needs_reenumeration or loop_i == _MAX_FEEDBACK_LOOPS:
            break

        # ── Feedback loop: targeted re-enumeration ─────────────────
        logger.info(
            "Feedback loop %d: re-enumerating with context: %s",
            loop_i + 1, p4_decision.reenumeration_context,
        )
        findings[2] = await _run_targeted_reenum(
            llm, target, findings, p4_decision.reenumeration_context
        )
        state.findings = findings

        # Re-run Phase 3 with updated findings
        del findings[3]
        findings[3] = await _run_phase(phase3_vulns, llm, target, findings)
        state.findings = findings

        # Clear Phase 4 so it re-runs with new vulns
        del findings[4]

        state.feedback_loop_count = loop_i + 1
        _save_state(state)

    # ── Phase 5: Post-Exploitation ─────────────────────────────────
    if p4_decision and p4_decision.skip_phase5:
        logger.info("No foothold — skipping Phase 5")
        findings[5] = "No foothold obtained in Phase 4. Phase 5 skipped."
    elif 5 not in findings:
        state.current_phase = 5
        _save_state(state)
        findings[5] = await _run_phase(
            phase5_postexploit, llm, target, findings
        )
        state.findings = findings
        _save_state(state)

    # ── Phase 6: Reporting ─────────────────────────────────────────
    state.current_phase = 6
    state.completion_status = True
    _save_state(state)

    report = await _run_report(llm, target, findings)
    state.findings = findings
    _save_state(state)
    return report
