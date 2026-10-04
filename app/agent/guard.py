"""Safety boundary. Applied to EVERY proposed action, regardless of which planner proposed it."""
from __future__ import annotations

from dataclasses import dataclass

from app.models import Action, TaskState, Verdict
from app.tools.registry import ToolRegistry


@dataclass
class GuardDecision:
    kind: str  # ok | block | needs_approval
    message: str = ""


def check(state: TaskState, action: Action, registry: ToolRegistry) -> GuardDecision:
    tool = registry.get(action.tool)
    if tool is None:
        return GuardDecision("block", f"Unknown tool {action.tool!r}.")
    if tool.requires_approval and action.tool not in state.approved_actions:
        return GuardDecision("needs_approval", f"{action.tool} changes the project and needs explicit human approval.")
    if action.tool == "create_remediation_case":
        a, alert = action.arguments, state.selected_alert
        if state.verdict != Verdict.CONFIRMED.value:
            return GuardDecision("block", "A case may only be created once the dependency is confirmed in a manifest.")
        if not state.duplicate_checked:
            return GuardDecision("block", "Duplicate check (list_remediation_cases) has not been performed.")
        if state.existing_case_id or state.target_case_id:
            return GuardDecision("block", "A case already exists for this alert; creating another is not allowed.")
        if alert is None or a.get("alert_id") != alert["id"] or a.get("package") != alert["package"]:
            return GuardDecision("block", "Case arguments do not match the selected alert.")
        invented = [e for e in a.get("evidence", []) if e not in state.evidence]
        if invented:
            return GuardDecision("block", f"{len(invented)} evidence item(s) were not observed by any tool.")
    return GuardDecision("ok")
