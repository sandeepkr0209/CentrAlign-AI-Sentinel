"""Planners choose the next tool call from the current state. Execution is done elsewhere."""
from __future__ import annotations

import json

from app.models import Action, TaskState, Verdict
from app.tools.registry import ToolRegistry

DEFAULT_MANIFESTS = ["requirements.txt", "pyproject.toml", "Pipfile", "package.json"]


def build_case_arguments(state: TaskState) -> dict:
    alert = state.selected_alert
    n_src = sum(1 for e in state.evidence if e["kind"] in ("source_import", "source_usage"))
    files = sorted({e["file"] for e in state.evidence if e["kind"] in ("source_import", "source_usage")})
    manifest = next(e for e in state.evidence if e["kind"] == "manifest")
    summary = (f"{alert['package']} is declared in {manifest['file']} (line {manifest['line']}: {manifest['snippet']}). "
               f"{alert['title']} ({alert.get('cve', 'no CVE')}); affected {alert.get('affected_versions', '?')}, "
               f"fixed in {alert.get('fixed_version', '?')}. {state.version_note} "
               f"{n_src} source reference(s) in {len(files)} file(s){': ' + ', '.join(files) if files else ''}. "
               "Static inspection only: exploitability and reachability were not assessed.")
    return {"alert_id": alert["id"], "package": alert["package"], "severity": alert["severity"],
            "title": f"Upgrade {alert['package']} to {alert.get('fixed_version', 'a fixed version')} ({alert['severity']} alert {alert['id']})",
            "summary": summary.strip(), "evidence": list(state.evidence), "task_id": state.task_id}


class PolicyPlanner:
    """Deterministic, state-driven policy. Chooses actions from observed state, not from a fixed script."""
    name = "rule-based"

    def next_action(self, state: TaskState, registry: ToolRegistry) -> Action | None:
        s = state
        if not s.alerts_listed:
            return Action("list_security_alerts", {}, "I need the available alerts to find the one the task refers to.")
        alert = s.selected_alert
        if not s.manifest_inspected:
            attempted = {f["path"] for f in s.files_inspected}
            candidates = [alert.get("manifest_path")] + DEFAULT_MANIFESTS
            nxt = next((c for c in candidates if c and c not in attempted), None)
            if nxt:
                why = ("The alert reports this manifest, so I will read it first." if not attempted else
                       "The previous manifest was unavailable; trying the next likely manifest.")
                return Action("inspect_project_file", {"path": nxt}, why)
            s.manifest_inspected = True
        if not s.searches:
            return Action("search_dependency", {"package": alert["package"]},
                          "Search manifests and source files for references to the affected package.")
        if not s.search_done:
            return Action("search_dependency", {"package": alert["package"], "include_docs": True},
                          "The first search found nothing; broadening to documentation to classify the mention.")
        if s.verdict == Verdict.CONFIRMED.value:
            if s.target_case_id and not (s.verification and s.verification["passed"]):
                return Action("get_remediation_case", {"case_id": s.target_case_id},
                              "Independently read the case back so it can be verified against my intended values.")
            if not s.duplicate_checked:
                return Action("list_remediation_cases", {"alert_id": alert["id"]},
                              "Check for an existing case before writing, to avoid a duplicate record.")
            return Action("create_remediation_case", build_case_arguments(s),
                          "Dependency is confirmed and no case exists; recording a remediation case with the collected evidence.")
        return None


SYSTEM_PROMPT = (
    "You are SENTINEL, a security-operations worker. Choose exactly ONE next tool call that advances the task, "
    "based on the state JSON. Rules: never invent evidence (copy evidence items verbatim from state.evidence); "
    "do not repeat a tool call that already succeeded; check for duplicate cases before creating one; after creating "
    "a case, read it back with get_remediation_case; read-only static inspection only; never attempt code changes.")


class LLMPlanner:
    """Asks any LLMProvider to choose the next tool call. Guard and schema validation still apply downstream."""

    def __init__(self, provider):
        self.provider = provider
        self.name = f"llm:{provider.id}/{provider.model}"

    def next_action(self, state: TaskState, registry: ToolRegistry) -> Action | None:
        view = {k: getattr(state, k) for k in ("request", "spec", "selected_alert", "files_inspected", "verdict",
                                               "search_done", "duplicate_checked", "existing_case_id", "target_case_id",
                                               "verification", "evidence", "alerts_listed")}
        view["searches"] = [{"include_docs": x["include_docs"], "counts": x["counts"]} for x in state.searches]
        view["completed"] = [{"tool": a["tool"], "args": a.get("args")} for a in state.completed_actions]
        view["recent_failures"] = state.failed_actions[-3:]
        proposal = self.provider.complete_tool_call(SYSTEM_PROMPT, "Current state:\n" + json.dumps(view, default=str),
                                                    registry.tool_specs())
        return Action(proposal.name, proposal.arguments, proposal.text or f"Selected by {self.provider.label}.", source="llm")
