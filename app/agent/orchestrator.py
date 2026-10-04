"""Agent Orchestrator: OBSERVE -> REASON -> SELECT TOOL -> EXECUTE -> OBSERVE -> UPDATE STATE."""
from __future__ import annotations

import re
import time

from app.agent import guard
from app.agent.interpreter import interpret
from app.agent.planner import PolicyPlanner
from app.agent.reasoning import assess_evidence, compute_final_status, select_alert, terminal_reason, version_in_range
from app.config import Config
from app.llm.base import ProviderFatalError
from app.models import Action, TaskState, TaskStatus, ToolResult, normalize_name, now_iso
from app.storage.db import Database
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry
from app.verification.engine import verify_case

FILE_ERRORS = {"FILE_NOT_FOUND", "PATH_DENIED", "FILE_TYPE_DENIED", "FILE_TOO_LARGE", "NOT_A_FILE"}

FINAL_MESSAGES = {
    "verified": "Remediation case created and independently verified.",
    "investigation_complete": "Investigation finished (read-only task, no case requested).",
    "no_case_warranted": "Investigation finished, but the evidence does not justify a remediation case. No case was created.",
    "outside_affected_range": "The package is declared, but its pinned version is outside the alert's affected range. No case was created.",
    "verification_failed": "A case was recorded but its stored content does not match what was intended. It is NOT verified.",
    "exhausted": "A tool kept failing and the retry limit was reached. The objective was not completed.",
    "max_iterations": "The iteration limit was reached before the objective was verified.",
    "awaiting": "Human input is required before this task can continue.",
}


class Orchestrator:
    def __init__(self, config: Config, registry: ToolRegistry, executor: ToolExecutor, planner, db: Database, on_update=None):
        self.cfg, self.registry, self.executor, self.planner, self.db = config, registry, executor, planner, db
        self.fallback = PolicyPlanner()
        self.on_update = on_update

    # ---- public ------------------------------------------------------
    def run(self, request: str) -> TaskState:
        state = TaskState.new(request, planner=self.planner.name)
        self._emit(state, "task_received", f"Task received: {request}")
        spec = interpret(request)
        state.spec, state.objective = spec.__dict__.copy(), spec.objective
        self._emit(state, "objective_interpreted", spec.objective,
                   {"intent": spec.intent, "severity": spec.severity, "alert_ids": spec.alert_ids,
                    "required_evidence": spec.required_evidence, "sensitive_actions": spec.sensitive_actions,
                    "expected_outcome": spec.expected_outcome})
        if spec.in_scope:
            state.plan = ["Identify the relevant security alert", "Inspect the dependency manifest", "Search for package references",
                          "Assess whether the evidence is sufficient"]
            if spec.wants_case:
                state.plan += ["Check for an existing case", "Create the remediation case", "Read the case back and verify it"]
        if not spec.in_scope:
            request_lower = request.lower()
            if any(term in request_lower for term in ("invoice", "payment", "due date", "billing")):
                detail = "Invoice processing (finding an invoice, extracting its amount or due date, and entering it into an internal system) is not currently supported."
            else:
                detail = f"Your request is outside SENTINEL's supported domain: security alerts, dependency investigation, and remediation cases. Original request: {request.strip()}"
            self._await(state, "clarification", detail + " No tools were run and no records were created. Please provide a supported security-operations task.")
        elif spec.sensitive_actions:
            self._emit(state, "approval_required", "The request includes a sensitive action (source patch). It will not run "
                       "without explicit approval.", {"sensitive_actions": spec.sensitive_actions})
            state.pending_approval = {"action": "apply_source_patch", "reason": "Changes project code"}
        self._persist(state)
        self._loop(state)
        return state

    # ---- loop --------------------------------------------------------
    def _loop(self, state: TaskState) -> None:
        reason = None
        for _ in range(self.cfg.max_iterations):
            state.iteration += 1
            self._reason(state)
            reason = terminal_reason(state, self.cfg.max_retries)
            if reason:
                break
            action = self._plan(state)
            if action is None:
                reason = "exhausted"
                if not state.provider_error:
                    state.exhausted.append("planner")
                    self._emit(state, "planner_stalled", "The planner could not choose a further action.")
                break
            self._act(state, action)
            self._persist(state)
        else:
            self._reason(state)
            reason = terminal_reason(state, self.cfg.max_retries) or "max_iterations"
        self._finalize(state, reason)

    def _reason(self, state: TaskState) -> None:
        if state.alerts_listed and not state.selection_done and not state.awaiting:
            state.selection_done = True
            alert, cands, why = select_alert(state.alerts, state.spec)
            if alert:
                state.selected_alert = alert
                self._emit(state, "alert_selected", f"Selected {alert['id']} ({alert['severity']}, {alert['package']}). {why}",
                           {"alert": alert})
            else:
                listing = "; ".join(f"{a['id']} {a['severity']} {a['package']}" for a in (cands or state.alerts)) or "none"
                self._await(state, "clarification", f"{why} Please name the alert or package. Candidates: {listing}.")
        if state.selected_alert and state.searches and not state.search_done:
            verdict, done, why = assess_evidence(state)
            self._emit(state, "evidence_assessed", why, {"verdict": verdict, "final": done,
                                                         "evidence_items": len(state.evidence)})
            if done:
                state.verdict, state.search_done = verdict, True
                if verdict == "INSUFFICIENT":
                    self._await(state, "clarification", why + " Please confirm which dependency file should declare it.")
            else:
                state.plan.append("Recovery: broaden the search to documentation")

    REPEATABLE = {"get_remediation_case", "list_remediation_cases"}

    def _plan(self, state: TaskState) -> Action | None:
        try:
            action = self.planner.next_action(state, self.registry)
        except ProviderFatalError as exc:  # invalid key / bad model: stop, never pretend or silently switch planners
            state.provider_error = str(exc)
            state.exhausted.append("llm_provider")
            self._emit(state, "provider_error", str(exc))
            return None
        except Exception as exc:  # temporary provider/network failure: fall back for this step, and say so
            self._emit(state, "planner_fallback", f"{self.planner.name} planner failed ({type(exc).__name__}: {exc}); "
                       "using the rule-based policy for this step.")
            return self.fallback.next_action(state, self.registry)
        if action is not None and action.source == "llm":
            problems = self.executor.validate_args(action.tool, action.arguments)
            decision = guard.check(state, action, self.registry) if not problems else None
            repeat = (not problems and action.tool not in self.REPEATABLE and
                      any(a["tool"] == action.tool and a.get("args") == self._brief_args(action.arguments)
                          for a in state.completed_actions))
            if problems or repeat or (decision and decision.kind == "block"):
                why = "; ".join(problems) or ("it repeats an action that already succeeded" if repeat else decision.message)
                self._emit(state, "planner_fallback", f"LLM proposal '{action.tool}' rejected: {why}. "
                           "Using the rule-based policy for this step.", {"proposal": action.tool})
                return self.fallback.next_action(state, self.registry)
        return action

    def _act(self, state: TaskState, action: Action) -> None:
        decision = guard.check(state, action, self.registry)
        if decision.kind == "needs_approval":
            state.pending_approval = {"action": action.tool, "arguments": action.arguments}
            self._await(state, "approval", decision.message)
            return
        if decision.kind == "block":
            state.guard_blocks += 1
            state.failed_actions.append({"iteration": state.iteration, "tool": action.tool, "error_code": "GUARD_BLOCKED",
                                         "error": decision.message})
            self._emit(state, "guard_blocked", f"Blocked {action.tool}: {decision.message}")
            if state.guard_blocks >= 3:
                state.exhausted.append("guard")
            return
        state.current_action = action.tool
        self._emit(state, "tool_selected", f"{action.tool}: {action.rationale}",
                   {"tool": action.tool, "arguments": self._brief_args(action.arguments), "source": action.source})
        result = self.executor.execute(action.tool, action.arguments)
        self._emit(state, "tool_executed", f"{action.tool} {'succeeded' if result.ok else 'failed'} in {result.duration_ms} ms",
                   {"tool": action.tool, "ok": result.ok, "error_code": result.error_code})
        self._observe(state, action, result)

    # ---- observation -------------------------------------------------
    def _observe(self, state: TaskState, action: Action, r: ToolResult) -> None:
        if not r.ok:
            return self._observe_failure(state, action, r)
        state.retries[r.tool] = 0
        d, summary = r.data, ""
        if r.tool == "list_security_alerts":
            state.alerts, state.alerts_listed = d["alerts"], True
            summary = f"{d['count']} alert(s) retrieved"
        elif r.tool == "inspect_project_file":
            state.files_inspected.append({"path": d["path"], "ok": True, "total_lines": d["total_lines"]})
            state.manifest_inspected = True
            norm = normalize_name(state.selected_alert["package"])
            hits = []
            for ln in d["lines"]:
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)", ln["text"])
                if m and normalize_name(m.group(1)) == norm:
                    hits.append({"file": d["path"], "line": ln["n"], "kind": "manifest", "snippet": ln["text"].strip()[:200]})
            self._add_evidence(state, hits)
            summary = f"read {d['path']} ({d['total_lines']} lines); {len(hits)} manifest reference(s)"
        elif r.tool == "search_dependency":
            state.searches.append({"include_docs": d["include_docs"], "counts": d["counts"], "files_scanned": d["files_scanned"]})
            self._add_evidence(state, [{k: m[k] for k in ("file", "line", "kind", "snippet")} for m in d["matches"]])
            for m in d["matches"]:
                if m["kind"] == "manifest":
                    self._assess_version(state, m.get("version_spec", ""))
                    break
            summary = f"{sum(d['counts'].values())} reference(s) {d['counts']}"
        elif r.tool == "list_remediation_cases":
            state.duplicate_checked = True
            if d["count"]:
                state.existing_case_id = state.target_case_id = d["cases"][0]["case_id"]
                state.case_reused = True
                self._emit(state, "recovery", f"Case {state.existing_case_id} already exists for this alert; reusing it instead "
                           "of creating a duplicate. It will still be independently verified.")
                state.plan.append("Recovery: reuse the existing case (duplicate prevented)")
            summary = f"{d['count']} existing case(s) for the alert"
        elif r.tool == "create_remediation_case":
            state.created_case_id = state.target_case_id = d["case_id"]
            state.verification = None
            self._emit(state, "case_created", f"Case {d['case_id']} created (tool reported success; not yet verified).",
                       {"case_id": d["case_id"]})
            summary = f"created {d['case_id']}"
        elif r.tool == "get_remediation_case":
            self._verify(state, d["case"])
            summary = f"read back {d['case']['case_id']}; verification {'passed' if state.verification['passed'] else 'FAILED'}"
        state.completed_actions.append({"iteration": state.iteration, "tool": r.tool, "summary": summary, "source": action.source,
                                        "args": self._brief_args(action.arguments)})
        state.observations.append({"iteration": state.iteration, "tool": r.tool, "ok": True, "summary": summary})
        self._emit(state, "observation", f"{r.tool}: {summary}")

    def _observe_failure(self, state: TaskState, action: Action, r: ToolResult) -> None:
        state.failed_actions.append({"iteration": state.iteration, "tool": r.tool, "error_code": r.error_code,
                                     "error": r.error, "retryable": r.retryable})
        state.observations.append({"iteration": state.iteration, "tool": r.tool, "ok": False, "summary": f"{r.error_code}: {r.error}"})
        self._emit(state, "observation", f"{r.tool} failed: {r.error_code} - {r.error}")
        if r.tool == "create_remediation_case" and r.error_code == "DUPLICATE_CASE":
            state.existing_case_id = state.target_case_id = r.details["existing_case_id"]
            state.case_reused, state.duplicate_checked = True, True
            self._emit(state, "recovery", f"Tracker rejected a duplicate; reusing existing case {state.existing_case_id}.")
        elif r.tool == "inspect_project_file" and r.error_code in FILE_ERRORS:
            state.files_inspected.append({"path": action.arguments.get("path"), "ok": False, "error": r.error_code})
            self._emit(state, "recovery", f"File unavailable ({r.error_code}); switching to an alternative source.")
            state.plan.append(f"Recovery: {action.arguments.get('path')} unavailable, try another manifest")
        elif r.retryable:
            state.retries[r.tool] = state.retries.get(r.tool, 0) + 1
            state.retry_count += 1
            if r.tool == "create_remediation_case":
                state.duplicate_checked = False  # the write may have landed: re-check before trying again
            if state.retries[r.tool] > self.cfg.max_retries:
                state.exhausted.append(r.tool)
                self._emit(state, "recovery", f"{r.tool} failed {state.retries[r.tool]} times; retry limit reached, giving up.")
            else:
                self._emit(state, "recovery", f"Temporary failure in {r.tool}; retry {state.retries[r.tool]}/{self.cfg.max_retries}"
                           + (" after re-checking for duplicates." if r.tool == "create_remediation_case" else "."))
                state.plan.append(f"Recovery: retry {r.tool} ({state.retries[r.tool]}/{self.cfg.max_retries})")
                time.sleep(self.cfg.retry_delay * state.retries[r.tool])
        else:
            state.exhausted.append(r.tool)

    # ---- helpers -----------------------------------------------------
    def _add_evidence(self, state: TaskState, items: list[dict]) -> None:
        seen = {(e["file"], e["line"], e["kind"]) for e in state.evidence}
        for it in items:
            key = (it["file"], it["line"], it["kind"])
            if key not in seen:
                seen.add(key)
                state.evidence.append({"file": it["file"], "line": it["line"], "kind": it["kind"], "snippet": it["snippet"]})

    def _assess_version(self, state: TaskState, spec: str) -> None:
        affected = state.selected_alert.get("affected_versions", "")
        inside = version_in_range(spec, affected) if affected else None
        state.affected_status = inside
        if inside is None:
            state.version_note = f"Declared constraint '{spec or 'unpinned'}' cannot be compared exactly with affected range {affected}."
        else:
            state.version_note = (f"Declared version {spec.lstrip('=')} is {'inside' if inside else 'outside'} the affected range {affected}.")

    def _verify(self, state: TaskState, fetched: dict) -> None:
        a = state.selected_alert
        expected = {"case_id": state.target_case_id, "alert_id": a["id"], "package": a["package"],
                    "severity": a["severity"], "evidence": state.evidence}
        state.fetched_case = {k: fetched[k] for k in ("case_id", "alert_id", "status", "title")}
        state.verification = verify_case(fetched, expected, strict_evidence=not state.case_reused)
        state.verify_attempts += 1
        v = state.verification
        self._emit(state, "verification_performed",
                   "Independent read-back verification " + ("PASSED" if v["passed"] else f"FAILED ({', '.join(v['failed_checks'])})"),
                   {"passed": v["passed"], "failed_checks": v["failed_checks"], "attempt": state.verify_attempts})
        if not v["passed"] and state.verify_attempts < 1 + self.cfg.max_retries:
            state.retry_count += 1
            self._emit(state, "recovery", f"Verification mismatch; re-reading the case (attempt {state.verify_attempts + 1}/"
                       f"{1 + self.cfg.max_retries}).")
            state.plan.append("Recovery: re-read the case after verification mismatch")

    @staticmethod
    def _brief_args(args: dict) -> dict:
        out = dict(args)
        if "evidence" in out:
            out["evidence"] = f"[{len(out['evidence'])} item(s)]"
        return out

    def _await(self, state: TaskState, kind: str, message: str) -> None:
        state.awaiting, state.awaiting_message = kind, message
        self._emit(state, "approval_required" if kind == "approval" else "clarification_required", message)

    def _finalize(self, state: TaskState, reason: str) -> None:
        if reason == "verified" and state.spec["sensitive_actions"]:
            self._await(state, "approval", "The case is verified. Applying a source patch or dependency upgrade requires explicit "
                        "human approval and was NOT performed.")
        state.final_reason = reason
        state.status = compute_final_status(state, reason).value
        msg = FINAL_MESSAGES.get(reason, reason)
        if state.provider_error:
            msg = f"LLM provider error: {state.provider_error} No rule-based fallback was used; unset LLM_PROVIDER to run in rule-based mode."
        elif state.awaiting:
            msg = state.awaiting_message
        elif state.verdict and reason == "no_case_warranted":
            msg += f" Verdict: {state.verdict}."
        state.final_message = msg
        state.limitations = ["Static inspection only: exploitability and reachability were not assessed."]
        recovered = {a["tool"] for a in state.completed_actions}
        state.limitations += [f"{f['tool']}: {f['error_code']} (not recovered)" for f in state.failed_actions[-3:]
                              if f["error_code"] not in ("FILE_NOT_FOUND",) and f["tool"] not in recovered]
        state.current_action = ""
        state.finished_at = now_iso()
        self._emit(state, "task_finished", f"{state.status}: {msg}", {"status": state.status, "reason": reason})
        self._persist(state)

    def _emit(self, state: TaskState, etype: str, message: str, data: dict | None = None) -> None:
        self.db.add_event(state.task_id, etype, message, data)
        if self.on_update:
            self.on_update(state)

    def _persist(self, state: TaskState) -> None:
        self.db.save_run(state.to_dict())
        if self.on_update:
            self.on_update(state)
