"""Reporting layer: plain-text execution report built from persisted state and events."""
from __future__ import annotations


def render_report(state: dict, events: list[dict]) -> str:
    out = []
    w = out.append
    w("=" * 72)
    w(f"SENTINEL execution report  {state['task_id']}   planner: {state['planner']}")
    w("=" * 72)
    w(f"Request : {state['request']}")
    w(f"Status  : {state['status']}   ({state['final_reason']})")
    w(f"Result  : {state['final_message']}")
    a = state.get("selected_alert")
    if a:
        w(f"Alert   : {a['id']} {a['severity']} {a['package']} - {a['title']}")
    w(f"Verdict : {state.get('verdict') or 'n/a'}   {state.get('version_note', '')}")
    if state.get("created_case_id") or state.get("target_case_id"):
        cid = state.get("target_case_id")
        w(f"Case    : {cid} ({'existing case reused' if state['case_reused'] else 'created by this task'})")
    v = state.get("verification")
    if v:
        w("Verification (independent read-back):")
        for c in v["checks"]:
            w(f"   [{'ok' if c['ok'] else 'FAIL'}] {c['name']}")
    w(f"Files inspected: " + ", ".join(f"{f['path']} ({'ok' if f['ok'] else f['error']})" for f in state["files_inspected"]) or "none")
    w(f"Evidence ({len(state['evidence'])}):")
    for e in state["evidence"]:
        w(f"   {e['kind']:<13} {e['file']}:{e['line']}  {e['snippet'][:70]}")
    srcs = [a.get("source", "policy") for a in state["completed_actions"]]
    w(f"Planner: {state['planner']}   successful actions chosen by: LLM={srcs.count('llm')}, rule-based={srcs.count('policy')}")
    w(f"Actions: {len(state['completed_actions'])} succeeded, {len(state['failed_actions'])} failed, "
      f"{state['retry_count']} recovery attempt(s), {state['iteration']} loop iteration(s)")
    w("Timeline:")
    for e in events:
        w(f"   {e['ts'][11:23]}  {e['type']:<22} {e['message'][:100]}")
    for lim in state.get("limitations", []):
        w(f"Note: {lim}")
    return "\n".join(out)
