"""Pure-code reasoning helpers: alert selection, evidence assessment, termination, final status."""
from __future__ import annotations

import re
from collections import Counter

from app.models import TaskState, TaskStatus, Verdict, normalize_name


def select_alert(alerts: list[dict], spec: dict) -> tuple[dict | None, list[dict], str]:
    cands = [a for a in alerts if a.get("status", "open") == "open"]
    if spec["alert_ids"]:
        cands = [a for a in cands if a["id"] in spec["alert_ids"]]
    else:
        toks = {normalize_name(t) for t in spec["keywords"]}
        by_pkg = [a for a in cands if normalize_name(a["package"]) in toks]
        if by_pkg:
            cands = by_pkg
    if spec["severity"]:
        cands = [a for a in cands if a["severity"] == spec["severity"]]
    if len(cands) == 1:
        return cands[0], cands, "Exactly one open alert matches the request."
    if not cands:
        return None, [], "No open alert matches the request."
    return None, cands, f"{len(cands)} alerts match the request."


def _vkey(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def version_in_range(declared_spec: str, affected: str) -> bool | None:
    """True/False if an exact pinned version can be compared with the affected range, else None."""
    m = re.fullmatch(r"==\s*([\d.]+)", declared_spec.strip())
    if not m:
        return None
    declared = _vkey(m.group(1))
    for clause in affected.split(","):
        c = re.fullmatch(r"\s*(<=|>=|<|>|==)\s*([\d.]+)\s*", clause)
        if not c:
            return None
        op, ver = c.group(1), _vkey(c.group(2))
        if not {"<": declared < ver, "<=": declared <= ver, ">": declared > ver, ">=": declared >= ver, "==": declared == ver}[op]:
            return False
    return True


def assess_evidence(state: TaskState) -> tuple[str | None, bool, str]:
    """Return (verdict, search_done, explanation). Verdict is derived only from collected evidence."""
    if not state.searches:
        return None, False, "No dependency search has been executed yet."
    kinds = Counter(e["kind"] for e in state.evidence)
    manifest, source, docs = kinds["manifest"], kinds["source_import"] + kinds["source_usage"], kinds["doc"]
    broadened = any(s["include_docs"] for s in state.searches)
    if manifest:
        return Verdict.CONFIRMED.value, True, f"Declared in a dependency manifest ({manifest} entry); {source} source reference(s)."
    if source:
        return Verdict.INSUFFICIENT.value, True, ("Referenced in source code but not declared in any manifest; it may be a transitive or "
                                                  "vendored dependency, so declared presence cannot be confirmed.")
    if not broadened:
        return None, False, "No manifest or source references; broadening the search to documentation."
    if docs:
        return Verdict.DOC_ONLY.value, True, f"Only mentioned in documentation ({docs} reference(s)); no manifest or code uses it."
    return Verdict.NOT_FOUND.value, True, "No reference to the package anywhere in the repository."


def terminal_reason(state: TaskState, max_retries: int) -> str | None:
    if state.awaiting:
        return "awaiting"
    if state.exhausted:
        return "exhausted"
    if not state.alerts_listed or state.selected_alert is None or not state.search_done:
        return None
    if not state.spec["wants_case"]:
        return "investigation_complete"
    if state.verdict != Verdict.CONFIRMED.value:
        return "no_case_warranted"
    if state.affected_status is False:
        return "outside_affected_range"
    v = state.verification
    if v and v["passed"]:
        return "verified"
    if v and not v["passed"] and state.verify_attempts >= 1 + max_retries:
        return "verification_failed"
    return None


def compute_final_status(state: TaskState, reason: str) -> TaskStatus:
    if state.awaiting:
        return TaskStatus.NEEDS_APPROVAL
    if reason == "verified":
        return TaskStatus.COMPLETED
    if reason == "investigation_complete":
        return TaskStatus.COMPLETED if state.verdict else TaskStatus.FAILED
    if state.verdict or state.created_case_id:
        return TaskStatus.PARTIALLY_COMPLETED
    return TaskStatus.FAILED
