"""Task Interpreter: turns a natural-language request into a structured TaskSpec (rule-based)."""
from __future__ import annotations

import re

from app.models import TaskSpec

SECURITY_TERMS = {"alert", "alerts", "vulnerability", "vulnerabilities", "vulnerable", "dependency", "dependencies",
                  "cve", "security", "package", "remediation", "advisory", "finding", "findings", "library", "used", "usage",
                  "affected", "dependent"}
SEVERITIES = ("critical", "high", "medium", "low")
PATCH_RE = re.compile(r"\b(patch|apply (a |the )?(fix|patch|upgrade)|upgrade the|bump|update the dependency|rewrite|modify the code)\b")


def interpret(request: str) -> TaskSpec:
    text = request.lower()
    tokens = re.findall(r"[a-z0-9][a-z0-9_.\-]*", text)
    token_set = set(tokens)
    alert_ids = [a.upper() for a in re.findall(r"alert-\d+", text)]
    severity = next((s for s in SEVERITIES if s in token_set), None)
    in_scope = bool(token_set & SECURITY_TERMS or alert_ids)
    wants_case = bool(re.search(r"\b(case|ticket|remediation case|track|record)\b", text))
    wants_patch = bool(PATCH_RE.search(text))
    sensitive = ["apply_source_patch"] if wants_patch else []
    required = ["security alert record", "dependency manifest inspection", "package reference search"]
    if wants_case:
        required += ["evidence attached to the case", "independent read-back of the created case"]
    target = f"{severity} " if severity else ""
    if in_scope:
        objective = (f"Investigate the {target}security alert, determine whether the affected package is really used"
                     + (", record a remediation case with evidence and verify it" if wants_case else ""))
        intent = "investigate_and_record" if wants_case else "investigate"
        expected_outcome = "Verified remediation case with evidence" if wants_case else "Evidence-based finding on package usage"
    else:
        # Preserve the user's request verbatim; never rewrite an unrelated task into a security task.
        objective = request.strip()
        intent = "out_of_scope"
        expected_outcome = "Clarification identifying the unsupported request"
    return TaskSpec(
        objective=objective,
        intent=intent,
        in_scope=in_scope, alert_ids=alert_ids, severity=severity, keywords=tokens,
        wants_case=wants_case, wants_patch=wants_patch, sensitive_actions=sensitive,
        required_evidence=required,
        expected_outcome=expected_outcome,
    )
