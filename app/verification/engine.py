"""Verification Engine: independently compares the stored case with what the agent intended to record."""
from __future__ import annotations

from app.models import evidence_digest


def verify_case(fetched: dict, expected: dict, strict_evidence: bool = True) -> dict:
    """fetched = case returned by get_remediation_case; expected = values derived from the agent's own state."""
    checks = []

    def check(name, exp, act, ok):
        checks.append({"name": name, "expected": exp, "actual": act, "ok": bool(ok)})

    check("case_id", expected["case_id"], fetched.get("case_id"), fetched.get("case_id") == expected["case_id"])
    check("alert_id", expected["alert_id"], fetched.get("alert_id"), fetched.get("alert_id") == expected["alert_id"])
    check("package", expected["package"], fetched.get("package"), fetched.get("package") == expected["package"])
    check("severity", expected["severity"], fetched.get("severity"), fetched.get("severity") == expected["severity"])
    check("status", "OPEN", fetched.get("status"), fetched.get("status") == "OPEN")
    stored = fetched.get("evidence") or []
    check("evidence_present", "at least 1 item", f"{len(stored)} item(s)", len(stored) > 0)
    if strict_evidence:
        missing = [e for e in expected["evidence"] if e not in stored]
        check("evidence_items", f"{len(expected['evidence'])} item(s) match", f"{len(missing)} missing", not missing)
        digest = evidence_digest(stored) if stored else "(none)"
        check("evidence_digest", evidence_digest(expected["evidence"]), digest, digest == evidence_digest(expected["evidence"]))
    stored_digest = fetched.get("evidence_digest")
    actual_digest = evidence_digest(stored) if stored else "(none)"
    check("stored_digest_consistent", stored_digest, actual_digest, stored_digest == actual_digest)
    failed = [c["name"] for c in checks if not c["ok"]]
    return {"passed": not failed, "failed_checks": failed, "checks": checks, "strict_evidence": strict_evidence}
