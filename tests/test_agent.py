import unittest

from app.agent import guard
from app.agent.reasoning import compute_final_status
from app.environment.faults import FaultInjector
from app.models import Action, TaskState
from app.tools.registry import Tool
from tests.helpers import AgentTestCase, TASK


class AgentTests(AgentTestCase):
    def test_06_verification_and_end_to_end(self):
        agent, st = self.run_task()
        self.assertEqual(st.status, "COMPLETED")
        self.assertTrue(st.verification["passed"])
        case = self.db.get_case(st.created_case_id)  # real record, read directly from SQLite
        self.assertEqual((case["alert_id"], case["package"], case["status"]), ("ALERT-001", "PyYAML", "OPEN"))
        self.assertTrue(any(e["kind"] == "manifest" for e in case["evidence"]))
        self.assertEqual(case["evidence"], st.evidence)
        self.assertEqual(self.db.load_run(st.task_id)["status"], "COMPLETED")
        types = [e["type"] for e in self.db.events(st.task_id)]
        self.assertLess(types.index("case_created"), types.index("verification_performed"))

    def test_missing_manifest_triggers_alternative_not_failure(self):
        _, st = self.run_task()
        self.assertEqual([f["ok"] for f in st.files_inspected], [False, True])
        self.assertEqual(st.files_inspected[0]["path"], "pyproject.toml")

    def test_search_without_result_broadens_then_reports_limit(self):
        _, st = self.run_task("Investigate the high severity Jinja2 alert and create a remediation case with evidence.")
        self.assertEqual(len(st.searches), 2)
        self.assertTrue(st.searches[1]["include_docs"])
        self.assertEqual((st.verdict, st.status), ("DOC_ONLY", "PARTIALLY_COMPLETED"))
        self.assertEqual(self.db.list_cases(), [])

    def test_not_found_never_reports_success(self):
        _, st = self.run_task("Check the Pillow alert and create a remediation case.")
        self.assertEqual((st.verdict, st.status), ("NOT_FOUND", "PARTIALLY_COMPLETED"))
        self.assertIsNone(st.created_case_id)

    def test_10_bounded_retry_recovers_within_limit(self):
        _, st = self.run_task(faults=FaultInjector(transient={"create_remediation_case": 2}))
        self.assertEqual(st.status, "COMPLETED")
        self.assertEqual(st.retry_count, 2)
        self.assertEqual(len(self.db.list_cases()), 1)
        self.assertEqual(st.limitations, ["Static inspection only: exploitability and reachability were not assessed."])

    def test_10b_bounded_retry_gives_up(self):
        _, st = self.run_task(faults=FaultInjector(transient={"create_remediation_case": 99}))
        self.assertEqual(st.status, "PARTIALLY_COMPLETED")
        self.assertIn("create_remediation_case", st.exhausted)
        self.assertEqual(st.retry_count, self.cfg.max_retries + 1)
        self.assertEqual(self.db.list_cases(), [])
        self.assertIsNone(st.verification)

    def test_write_then_fail_does_not_create_duplicate(self):
        _, st = self.run_task(faults=FaultInjector(write_then_fail=1))
        self.assertEqual(st.status, "COMPLETED")
        self.assertEqual(len(self.db.list_cases()), 1)
        self.assertTrue(st.case_reused)

    def test_existing_case_is_reused_on_second_run(self):
        _, first = self.run_task()
        _, second = self.run_task()
        self.assertEqual(second.status, "COMPLETED")
        self.assertEqual(second.target_case_id, first.created_case_id)
        self.assertIsNone(second.created_case_id)
        self.assertEqual(len(self.db.list_cases()), 1)

    def test_11_incorrect_verification_result(self):
        _, st = self.run_task(faults=FaultInjector(tamper=True))
        self.assertEqual(st.status, "PARTIALLY_COMPLETED")
        self.assertEqual(st.final_reason, "verification_failed")
        self.assertFalse(st.verification["passed"])
        self.assertIn("evidence_present", st.verification["failed_checks"])
        self.assertEqual(st.verify_attempts, 1 + self.cfg.max_retries)  # bounded re-reads
        self.assertNotEqual(st.status, "COMPLETED")

    def test_12_final_status_calculation(self):
        s = TaskState.new("x", "policy")
        self.assertEqual(compute_final_status(s, "exhausted").value, "FAILED")
        s.verdict = "CONFIRMED"
        self.assertEqual(compute_final_status(s, "exhausted").value, "PARTIALLY_COMPLETED")
        self.assertEqual(compute_final_status(s, "verified").value, "COMPLETED")
        s.awaiting = "clarification"
        self.assertEqual(compute_final_status(s, "verified").value, "NEEDS_APPROVAL")

    def test_ambiguous_request_asks_for_clarification(self):
        _, st = self.run_task("Investigate the security alert and create a remediation case.")
        self.assertEqual((st.status, st.awaiting), ("NEEDS_APPROVAL", "clarification"))
        self.assertIsNone(st.selected_alert)
        self.assertEqual(self.db.list_cases(), [])

    def test_out_of_scope_request(self):
        _, st = self.run_task("Write me a poem about autumn.")
        self.assertEqual((st.status, st.awaiting), ("NEEDS_APPROVAL", "clarification"))
        self.assertEqual(st.iteration, 1)

    def test_invoice_request_is_preserved_and_rejected_without_tool_calls(self):
        request = ("Find the latest invoice from Company X, extract the amount and due date, "
                   "enter it into our internal system, and tell me once it is done")
        agent = self.agent()
        calls = []
        original_execute = agent.executor.execute
        def count_execute(*args, **kwargs):
            calls.append((args, kwargs))
            return original_execute(*args, **kwargs)
        agent.executor.execute = count_execute
        st = agent.run(request)
        self.assertEqual(st.status, "NEEDS_APPROVAL")
        self.assertEqual(st.awaiting, "clarification")
        self.assertEqual(st.objective, request)
        self.assertEqual(st.spec["objective"], request)
        self.assertIn("Invoice processing", st.final_message)
        self.assertIn("not currently supported", st.final_message)
        self.assertEqual(calls, [])
        self.assertEqual(st.completed_actions, [])
        self.assertEqual(st.failed_actions, [])
        self.assertEqual(self.db.list_cases(), [])
        events = self.db.events(st.task_id)
        interpreted = next(e for e in events if e["type"] == "objective_interpreted")
        self.assertEqual(interpreted["message"], request)

    def test_patch_requires_approval_and_is_not_performed(self):
        _, st = self.run_task("Investigate the critical dependency alert, create a remediation case and apply a patch to upgrade the package.")
        self.assertEqual((st.status, st.awaiting), ("NEEDS_APPROVAL", "approval"))
        self.assertTrue(st.verification["passed"])  # the allowed part still completed and was verified
        self.assertIn("NOT performed", st.final_message)

    def test_read_only_task_creates_nothing(self):
        _, st = self.run_task("Check whether PyYAML is used in this project.")
        self.assertEqual((st.status, st.verdict), ("COMPLETED", "CONFIRMED"))
        self.assertEqual(self.db.list_cases(), [])

    def test_guard_blocks_case_without_evidence_or_duplicate_check(self):
        agent, _ = self.run_task("Investigate the high severity Jinja2 alert and create a remediation case with evidence.")
        s = TaskState.new("x", "policy")
        s.selected_alert = {"id": "ALERT-001", "package": "PyYAML"}
        bad = Action("create_remediation_case", {"alert_id": "ALERT-001", "package": "PyYAML", "evidence": []}, "x")
        self.assertEqual(guard.check(s, bad, agent.registry).kind, "block")
        s.verdict, s.duplicate_checked = "CONFIRMED", True
        invented = Action("create_remediation_case", {"alert_id": "ALERT-001", "package": "PyYAML",
                          "evidence": [{"file": "x.py", "line": 1, "kind": "manifest", "snippet": "fake"}]}, "x")
        self.assertIn("not observed", guard.check(s, invented, agent.registry).message)

    def test_sensitive_tool_needs_approval(self):
        agent, _ = self.run_task("Check the Pillow alert.")
        agent.registry.register(Tool("apply_patch", "patch", {"type": "object"}, lambda a: {}, requires_approval=True))
        s = TaskState.new("x", "policy")
        self.assertEqual(guard.check(s, Action("apply_patch", {}, "x"), agent.registry).kind, "needs_approval")


if __name__ == "__main__":
    unittest.main()
