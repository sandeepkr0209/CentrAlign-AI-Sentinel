import unittest

from app.environment.faults import FaultInjector
from app.tools.builtin import SecurityEnvironment, build_registry
from app.tools.executor import ToolExecutor
from tests.helpers import AgentTestCase

EVIDENCE = [{"file": "requirements.txt", "line": 3, "kind": "manifest", "snippet": "PyYAML==5.3"}]


class ToolTests(AgentTestCase):
    def setUp(self):
        super().setUp()
        self.env = SecurityEnvironment(self.cfg.repo_root, self.cfg.alerts_path, self.db)
        self.ex = ToolExecutor(build_registry(self.env), timeout=2)

    def case_args(self, **over):
        a = {"alert_id": "ALERT-001", "package": "PyYAML", "severity": "critical", "title": "Upgrade PyYAML",
             "summary": "PyYAML declared in requirements.txt", "evidence": EVIDENCE}
        a.update(over)
        return a

    def test_01_alert_retrieval(self):
        r = self.ex.execute("list_security_alerts", {})
        self.assertTrue(r.ok)
        self.assertEqual(r.data["count"], 3)
        crit = self.ex.execute("list_security_alerts", {"severity": "critical"})
        self.assertEqual([a["id"] for a in crit.data["alerts"]], ["ALERT-001"])

    def test_02_file_inspection(self):
        r = self.ex.execute("inspect_project_file", {"path": "requirements.txt"})
        self.assertTrue(r.ok)
        self.assertIn("PyYAML==5.3", [l["text"] for l in r.data["lines"]])

    def test_03_dependency_search_classifies_kinds(self):
        r = self.ex.execute("search_dependency", {"package": "PyYAML"})
        self.assertEqual(r.data["counts"]["manifest"], 1)
        self.assertGreaterEqual(r.data["counts"]["source_import"], 1)
        docs = self.ex.execute("search_dependency", {"package": "Jinja2", "include_docs": True})
        self.assertEqual(docs.data["counts"], {"manifest": 0, "source_import": 0, "source_usage": 0, "doc": 2})
        none = self.ex.execute("search_dependency", {"package": "Pillow", "include_docs": True})
        self.assertEqual(sum(none.data["counts"].values()), 0)

    def test_04_case_creation_is_real_and_persisted(self):
        r = self.ex.execute("create_remediation_case", self.case_args())
        self.assertTrue(r.ok, r.error)
        again = type(self.db)(self.cfg.db_path)  # a fresh connection to the same file
        self.assertEqual(again.get_case(r.data["case_id"])["alert_id"], "ALERT-001")
        got = self.ex.execute("get_remediation_case", {"case_id": r.data["case_id"]})
        self.assertEqual(got.data["case"]["evidence"], EVIDENCE)

    def test_05_duplicate_prevention(self):
        self.assertTrue(self.ex.execute("create_remediation_case", self.case_args()).ok)
        dup = self.ex.execute("create_remediation_case", self.case_args())
        self.assertFalse(dup.ok)
        self.assertEqual(dup.error_code, "DUPLICATE_CASE")
        self.assertEqual(len(self.db.list_cases()), 1)

    def test_07_invalid_arguments(self):
        for name, args in [("create_remediation_case", self.case_args(severity="catastrophic")),
                           ("create_remediation_case", self.case_args(evidence=[])),
                           ("get_remediation_case", {"case_id": "nope"}),
                           ("search_dependency", {}), ("inspect_project_file", {"path": 5}),
                           ("list_security_alerts", {"bogus": 1}), ("no_such_tool", {})]:
            r = self.ex.execute(name, args)
            self.assertFalse(r.ok, name)
            self.assertEqual(r.error_code, "INVALID_ARGUMENTS", name)
        self.assertEqual(self.db.list_cases(), [])

    def test_08_missing_and_unsafe_files(self):
        self.assertEqual(self.ex.execute("inspect_project_file", {"path": "nope.txt"}).error_code, "FILE_NOT_FOUND")
        for bad in ("../data/sample_alerts.json", "/etc/passwd", "docs/../../app/main.py", ".env"):
            self.assertEqual(self.ex.execute("inspect_project_file", {"path": bad}).error_code, "PATH_DENIED", bad)
        self.assertEqual(self.ex.execute("get_remediation_case", {"case_id": "SEC-2026-999"}).error_code, "CASE_NOT_FOUND")

    def test_09_temporary_failure_is_reported_as_retryable(self):
        env = SecurityEnvironment(self.cfg.repo_root, self.cfg.alerts_path, self.db, FaultInjector(transient={"create_remediation_case": 1}))
        ex = ToolExecutor(build_registry(env))
        first = ex.execute("create_remediation_case", self.case_args())
        self.assertFalse(first.ok)
        self.assertTrue(first.retryable)
        self.assertEqual(self.db.list_cases(), [])
        self.assertTrue(ex.execute("create_remediation_case", self.case_args()).ok)


if __name__ == "__main__":
    unittest.main()
