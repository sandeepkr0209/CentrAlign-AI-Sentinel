import os
import tempfile
import unittest

from app.config import Config
from app.environment.faults import FaultInjector
from app.factory import build_agent
from app.storage.db import Database

TASK = ("Investigate the critical dependency security alert in this project. Check whether the affected package is "
        "actually used, create a remediation case with supporting evidence, and verify that the case was recorded.")


class AgentTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(db_path=os.path.join(self.tmp.name, "t.db"), retry_delay=0)
        self.db = Database(self.cfg.db_path)

    def agent(self, faults=None, planner=None):
        return build_agent(self.cfg, faults=faults, planner=planner, db=self.db)

    def run_task(self, task=TASK, faults=None, planner=None):
        a = self.agent(faults, planner)
        return a, a.run(task)
