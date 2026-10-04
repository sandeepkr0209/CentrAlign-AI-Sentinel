"""Three required demo scenarios (+1 clarification case). Each uses a fresh database."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from app.config import Config
from app.environment.faults import FaultInjector
from app.factory import build_agent
from app.report import render_report
from app.storage.db import Database

TASK_MAIN = ("Investigate the critical dependency security alert in this project. Check whether the affected package is "
             "actually used, create a remediation case with supporting evidence, and verify that the case was recorded.")

SCENARIOS = {
    1: ("Successful execution", TASK_MAIN, None),
    2: ("Recovery from temporary failure (create fails twice, then succeeds)", TASK_MAIN, "transient:2"),
    3: ("Missing evidence: Jinja2 is only mentioned in documentation",
        "Investigate the high severity Jinja2 alert and create a remediation case with evidence.", None),
    4: ("Ambiguous request: needs clarification", "Investigate the security alert and create a remediation case.", None),
    5: ("Sensitive action: patch needs approval",
        "Investigate the critical dependency alert, create a remediation case and apply a patch to upgrade the package.", None),
}


def run_scenario(n: int, config: Config) -> tuple[dict, list[dict], Database]:
    title, task, fault = SCENARIOS[n]
    db_path = Path(config.db_path).parent / "demo" / f"scenario{n}.db"
    if db_path.exists():
        db_path.unlink()
    cfg = replace(config, db_path=db_path)
    db = Database(db_path)
    agent = build_agent(cfg, faults=FaultInjector.parse(fault), db=db)
    state = agent.run(task)
    return state.to_dict(), db.events(state.task_id), db
