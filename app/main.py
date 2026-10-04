"""SENTINEL command line.   python -m app.main --help"""
from __future__ import annotations

import argparse
import sys
from dataclasses import replace

from app.config import Config
from app.demo import SCENARIOS, run_scenario
from app.environment.faults import FaultInjector
from app.factory import build_agent
from app.llm.base import ProviderFatalError
from app.llm.factory import describe_planner
from app.report import render_report
from app.storage.db import Database


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sentinel", description="SENTINEL - Investigate. Act. Verify.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a natural-language task")
    r.add_argument("task")
    r.add_argument("--fault", help="demo fault injection: transient[:N], write-then-fail, tamper")
    r.add_argument("--db", help="override database path")
    d = sub.add_parser("demo", help="run a demo scenario")
    d.add_argument("n", type=int, choices=sorted(SCENARIOS))
    d.add_argument("--rules", action="store_true", help="force the rule-based planner even if LLM_PROVIDER is set")
    sub.add_parser("cases", help="list remediation cases")
    s = sub.add_parser("serve", help="start the web console")
    s.add_argument("--port", type=int, default=8765)
    args = p.parse_args(argv)
    cfg = Config.from_env()

    if args.cmd == "run":
        if args.db:
            cfg = replace(cfg, db_path=args.db)
        info = describe_planner(cfg)
        if info["error"]:
            print("Error: " + info["error"], file=sys.stderr)
            return 1
        agent = build_agent(cfg, faults=FaultInjector.parse(args.fault))
        print(info["label"])
        state = agent.run(args.task)
        print(render_report(state.to_dict(), agent.db.events(state.task_id)))
        return 0 if state.status == "COMPLETED" else 2
    if args.cmd == "demo":
        title, task, fault = SCENARIOS[args.n]
        print(f"### Scenario {args.n}: {title}\n### Task: {task}\n### Fault injection: {fault or 'none'}")
        dcfg = replace(cfg, llm_provider="none") if args.rules else cfg
        info = describe_planner(dcfg)
        if info["error"]:
            print("Error: " + info["error"], file=sys.stderr)
            return 1
        print("### " + info["label"])
        state, events, db = run_scenario(args.n, dcfg)
        print(render_report(state, events))
        if state["target_case_id"]:
            print("\nIndependent check straight from SQLite:", db.get_case(state["target_case_id"])["case_id"],
                  "-", db.get_case(state["target_case_id"])["title"])
        return 0
    if args.cmd == "cases":
        for c in Database(cfg.db_path).list_cases():
            print(f"{c['case_id']}  {c['status']:<6} {c['severity']:<8} {c['alert_id']}  {c['title']}")
        return 0
    if args.cmd == "serve":
        from app.web import serve
        serve(cfg, args.port)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
