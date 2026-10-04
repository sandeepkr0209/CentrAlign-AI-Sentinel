"""The six real tools. Every one executes local code and returns structured data."""
from __future__ import annotations

import json
import re

from app.environment.faults import FaultInjector
from app.environment.sandbox import Sandbox
from app.models import normalize_name
from app.storage.db import Database
from app.tools.errors import ToolError
from app.tools.registry import Tool, ToolRegistry

IMPORT_ALIASES = {"pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"],
                  "scikit-learn": ["sklearn"], "opencv-python": ["cv2"], "python-dateutil": ["dateutil"]}
MANIFEST_NAMES = ("requirements", "pipfile", "pyproject.toml", "package.json", "setup.cfg")
SEVERITIES = ["critical", "high", "medium", "low"]
EVIDENCE_ITEM = {"type": "object", "required": ["file", "line", "kind", "snippet"],
                 "properties": {"file": {"type": "string", "minLength": 1}, "line": {"type": "integer", "minimum": 1},
                                "kind": {"type": "string", "enum": ["manifest", "source_import", "source_usage", "doc"]},
                                "snippet": {"type": "string", "maxLength": 300}}}


def _is_manifest(name: str) -> bool:
    n = name.lower()
    return n.startswith("requirements") and n.endswith(".txt") or n in MANIFEST_NAMES


class SecurityEnvironment:
    def __init__(self, repo_root, alerts_path, db: Database, faults: FaultInjector | None = None):
        self.sandbox, self.alerts_path, self.db = Sandbox(repo_root), alerts_path, db
        self.faults = faults or FaultInjector()

    # ---- tools -------------------------------------------------------
    def load_alerts(self) -> list[dict]:
        try:
            with open(self.alerts_path, encoding="utf-8") as fh:
                alerts = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolError("ALERTS_UNAVAILABLE", f"Cannot read alert feed: {exc}", retryable=True)
        return alerts

    def list_security_alerts(self, args: dict) -> dict:
        alerts = self.load_alerts()
        if "severity" in args:
            alerts = [a for a in alerts if a["severity"] == args["severity"]]
        if "status" in args:
            alerts = [a for a in alerts if a["status"] == args["status"]]
        return {"alerts": alerts, "count": len(alerts)}

    def inspect_project_file(self, args: dict) -> dict:
        path = self.sandbox.resolve(args["path"])
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        limit = args.get("max_lines", 200)
        return {"path": self.sandbox.rel(path), "size_bytes": path.stat().st_size, "total_lines": len(lines),
                "truncated": len(lines) > limit, "lines": [{"n": i + 1, "text": l} for i, l in enumerate(lines[:limit])]}

    def search_dependency(self, args: dict) -> dict:
        package, include_docs = args["package"], args.get("include_docs", False)
        norm = normalize_name(package)
        names = {norm, norm.replace("-", "_")}
        aliases = set(IMPORT_ALIASES.get(norm, []))
        manifest_re = re.compile(r"^[\s\"']*([A-Za-z0-9_.\-]+)[\"']?\s*(?:\[[^\]]*\])?\s*[\"']?\s*(?::\s*\"?)?\s*([=<>!~^][^\s,\"']*)?")
        matches, scanned = [], 0
        for path in self.sandbox.iter_files():
            scanned += 1
            rel = self.sandbox.rel(path)
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            suffix = path.suffix.lower()
            for n, line in enumerate(lines, 1):
                snippet = line.strip()[:200]
                if _is_manifest(path.name):
                    m = manifest_re.match(line)
                    if m and normalize_name(m.group(1)) == norm:
                        matches.append({"file": rel, "line": n, "kind": "manifest", "snippet": snippet,
                                        "version_spec": m.group(2) or ""})
                elif suffix in (".py", ".js"):
                    for alias in names | aliases:
                        if re.match(rf"^\s*(import|from)\s+{re.escape(alias)}(\.|\s|$)", line):
                            matches.append({"file": rel, "line": n, "kind": "source_import", "snippet": snippet})
                            break
                        if re.search(rf"\b{re.escape(alias)}\.\w+", line) and not re.match(r"^\s*(import|from)\s", line):
                            matches.append({"file": rel, "line": n, "kind": "source_usage", "snippet": snippet})
                            break
                elif include_docs and suffix in (".md", ".rst", ".txt"):
                    if any(re.search(rf"\b{re.escape(w)}\b", line, re.I) for w in {package, norm}):
                        matches.append({"file": rel, "line": n, "kind": "doc", "snippet": snippet})
        counts = {k: sum(1 for m in matches if m["kind"] == k) for k in ("manifest", "source_import", "source_usage", "doc")}
        return {"package": package, "include_docs": include_docs, "files_scanned": scanned,
                "matches": matches, "counts": counts}

    def create_remediation_case(self, args: dict) -> dict:
        self.faults.before("create_remediation_case")
        if not any(a["id"] == args["alert_id"] for a in self.load_alerts()):
            raise ToolError("ALERT_NOT_FOUND", f"Unknown alert: {args['alert_id']}")
        case = self.db.create_case(alert_id=args["alert_id"], package=args["package"], severity=args["severity"],
                                   title=args["title"], summary=args["summary"], evidence=args["evidence"],
                                   task_id=args.get("task_id"))
        if self.faults.tamper:
            self.db.tamper_case_evidence(case["case_id"])
        self.faults.after_write()
        return {"case_id": case["case_id"], "status": case["status"], "created_at": case["created_at"]}

    def get_remediation_case(self, args: dict) -> dict:
        case = self.db.get_case(args["case_id"])
        if case is None:
            raise ToolError("CASE_NOT_FOUND", f"No case with id {args['case_id']}")
        return {"case": case}

    def list_remediation_cases(self, args: dict) -> dict:
        cases = self.db.list_cases(alert_id=args.get("alert_id"), status=args.get("status"))
        return {"cases": [{k: c[k] for k in ("case_id", "alert_id", "package", "severity", "status", "title")} for c in cases],
                "count": len(cases)}


def build_registry(env: SecurityEnvironment) -> ToolRegistry:
    obj = lambda props, req=(): {"type": "object", "properties": props, "required": list(req), "additionalProperties": False}
    r = ToolRegistry()
    r.register(Tool("list_security_alerts", "Retrieve the available security alerts (optionally filter by severity/status).",
                    obj({"severity": {"type": "string", "enum": SEVERITIES}, "status": {"type": "string", "enum": ["open", "closed"]}}),
                    env.list_security_alerts))
    r.register(Tool("inspect_project_file", "Safely read a file from the sample repository (relative path only).",
                    obj({"path": {"type": "string", "minLength": 1, "maxLength": 200},
                         "max_lines": {"type": "integer", "minimum": 1, "maximum": 500}}, ["path"]),
                    env.inspect_project_file))
    r.register(Tool("search_dependency", "Search manifests and source files (and optionally docs) for references to a package.",
                    obj({"package": {"type": "string", "minLength": 1, "maxLength": 100, "pattern": r"[A-Za-z0-9_.\-]+"},
                         "include_docs": {"type": "boolean"}}, ["package"]),
                    env.search_dependency))
    r.register(Tool("create_remediation_case", "Create a remediation case in the local tracker. Evidence must come from collected observations.",
                    obj({"alert_id": {"type": "string", "pattern": r"ALERT-\d+"}, "package": {"type": "string", "minLength": 1},
                         "severity": {"type": "string", "enum": SEVERITIES}, "title": {"type": "string", "minLength": 5, "maxLength": 200},
                         "summary": {"type": "string", "minLength": 10, "maxLength": 2000},
                         "evidence": {"type": "array", "minItems": 1, "maxItems": 50, "items": EVIDENCE_ITEM},
                         "task_id": {"type": "string", "maxLength": 40}},
                        ["alert_id", "package", "severity", "title", "summary", "evidence"]),
                    env.create_remediation_case))
    r.register(Tool("get_remediation_case", "Retrieve an existing remediation case by id (used for independent verification).",
                    obj({"case_id": {"type": "string", "pattern": r"SEC-\d{4}-\d{3,}"}}, ["case_id"]),
                    env.get_remediation_case))
    r.register(Tool("list_remediation_cases", "List remediation cases, optionally for one alert (duplicate detection).",
                    obj({"alert_id": {"type": "string", "pattern": r"ALERT-\d+"}, "status": {"type": "string", "enum": ["OPEN", "CLOSED"]}}),
                    env.list_remediation_cases))
    return r
