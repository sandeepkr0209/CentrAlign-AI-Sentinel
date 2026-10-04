"""SQLite persistence: remediation cases, task runs and the audit event log."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from datetime import datetime
from pathlib import Path

from app.models import evidence_digest, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, package TEXT NOT NULL, severity TEXT NOT NULL,
    title TEXT NOT NULL, summary TEXT NOT NULL, evidence_json TEXT NOT NULL, evidence_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN', created_by_task TEXT, created_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_open_case_per_alert ON cases(alert_id) WHERE status = 'OPEN';
CREATE TABLE IF NOT EXISTS runs (
    task_id TEXT PRIMARY KEY, request TEXT NOT NULL, status TEXT NOT NULL, state_json TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL, seq INTEGER NOT NULL, ts TEXT NOT NULL,
    type TEXT NOT NULL, message TEXT NOT NULL, data_json TEXT NOT NULL);
"""


class DuplicateCaseError(Exception):
    def __init__(self, existing_case_id: str):
        super().__init__(f"An open case already exists for this alert: {existing_case_id}")
        self.existing_case_id = existing_case_id


class Database:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._lock, closing(self._conn()) as c, c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    # ---- cases -------------------------------------------------------
    @staticmethod
    def _case(row) -> dict:
        d = dict(row)
        d["evidence"] = json.loads(d.pop("evidence_json"))
        return d

    def create_case(self, *, alert_id, package, severity, title, summary, evidence, task_id=None) -> dict:
        with self._lock, closing(self._conn()) as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                row = c.execute("SELECT case_id FROM cases WHERE alert_id=? AND status='OPEN'", (alert_id,)).fetchone()
                if row:
                    raise DuplicateCaseError(row["case_id"])
                year = datetime.now().year
                last = c.execute("SELECT MAX(CAST(substr(case_id, 10) AS INTEGER)) AS n FROM cases WHERE case_id LIKE ?",
                                 (f"SEC-{year}-%",)).fetchone()["n"] or 0
                case_id = f"SEC-{year}-{last + 1:03d}"
                c.execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                          (case_id, alert_id, package, severity, title, summary, json.dumps(evidence),
                           evidence_digest(evidence), "OPEN", task_id, now_iso()))
                c.commit()
            except Exception:
                c.rollback()
                raise
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> dict | None:
        with self._lock, closing(self._conn()) as c:
            row = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return self._case(row) if row else None

    def list_cases(self, alert_id: str | None = None, status: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM cases WHERE 1=1", []
        if alert_id:
            q += " AND alert_id=?"; args.append(alert_id)
        if status:
            q += " AND status=?"; args.append(status)
        with self._lock, closing(self._conn()) as c:
            rows = c.execute(q + " ORDER BY created_at", args).fetchall()
        return [self._case(r) for r in rows]

    def tamper_case_evidence(self, case_id: str) -> None:
        """Fault-injection helper only: silently drops stored evidence to simulate corruption."""
        with self._lock, closing(self._conn()) as c, c:
            c.execute("UPDATE cases SET evidence_json='[]' WHERE case_id=?", (case_id,))

    # ---- runs & events -----------------------------------------------
    def save_run(self, state: dict) -> None:
        with self._lock, closing(self._conn()) as c, c:
            c.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET "
                "status=excluded.status, state_json=excluded.state_json, updated_at=excluded.updated_at",
                (state["task_id"], state["request"], state["status"], json.dumps(state), state["created_at"], now_iso()))

    def load_run(self, task_id: str) -> dict | None:
        with self._lock, closing(self._conn()) as c:
            row = c.execute("SELECT state_json FROM runs WHERE task_id=?", (task_id,)).fetchone()
        return json.loads(row["state_json"]) if row else None

    def list_runs(self, limit: int = 20) -> list[dict]:
        with self._lock, closing(self._conn()) as c:
            rows = c.execute("SELECT task_id, request, status, updated_at FROM runs ORDER BY updated_at DESC LIMIT ?",
                             (limit,)).fetchall()
        return [dict(r) for r in rows]

    def add_event(self, task_id: str, etype: str, message: str, data: dict | None = None) -> dict:
        with self._lock, closing(self._conn()) as c, c:
            seq = (c.execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM events WHERE task_id=?", (task_id,)).fetchone()["n"])
            ts = now_iso()
            c.execute("INSERT INTO events (task_id, seq, ts, type, message, data_json) VALUES (?,?,?,?,?,?)",
                      (task_id, seq, ts, etype, message, json.dumps(data or {}, default=str)))
        return {"seq": seq, "ts": ts, "type": etype, "message": message, "data": data or {}}

    def events(self, task_id: str) -> list[dict]:
        with self._lock, closing(self._conn()) as c:
            rows = c.execute("SELECT seq, ts, type, message, data_json FROM events WHERE task_id=? ORDER BY seq",
                             (task_id,)).fetchall()
        return [{"seq": r["seq"], "ts": r["ts"], "type": r["type"], "message": r["message"],
                 "data": json.loads(r["data_json"])} for r in rows]

    def reset(self) -> None:
        with self._lock, closing(self._conn()) as c, c:
            for table in ("cases", "runs", "events"):
                c.execute(f"DELETE FROM {table}")
