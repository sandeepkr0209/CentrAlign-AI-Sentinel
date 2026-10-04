"""Minimal standard-library web console (no framework). Binds to localhost only."""
from __future__ import annotations
import os 
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.config import Config
from app.environment.faults import FaultInjector
from app.factory import build_agent
from app.llm.base import ProviderFatalError
from app.llm.factory import describe_planner
from app.report import render_report
from app.storage.db import Database

INDEX = Path(__file__).parent / "static" / "index.html"


def make_handler(cfg: Config, db: Database):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code: int, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
            if self.path.startswith("/api/runs/"):
                state = db.load_run(self.path.rsplit("/", 1)[1])
                if state is None:
                    return self._send(404, {"error": "run not found yet"})
                events = db.events(state["task_id"])
                return self._send(200, {"state": state, "events": events, "report": render_report(state, events)})
            if self.path == "/api/cases":
                return self._send(200, {"cases": db.list_cases()})
            if self.path == "/api/config":
                return self._send(200, describe_planner(cfg))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            length = min(int(self.headers.get("Content-Length", 0)), 20_000)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "invalid JSON"})
            if self.path == "/api/reset":
                if os.environ.get("SENTINEL_ALLOW_RESET", "true").lower() != "true":
                    return self._send(403, {"error": "Reset is disabled on this deployment."})
                db.reset()
                return self._send(200, {"ok": True})
            if self.path != "/api/run":
                return self._send(404, {"error": "not found"})
            task = str(body.get("task", "")).strip()
            if not task or len(task) > 2000:
                return self._send(400, {"error": "Enter a task (max 2000 characters)."})
            try:
                faults = FaultInjector.parse(body.get("fault") or None)
            except ValueError as exc:
                return self._send(400, {"error": str(exc)})
            holder, ready = {}, threading.Event()

            def on_update(state):
                holder.setdefault("id", state.task_id)
                ready.set()

            try:
                agent = build_agent(cfg, faults=faults, db=db, on_update=on_update)
            except ProviderFatalError as exc:
                return self._send(400, {"error": str(exc)})
            threading.Thread(target=agent.run, args=(task,), daemon=True).start()
            ready.wait(5)
            self._send(200, {"task_id": holder.get("id")})

    return Handler


def serve(cfg: Config, port: int = 8765, host: str = "127.0.0.1") -> None:
    db = Database(cfg.db_path)
    server = ThreadingHTTPServer((host, port), make_handler(cfg, db))
    print(describe_planner(cfg)["label"])
    print(f"SENTINEL console listening on {host}:{port}   (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
