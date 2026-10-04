"""Core data models: task spec, agent state, actions, tool results."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


class TaskStatus(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"  # needs a human: approval or clarification


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"        # declared in a dependency manifest
    DOC_ONLY = "DOC_ONLY"          # only mentioned in documentation
    NOT_FOUND = "NOT_FOUND"        # no reference anywhere
    INSUFFICIENT = "INSUFFICIENT"  # ambiguous evidence (e.g. imported but undeclared)


def now_iso() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


def normalize_name(name: str) -> str:
    import re
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def evidence_digest(items: list[dict]) -> str:
    key = sorted(
        ({"file": i["file"], "line": i["line"], "kind": i["kind"], "snippet": i["snippet"]} for i in items),
        key=lambda d: (d["file"], d["line"], d["kind"]),
    )
    return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()


@dataclass
class TaskSpec:
    objective: str
    intent: str                      # investigate | investigate_and_record
    in_scope: bool
    alert_ids: list[str]
    severity: str | None
    keywords: list[str]
    wants_case: bool
    wants_patch: bool
    sensitive_actions: list[str]
    required_evidence: list[str]
    expected_outcome: str


@dataclass
class Action:
    tool: str
    arguments: dict
    rationale: str
    source: str = "policy"  # policy | llm


@dataclass
class ToolResult:
    tool: str
    arguments: dict
    ok: bool
    data: dict | None = None
    error_code: str | None = None
    error: str | None = None
    retryable: bool = False
    details: dict = field(default_factory=dict)
    duration_ms: int = 0


@dataclass
class TaskState:
    task_id: str
    request: str
    planner: str = "rule-based"
    objective: str = ""
    spec: dict = field(default_factory=dict)
    plan: list = field(default_factory=list)
    status: str = TaskStatus.RUNNING.value
    current_action: str = ""
    iteration: int = 0
    alerts: list = field(default_factory=list)
    alerts_listed: bool = False
    selection_done: bool = False
    selected_alert: dict | None = None
    files_inspected: list = field(default_factory=list)
    manifest_inspected: bool = False
    searches: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    verdict: str | None = None
    search_done: bool = False
    affected_status: bool | None = None   # declared version inside affected range?
    version_note: str = ""
    duplicate_checked: bool = False
    existing_case_id: str | None = None
    created_case_id: str | None = None
    target_case_id: str | None = None     # case that must be independently verified
    case_reused: bool = False
    fetched_case: dict | None = None
    completed_actions: list = field(default_factory=list)
    failed_actions: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    retries: dict = field(default_factory=dict)      # consecutive failures per tool
    retry_count: int = 0                             # total recovery attempts
    exhausted: list = field(default_factory=list)
    guard_blocks: int = 0
    verification: dict | None = None
    verify_attempts: int = 0
    awaiting: str | None = None           # approval | clarification
    awaiting_message: str = ""
    pending_approval: dict | None = None
    approved_actions: list = field(default_factory=list)
    provider_error: str | None = None
    final_reason: str = ""
    final_message: str = ""
    limitations: list = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)
    finished_at: str | None = None

    @classmethod
    def new(cls, request: str, planner: str) -> "TaskState":
        return cls(task_id="TASK-" + uuid.uuid4().hex[:8].upper(), request=request, planner=planner)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "TaskState":
        return cls(**data)
