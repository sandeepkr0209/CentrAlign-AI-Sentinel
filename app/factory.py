"""Wires everything together."""
from __future__ import annotations

from app.agent.orchestrator import Orchestrator
from app.agent.planner import LLMPlanner, PolicyPlanner
from app.config import Config
from app.environment.faults import FaultInjector
from app.llm.factory import create_provider
from app.storage.db import Database
from app.tools.builtin import SecurityEnvironment, build_registry
from app.tools.executor import ToolExecutor


def build_agent(config: Config, faults: FaultInjector | None = None, planner=None, db: Database | None = None,
                on_update=None, provider=None) -> Orchestrator:
    """Raises ProviderFatalError if LLM_PROVIDER is selected but misconfigured (never silently falls back)."""
    if planner is None:
        provider = provider or create_provider(config)
        planner = LLMPlanner(provider) if provider else PolicyPlanner()
    db = db or Database(config.db_path)
    env = SecurityEnvironment(config.repo_root, config.alerts_path, db, faults)
    registry = build_registry(env)
    return Orchestrator(config, registry, ToolExecutor(registry, config.tool_timeout), planner, db, on_update)
