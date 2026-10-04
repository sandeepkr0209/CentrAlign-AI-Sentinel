"""Runtime configuration (environment variables, optional .env file)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class Config:
    repo_root: Path = ROOT / "data" / "sample_repository"
    alerts_path: Path = ROOT / "data" / "sample_alerts.json"
    db_path: Path = ROOT / "data" / "sentinel.db"
    max_iterations: int = 20
    max_retries: int = 3
    retry_delay: float = 0.3
    tool_timeout: float = 10.0
    llm_provider: str = ""            # "" / none = rule-based | groq | anthropic
    llm_model: str | None = None      # optional override of the provider's default model
    api_keys: dict = field(default_factory=dict, repr=False)  # provider -> key, read from env only

    @classmethod
    def from_env(cls) -> "Config":
        _load_dotenv(ROOT / ".env")
        env = os.environ.get
        cfg = cls()
        cfg.repo_root = Path(env("SENTINEL_REPO", cfg.repo_root))
        cfg.alerts_path = Path(env("SENTINEL_ALERTS", cfg.alerts_path))
        cfg.db_path = Path(env("SENTINEL_DB", cfg.db_path))
        cfg.max_iterations = int(env("SENTINEL_MAX_ITER", cfg.max_iterations))
        cfg.max_retries = int(env("SENTINEL_MAX_RETRIES", cfg.max_retries))
        cfg.retry_delay = float(env("SENTINEL_RETRY_DELAY", cfg.retry_delay))
        cfg.tool_timeout = float(env("SENTINEL_TOOL_TIMEOUT", cfg.tool_timeout))
        cfg.llm_provider = env("LLM_PROVIDER", "").strip()
        cfg.llm_model = env("LLM_MODEL") or None
        cfg.api_keys = {"groq": env("GROQ_API_KEY") or None, "anthropic": env("ANTHROPIC_API_KEY") or None}
        return cfg
