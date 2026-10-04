"""Chooses the provider from configuration. Returns None for rule-based mode."""
from __future__ import annotations

from app.config import Config
from app.llm.anthropic import AnthropicProvider
from app.llm.base import LLMProvider, ProviderConfigError
from app.llm.groq import GroqProvider

PROVIDERS = {"groq": GroqProvider, "anthropic": AnthropicProvider}
DEFAULT_MODELS = {"groq": "llama-3.3-70b-versatile", "anthropic": "claude-haiku-4-5-20251001"}
RULES_VALUES = {"", "none", "rules", "rule-based"}


def create_provider(cfg: Config, post=None) -> LLMProvider | None:
    name = (cfg.llm_provider or "").strip().lower()
    if name in RULES_VALUES:
        return None
    cls = PROVIDERS.get(name)
    if cls is None:
        raise ProviderConfigError(f"Unknown LLM_PROVIDER '{cfg.llm_provider}'. Use 'groq', 'anthropic', or leave it unset "
                                  "for the free rule-based planner.")
    key = cfg.api_keys.get(name)
    if not key:
        raise ProviderConfigError(f"LLM_PROVIDER={name} but {cls.key_env} is not set. Export your own key "
                                  f"(e.g. `export {cls.key_env}=...`) or put it in .env, or unset LLM_PROVIDER to use the "
                                  "rule-based planner.")
    return cls(key, cfg.llm_model or DEFAULT_MODELS[name], post=post)


def describe_planner(cfg: Config) -> dict:
    """What will actually run, for the CLI banner and web header. Never reveals keys."""
    try:
        provider = create_provider(cfg)
    except ProviderConfigError as exc:
        return {"mode": "error", "label": "LLM provider misconfigured", "error": str(exc)}
    if provider:
        return {"mode": "llm", "label": f"Planner: LLM via {provider.label}. Safety guard validates every action.", "error": None}
    note = ""
    if any(cfg.api_keys.values()):
        note = " (an API key is set but LLM_PROVIDER is not, so no LLM is used)"
    return {"mode": "rule-based", "label": "Planner: rule-based policy, no LLM is used" + note, "error": None}
