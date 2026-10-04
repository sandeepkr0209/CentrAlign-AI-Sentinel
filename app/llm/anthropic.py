from __future__ import annotations

from app.llm.base import LLMProvider, ProviderError, ToolProposal


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API with forced tool use."""
    id, display, key_env = "anthropic", "Anthropic", "ANTHROPIC_API_KEY"
    URL = "https://api.anthropic.com/v1/messages"

    def _build(self, system, user, tools):
        body = {"model": self.model, "max_tokens": 1024, "system": system, "tools": tools,
                "tool_choice": {"type": "any"}, "messages": [{"role": "user", "content": user}]}
        return self.URL, {"x-api-key": self._api_key, "anthropic-version": "2023-06-01"}, body

    def _parse(self, data):
        blocks = data["content"]
        text = " ".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
        for b in blocks:
            if b.get("type") == "tool_use":
                return ToolProposal(b["name"], b.get("input", {}), text)
        raise ProviderError("Anthropic model returned no tool call.")
