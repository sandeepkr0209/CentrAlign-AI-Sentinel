from __future__ import annotations

import json

from app.llm.base import LLMProvider, ProviderError, ToolProposal


class GroqProvider(LLMProvider):
    """Groq's OpenAI-compatible chat completions API with forced function calling."""
    id, display, key_env = "groq", "Groq", "GROQ_API_KEY"
    URL = "https://api.groq.com/openai/v1/chat/completions"

    def _build(self, system, user, tools):
        body = {"model": self.model, "temperature": 0, "max_tokens": 1024, "tool_choice": "required",
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "tools": [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                            "parameters": t["input_schema"]}} for t in tools]}
        return self.URL, {"authorization": f"Bearer {self._api_key}"}, body

    def _parse(self, data):
        msg = data["choices"][0]["message"]
        calls = msg.get("tool_calls") or []
        if not calls:
            raise ProviderError("Groq model returned no tool call.")
        fn = calls[0]["function"]
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            raise ProviderError("Groq model returned tool arguments that are not valid JSON.")
        if not isinstance(args, dict):
            raise ProviderError("Groq model returned tool arguments that are not an object.")
        return ToolProposal(fn["name"], args, (msg.get("content") or "").strip())
