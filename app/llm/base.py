"""Provider interface. The agent core depends only on this, never on a specific vendor."""
from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.llm.http import http_post_json


class LLMError(Exception):
    """Base class for provider problems."""


class ProviderError(LLMError):
    """Temporary problem (network, rate limit, 5xx, malformed reply). The agent falls back for that step, visibly."""


class ProviderFatalError(LLMError):
    """Problem that will not fix itself (missing/invalid key, bad model). The run stops with an actionable message."""


class ProviderConfigError(ProviderFatalError):
    pass


class ProviderAuthError(ProviderFatalError):
    pass


@dataclass
class ToolProposal:
    name: str
    arguments: dict
    text: str = ""


class LLMProvider(ABC):
    id: str = ""
    display: str = ""
    key_env: str = ""

    RATE_LIMIT_RETRIES = 2   # extra attempts on HTTP 429 before the step falls back
    MAX_WAIT = 10.0          # seconds, per wait

    def __init__(self, api_key: str, model: str, post=None, timeout: float = 30.0, sleep=None):
        self._api_key, self.model, self.timeout = api_key, model, timeout
        self._post = post or http_post_json
        self._sleep = sleep or time.sleep

    @property
    def label(self) -> str:
        return f"{self.display} ({self.model})"

    @abstractmethod
    def _build(self, system: str, user: str, tools: list[dict]) -> tuple[str, dict, dict]:
        """Return (url, headers, body) for one forced tool-call request."""

    @abstractmethod
    def _parse(self, data: dict) -> ToolProposal:
        """Extract the first proposed tool call from a 200 response."""

    def complete_tool_call(self, system: str, user: str, tools: list[dict]) -> ToolProposal:
        url, headers, body = self._build(system, user, tools)
        status, data = self._post(url, headers, body, self.timeout)
        for attempt in range(self.RATE_LIMIT_RETRIES):
            if status != 429:
                break
            self._sleep(self._wait_seconds(data, attempt))
            status, data = self._post(url, headers, body, self.timeout)
        if status != 200:
            raise self._map_error(status, data)
        try:
            return self._parse(data)
        except LLMError:
            raise
        except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
            raise ProviderError(f"{self.display} returned a response SENTINEL could not parse ({type(exc).__name__}).")

    def _wait_seconds(self, data, attempt: int) -> float:
        wait = None
        if isinstance(data, dict):
            wait = data.get("_retry_after")
            if wait is None:
                m = re.search(r"try again in ([\d.]+)\s*(ms|s)", self._api_message(data)[0])
                if m:
                    wait = float(m.group(1)) / (1000 if m.group(2) == "ms" else 1)
        if wait is None:
            wait = 1.5 * (attempt + 1)
        return min(max(wait, 0.2), self.MAX_WAIT)

    # ---- errors (messages never contain the API key) ------------------
    def _redact(self, text: str) -> str:
        return text.replace(self._api_key, "***") if self._api_key else text

    def _api_message(self, data) -> tuple[str, str]:
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            return str(err.get("message", ""))[:300], str(err.get("code") or err.get("type") or "")
        return (str(err)[:300] if err else ""), ""

    def _map_error(self, status: int, data) -> LLMError:
        msg, code = self._api_message(data)
        msg = self._redact(msg)
        if status in (401, 403):
            return ProviderAuthError(f"{self.display} rejected the API key (HTTP {status}). Check that {self.key_env} is set to a "
                                     f"valid key for your own {self.display} account."
                                     + (" HTTP 403 can also mean a firewall, proxy or region block is stopping the request."
                                        if status == 403 else ""))
        if status == 429:
            return ProviderError(f"{self.display} rate limit or quota reached (HTTP 429). {msg}".strip())
        if status >= 500:
            return ProviderError(f"{self.display} service error (HTTP {status}).")
        if status == 400 and code == "tool_use_failed":
            return ProviderError(f"{self.display} model produced a malformed tool call.")
        if status in (400, 404):
            return ProviderFatalError(f"{self.display} rejected the request (HTTP {status}): {msg} Check LLM_MODEL "
                                      f"('{self.model}') is available to your account and supports tool calling.")
        return ProviderError(f"{self.display} returned HTTP {status}. {msg}".strip())
