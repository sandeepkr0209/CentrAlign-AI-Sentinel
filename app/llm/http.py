"""Single standard-library HTTP helper shared by all providers."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def http_post_json(url: str, headers: dict, body: dict, timeout: float) -> tuple[int, dict]:
    from app.llm.base import ProviderError  # local import avoids a cycle
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={**headers, "content-type": "application/json", "user-agent": "sentinel-agent/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
            retry_after = None
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
        retry_after = exc.headers.get("retry-after") if exc.headers else None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"Network error contacting the LLM provider ({type(exc).__name__}). Check your connection.")
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        data = {}
    if isinstance(data, dict) and retry_after:
        try:
            data["_retry_after"] = float(retry_after)
        except ValueError:
            pass
    return status, data
