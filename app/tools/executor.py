"""Validates arguments, runs a tool with a timeout and returns a structured ToolResult."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from app.models import ToolResult
from app.storage.db import DuplicateCaseError
from app.tools.errors import ToolError
from app.tools.registry import ToolRegistry
from app.tools.schema import validate


class ToolExecutor:
    def __init__(self, registry: ToolRegistry, timeout: float = 10.0):
        self.registry, self.timeout = registry, timeout
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="tool")

    def validate_args(self, name: str, arguments) -> list[str]:
        tool = self.registry.get(name)
        if tool is None:
            return [f"unknown tool: {name!r}"]
        return validate(arguments, tool.input_schema)

    def execute(self, name: str, arguments) -> ToolResult:
        start = time.monotonic()
        args = arguments if isinstance(arguments, dict) else {}
        errors = self.validate_args(name, arguments)
        if errors:
            return ToolResult(name, args, False, error_code="INVALID_ARGUMENTS", error="; ".join(errors),
                              duration_ms=0)
        tool = self.registry.get(name)
        future = self._pool.submit(tool.func, arguments)
        try:
            data = future.result(timeout=self.timeout)
            return ToolResult(name, args, True, data=data, duration_ms=int((time.monotonic() - start) * 1000))
        except FutureTimeout:
            return ToolResult(name, args, False, error_code="TIMEOUT", retryable=True,
                              error=f"{name} exceeded {self.timeout}s", duration_ms=int(self.timeout * 1000))
        except DuplicateCaseError as exc:
            return ToolResult(name, args, False, error_code="DUPLICATE_CASE", error=str(exc),
                              details={"existing_case_id": exc.existing_case_id})
        except ToolError as exc:
            return ToolResult(name, args, False, error_code=exc.code, error=str(exc), retryable=exc.retryable,
                              details=exc.details, duration_ms=int((time.monotonic() - start) * 1000))
        except Exception as exc:  # unexpected bug: report, never crash the agent loop
            return ToolResult(name, args, False, error_code="INTERNAL_ERROR", error=f"{type(exc).__name__}: {exc}")
