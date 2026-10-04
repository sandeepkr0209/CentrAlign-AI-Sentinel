"""Fault injection for demos and tests. Never active unless explicitly configured."""
from __future__ import annotations

from app.tools.errors import TransientToolError


class FaultInjector:
    def __init__(self, transient: dict[str, int] | None = None, write_then_fail: int = 0, tamper: bool = False):
        self.transient = dict(transient or {})   # tool -> failures before the operation runs
        self.write_then_fail = write_then_fail   # create succeeds, but the response is lost
        self.tamper = tamper                     # stored evidence silently corrupted after create

    def before(self, tool: str) -> None:
        if self.transient.get(tool, 0) > 0:
            self.transient[tool] -= 1
            raise TransientToolError(f"Simulated temporary outage in {tool} (fault injection).")

    def after_write(self) -> None:
        if self.write_then_fail > 0:
            self.write_then_fail -= 1
            raise TransientToolError("Simulated lost response after the record was written (fault injection).")

    @classmethod
    def parse(cls, spec: str | None) -> "FaultInjector":
        """'transient:2', 'write-then-fail', 'tamper' (comma separated)."""
        f = cls()
        for part in filter(None, (spec or "").split(",")):
            name, _, arg = part.strip().partition(":")
            if name == "transient":
                f.transient["create_remediation_case"] = int(arg or 1)
            elif name == "write-then-fail":
                f.write_then_fail = int(arg or 1)
            elif name == "tamper":
                f.tamper = True
            else:
                raise ValueError(f"Unknown fault: {part}")
        return f
