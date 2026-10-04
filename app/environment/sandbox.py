"""Read-only sandbox over the sample repository. Blocks traversal, hidden files, big/odd files."""
from __future__ import annotations

from pathlib import Path

from app.tools.errors import ToolError

ALLOWED_SUFFIXES = {".txt", ".toml", ".json", ".py", ".md", ".cfg", ".yaml", ".yml", ".js", ".lock", ".rst"}
MAX_FILE_BYTES = 64 * 1024
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}


class Sandbox:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def resolve(self, rel: str) -> Path:
        if "\x00" in rel or rel.startswith(("/", "\\")) or (len(rel) > 1 and rel[1] == ":"):
            raise ToolError("PATH_DENIED", f"Absolute or malformed paths are not allowed: {rel!r}")
        parts = Path(rel.replace("\\", "/")).parts
        if any(p == ".." for p in parts) or any(p.startswith(".") for p in parts):
            raise ToolError("PATH_DENIED", f"Path traversal or hidden files are not allowed: {rel!r}")
        target = (self.root / rel).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            raise ToolError("PATH_DENIED", f"Path escapes the sandbox: {rel!r}")
        if not target.exists():
            raise ToolError("FILE_NOT_FOUND", f"File not found in repository: {rel}")
        if not target.is_file():
            raise ToolError("NOT_A_FILE", f"Not a regular file: {rel}")
        if target.suffix.lower() not in ALLOWED_SUFFIXES:
            raise ToolError("FILE_TYPE_DENIED", f"File type {target.suffix or '(none)'} is not allowed: {rel}")
        if target.stat().st_size > MAX_FILE_BYTES:
            raise ToolError("FILE_TOO_LARGE", f"File exceeds {MAX_FILE_BYTES} bytes: {rel}")
        return target

    def rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def iter_files(self):
        for path in sorted(self.root.rglob("*")):
            if any(p in SKIP_DIRS or (p.startswith(".") and p != ".") for p in path.relative_to(self.root).parts):
                continue
            if path.is_file() and path.suffix.lower() in ALLOWED_SUFFIXES and path.stat().st_size <= MAX_FILE_BYTES:
                yield path
