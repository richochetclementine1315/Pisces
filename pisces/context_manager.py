"""
pisces.context_manager
~~~~~~~~~~~~~~~~~~~~~~
Discovers Python files, manages hashing, drives AST extraction,
and persists the project intelligence to .pisces/context.json.

Core principle:
    For each .py file:
        read → SHA-256 → compare stored hash
        unchanged → reuse existing context entry  ← fast path
        changed   → re-parse AST → replace entry ← slow path (only when needed)
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pisces.ast_visitor import extract_file_context
from pisces.models import FileContext
from pisces.tui import (
    console,
    print_step_fail,
    print_step_ok,
    print_step_running,
    print_warning,
)

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

CONTEXT_SCHEMA_VERSION = "1"
CONTEXT_FILENAME       = "context.json"

# Default directories / patterns to always ignore
_DEFAULT_EXCLUDES = frozenset([
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pisces",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    ".eggs",
])


# ─────────────────────────────────────────────────────────────
# File hashing
# ─────────────────────────────────────────────────────────────

def hash_file(path: Path) -> str:
    """Return the SHA-256 hex digest of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────
# Python file discovery
# ─────────────────────────────────────────────────────────────

def discover_python_files(
    root: Path,
    extra_excludes: Optional[list[str]] = None,
) -> list[Path]:
    """
    Recursively find all .py files under *root*, respecting exclusion rules.

    Returns absolute Paths sorted for deterministic ordering.
    """
    excludes = set(_DEFAULT_EXCLUDES)
    if extra_excludes:
        excludes.update(extra_excludes)

    found: list[Path] = []

    def _is_excluded(path: Path) -> bool:
        # Exclude if any component matches an exclusion pattern
        for part in path.parts:
            if part in excludes:
                return True
        return False

    for py_file in root.rglob("*.py"):
        if not _is_excluded(py_file.relative_to(root)):
            found.append(py_file)

    return sorted(found)


# ─────────────────────────────────────────────────────────────
# Context JSON I/O
# ─────────────────────────────────────────────────────────────

def _context_path(project_root: Path) -> Path:
    return project_root / ".pisces" / CONTEXT_FILENAME


def load_raw_context(project_root: Path) -> dict:
    """Load context.json and return raw dict. Returns empty skeleton on failure."""
    ctx_path = _context_path(project_root)
    if not ctx_path.exists():
        return _empty_context(project_root)
    try:
        with ctx_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        print_warning("context.json is corrupted — starting fresh.")
        return _empty_context(project_root)


def _empty_context(project_root: Path) -> dict:
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "project": {
            "root":           str(project_root),
            "last_updated":   datetime.now(timezone.utc).isoformat(),
        },
        "files": {},
    }


def save_context(project_root: Path, raw: dict) -> None:
    """Atomically write context.json."""
    ctx_path = _context_path(project_root)
    ctx_path.parent.mkdir(parents=True, exist_ok=True)

    raw["project"]["last_updated"] = datetime.now(timezone.utc).isoformat()

    tmp_path = ctx_path.with_suffix(".json.tmp")
    try:
        tmp_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        tmp_path.replace(ctx_path)  # atomic on most platforms
    except OSError as e:
        print_warning(f"Could not save context.json: {e}")
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────
# Context Manager
# ─────────────────────────────────────────────────────────────

class ContextManager:
    """
    High-level interface for managing project context.

    Example:
        cm = ContextManager(project_root, extra_excludes=[".build"])
        stats = cm.update()
        print(f"Updated {stats['updated']} files, skipped {stats['skipped']}")
    """

    def __init__(
        self,
        project_root: Path,
        extra_excludes: Optional[list[str]] = None,
    ) -> None:
        self.project_root    = project_root
        self.extra_excludes  = extra_excludes or []
        self._raw: dict      = {}    # in-memory copy of context.json

    # ── Public API ────────────────────────────────────────

    def load(self) -> None:
        """Load context.json into memory."""
        self._raw = load_raw_context(self.project_root)

    def save(self) -> None:
        """Persist in-memory context to disk."""
        save_context(self.project_root, self._raw)

    def update(self, verbose: bool = True) -> dict:
        """
        Scan all Python files and update context.json incrementally.

        Returns stats dict: {discovered, updated, skipped, errors, elapsed_s}
        """
        self.load()

        t0 = time.monotonic()
        py_files = discover_python_files(
            self.project_root, extra_excludes=self.extra_excludes
        )

        stats = {
            "discovered": len(py_files),
            "updated":    0,
            "skipped":    0,
            "errors":     0,
        }

        if verbose:
            console.print(
                f"  [dim]Discovered[/] [cyan]{len(py_files)}[/] [dim]Python file(s)[/]"
            )

        existing_files: dict = self._raw.setdefault("files", {})

        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))

            try:
                file_hash = hash_file(py_file)
            except OSError as e:
                if verbose:
                    print_step_fail(f"Cannot read {rel}: {e}")
                stats["errors"] += 1
                continue

            # ─ Incremental check ─────────────────────────
            stored = existing_files.get(rel, {})
            if stored.get("hash") == file_hash:
                stats["skipped"] += 1
                continue   # ← fast path: file unchanged

            # ─ File changed or new → re-parse AST ────────
            if verbose:
                print_step_running(f"Parsing {rel} ...")

            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                if verbose:
                    print_step_fail(f"Cannot read source of {rel}: {e}")
                stats["errors"] += 1
                continue

            fc = extract_file_context(
                file_path=py_file,
                relative_path=rel,
                file_hash=file_hash,
                source=source,
            )

            if fc.parse_error and verbose:
                print_warning(f"Parse warning in {rel}: {fc.parse_error}")

            existing_files[rel] = fc.to_dict()
            stats["updated"] += 1

            if verbose:
                print_step_ok(f"{rel}")

        # Remove entries for files that no longer exist
        live_rels = {
            str(f.relative_to(self.project_root)) for f in py_files
        }
        stale = [k for k in existing_files if k not in live_rels]
        for k in stale:
            del existing_files[k]
            if verbose:
                print_step_ok(f"Removed stale entry: {k}")

        self._raw["files"] = existing_files
        self.save()

        stats["elapsed_s"] = round(time.monotonic() - t0, 3)
        return stats

    def update_single_file(self, file_path: Path) -> bool:
        """
        Update context for a single file (used by watch mode).

        Returns True if context was changed.
        """
        self.load()

        rel = str(file_path.relative_to(self.project_root))

        if not file_path.exists():
            # File deleted — remove from context
            if rel in self._raw.get("files", {}):
                del self._raw["files"][rel]
                self.save()
                return True
            return False

        try:
            file_hash = hash_file(file_path)
        except OSError:
            return False

        stored = self._raw.get("files", {}).get(rel, {})
        if stored.get("hash") == file_hash:
            return False   # unchanged

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False

        fc = extract_file_context(
            file_path=file_path,
            relative_path=rel,
            file_hash=file_hash,
            source=source,
        )

        self._raw.setdefault("files", {})[rel] = fc.to_dict()
        self.save()
        return True

    def get_file_context(self, rel_path: str) -> Optional[FileContext]:
        """Return a FileContext for a relative path, or None if not found."""
        data = self._raw.get("files", {}).get(rel_path)
        if data is None:
            return None
        return FileContext.from_dict(data)

    def all_files(self) -> list[str]:
        """Return all tracked relative file paths."""
        return list(self._raw.get("files", {}).keys())