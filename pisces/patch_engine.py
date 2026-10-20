"""
pisces.patch_engine
~~~~~~~~~~~~~~~~~~~
Handles patch parsing, application, checkpointing, and rollback.

The patch format pisces uses is a "block replacement":
    The LLM outputs a function (or set of lines) to replace.
    We locate the old function boundaries via AST, then do a line-range
    swap. This is far more reliable than applying unified diffs.

Atomicity guarantee:
    1. Checkpoint  — copy file to .pisces/history/<id>/original.py
    2. Write       — write new content to file.py.tmp
    3. Rename      — file.py.tmp → file.py  (atomic on most OSes)
    4. Rollback    — if anything fails, copy original.py → file.py
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

from pisces.tui import print_step_fail, print_step_ok, print_step_running, print_warning

# ─────────────────────────────────────────────────────────────
# LLM patch output format
# ─────────────────────────────────────────────────────────────

# The fix prompt asks the LLM to wrap patched code in these markers:
PATCH_START = "<<<PISCES_PATCH_START>>>"
PATCH_END = "<<<PISCES_PATCH_END>>>"


# ─────────────────────────────────────────────────────────────
# Patch extraction from LLM response
# ─────────────────────────────────────────────────────────────


def extract_patch_code(llm_response: str) -> str | None:
    """
    Extract the patched code block from the LLM response.

    Looks for text between PATCH_START and PATCH_END markers.
    Falls back to extracting the first ```python ... ``` code block.

    Returns the code string, or None if no patch found.
    """
    # Primary: marker-based extraction
    if PATCH_START in llm_response and PATCH_END in llm_response:
        start = llm_response.index(PATCH_START) + len(PATCH_START)
        end = llm_response.index(PATCH_END)
        code = llm_response[start:end].strip()
        # Strip any accidental ```python fences inside the markers
        code = _strip_fences(code)
        return code if code else None

    # Fallback: first ```python block
    import re

    pattern = re.compile(r"```python\s*\n(.*?)```", re.DOTALL)
    match = pattern.search(llm_response)
    if match:
        return match.group(1).strip()

    return None


def _strip_fences(code: str) -> str:
    """Remove leading/trailing ``` fences from a code block."""
    lines = code.strip().splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Patch validation — is the replacement valid Python?
# ─────────────────────────────────────────────────────────────


def validate_patch_syntax(patch_code: str) -> tuple[bool, str]:
    """
    Return (ok, error_message).
    Tries to parse the patch_code as Python and reports any SyntaxError.
    """
    try:
        ast.parse(patch_code)
        return True, ""
    except SyntaxError as e:
        return False, f"SyntaxError at line {e.lineno}: {e.msg}"


# ─────────────────────────────────────────────────────────────
# Checkpoint — save original file before patching
# ─────────────────────────────────────────────────────────────


def checkpoint_file(
    file_path: Path,
    project_root: Path,
    repair_id: str,
) -> Path:
    """
    Copy *file_path* to .pisces/history/<repair_id>/original.py.

    Returns the path of the checkpoint copy.
    Raises OSError if the copy fails.
    """
    history_dir = project_root / ".pisces" / "history" / repair_id
    history_dir.mkdir(parents=True, exist_ok=True)

    checkpoint = history_dir / "original.py"
    shutil.copy2(file_path, checkpoint)
    print_step_ok(f"Checkpoint saved: [dim]{checkpoint.relative_to(project_root)}[/]")
    return checkpoint


def save_patch_record(
    project_root: Path,
    repair_id: str,
    finding_dict: dict,
    patch_code: str,
    judge_result_dict: dict | None,
    human_approved: bool | None,
    state: str,
) -> None:
    """Write metadata.json and patch.py to the repair history directory."""
    import json
    from datetime import datetime, timezone

    history_dir = project_root / ".pisces" / "history" / repair_id
    history_dir.mkdir(parents=True, exist_ok=True)

    # patch.py — the actual replacement code
    (history_dir / "patch.py").write_text(patch_code, encoding="utf-8")

    # metadata.json
    meta = {
        "repair_id": repair_id,
        "state": state,
        "finding": finding_dict,
        "judge_result": judge_result_dict,
        "human_approved": human_approved,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (history_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


# ─────────────────────────────────────────────────────────────
# Patch application — line-range swap
# ─────────────────────────────────────────────────────────────


def locate_function_lines(
    file_path: Path,
    finding_line: int,
) -> tuple[int, int]:
    """
    Return (line_start, line_end) of the function that *contains* finding_line.

    If no enclosing function is found, returns (finding_line, finding_line)
    — we still patch just that one line.

    Uses AST for accuracy (accounts for decorators, nested functions, etc.)
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return finding_line, finding_line

    best: tuple[int, int] | None = None
    best_size = float("inf")

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.lineno
        end = node.end_lineno or node.lineno
        if start <= finding_line <= end:
            size = end - start
            if size < best_size:
                best_size = size
                best = (start, end)

    return best if best else (finding_line, finding_line)


def apply_patch(
    file_path: Path,
    patch_code: str,
    line_start: int,
    line_end: int,
) -> None:
    """
    Replace lines [line_start, line_end] (1-indexed, inclusive) in *file_path*
    with *patch_code*, atomically via a .tmp file.

    Raises:
        OSError      — file read/write failure
        ValueError   — patch would produce invalid Python
    """
    # Read current file
    original_lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)

    # Preserve leading indentation of the original block
    # (the replaced block may be inside a class — keep its indentation)
    original_block_indent = ""
    if line_start <= len(original_lines):
        first_original = original_lines[line_start - 1]
        original_block_indent = first_original[: len(first_original) - len(first_original.lstrip())]

    # Re-indent the patch_code to match the original indentation
    patch_lines = patch_code.splitlines(keepends=True)
    first_patch = patch_lines[0] if patch_lines else ""
    patch_indent = first_patch[: len(first_patch) - len(first_patch.lstrip())]

    if patch_indent != original_block_indent:
        # Adjust: strip patch's own leading indent, add original's
        adjusted = []
        for pl in patch_lines:
            stripped = pl.removeprefix(patch_indent)
            adjusted.append(original_block_indent + stripped)
        patch_lines = adjusted

    # Assemble new file content
    before = original_lines[: line_start - 1]
    after = original_lines[line_end:]
    new_content = "".join(before + patch_lines + after)

    # Validate the new file as a whole
    valid, err = validate_patch_syntax(new_content)
    if not valid:
        raise ValueError(f"Patched file has a syntax error: {err}")

    # Atomic write via .tmp
    tmp_path = file_path.with_suffix(".py.tmp")
    try:
        tmp_path.write_text(new_content, encoding="utf-8")
        tmp_path.replace(file_path)
    except OSError:
        tmp_path.unlink(missing_ok=True)
        raise

    print_step_ok(
        f"Patch applied to [cyan]{file_path.name}[/] (replaced lines {line_start}–{line_end})"
    )


# ─────────────────────────────────────────────────────────────
# Rollback
# ─────────────────────────────────────────────────────────────


def rollback(file_path: Path, checkpoint: Path) -> None:
    """Restore *file_path* from the checkpoint copy."""
    print_step_running(f"Rolling back [cyan]{file_path.name}[/] ...")
    try:
        shutil.copy2(checkpoint, file_path)
        print_step_ok("Rollback complete — original file restored")
    except OSError as e:
        print_step_fail(f"Rollback FAILED: {e} — manual recovery needed!")
        print_warning(f"Checkpoint is at: {checkpoint}")
