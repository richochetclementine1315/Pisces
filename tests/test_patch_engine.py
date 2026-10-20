"""Tests for pisces.patch_engine — extract, validate, apply, rollback."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from pisces.patch_engine import (
    PATCH_END,
    PATCH_START,
    apply_patch,
    checkpoint_file,
    extract_patch_code,
    locate_function_lines,
    rollback,
    validate_patch_syntax,
)

# ─────────────────────────────────────────────────────────────
# extract_patch_code
# ─────────────────────────────────────────────────────────────

class TestExtractPatchCode:
    def test_marker_based_extraction(self):
        llm_output = (
            f"Here is the fix:\n{PATCH_START}\ndef safe():\n    pass\n{PATCH_END}\nDone."
        )
        code = extract_patch_code(llm_output)
        assert code is not None
        assert "def safe():" in code

    def test_fallback_to_python_fence(self):
        llm_output = "Here:\n```python\ndef safe():\n    pass\n```\nDone."
        code = extract_patch_code(llm_output)
        assert code is not None
        assert "def safe():" in code

    def test_returns_none_when_no_marker_and_no_fence(self):
        code = extract_patch_code("No patch here, just explanation text.")
        assert code is None

    def test_strips_inner_fence_from_marker_block(self):
        llm_output = f"{PATCH_START}\n```python\ndef fn(): pass\n```\n{PATCH_END}"
        code = extract_patch_code(llm_output)
        assert "```" not in code


# ─────────────────────────────────────────────────────────────
# validate_patch_syntax
# ─────────────────────────────────────────────────────────────

class TestValidatePatchSyntax:
    def test_valid_python_returns_true(self):
        ok, err = validate_patch_syntax("def f():\n    return 42\n")
        assert ok is True
        assert err == ""

    def test_syntax_error_returns_false(self):
        ok, err = validate_patch_syntax("def f(\n    broken syntax here @@@")
        assert ok is False
        assert err != ""

    def test_empty_string_is_valid(self):
        ok, _ = validate_patch_syntax("")
        assert ok is True


# ─────────────────────────────────────────────────────────────
# locate_function_lines
# ─────────────────────────────────────────────────────────────

class TestLocateFunctionLines:
    def _write(self, tmp_path: Path, source: str) -> Path:
        p = tmp_path / "src.py"
        p.write_text(textwrap.dedent(source), encoding="utf-8")
        return p

    def test_finds_enclosing_function(self, tmp_path):
        p = self._write(tmp_path, """\
            def greet(name):
                print(name)
                return name
        """)
        start, end = locate_function_lines(p, finding_line=2)
        assert start == 1
        assert end   == 3

    def test_no_enclosing_function_returns_finding_line(self, tmp_path):
        p = self._write(tmp_path, """\
            import os
            x = os.system("ls")
        """)
        start, end = locate_function_lines(p, finding_line=2)
        assert start == 2
        assert end   == 2

    def test_nested_function_prefers_innermost(self, tmp_path):
        p = self._write(tmp_path, """\
            def outer():
                def inner():
                    return eval(x)
                return inner()
        """)
        start, end = locate_function_lines(p, finding_line=3)
        # Should locate inner(), not outer()
        assert start == 2
        assert end   == 3


# ─────────────────────────────────────────────────────────────
# apply_patch
# ─────────────────────────────────────────────────────────────

class TestApplyPatch:
    def test_replaces_lines_correctly(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("line1\nline2\nline3\nline4\n", encoding="utf-8")

        apply_patch(src, "REPLACED\n", line_start=2, line_end=3)

        content = src.read_text()
        assert "line1"    in content
        assert "REPLACED" in content
        assert "line4"    in content
        assert "line2"    not in content  # replaced

    def test_raises_on_invalid_python(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def f():\n    return 1\n", encoding="utf-8")

        with pytest.raises(ValueError, match="syntax error"):
            apply_patch(src, "def f(:\n    broken @@\n", line_start=1, line_end=2)

    def test_atomic_write_no_tmp_left_on_success(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("x = 1\n", encoding="utf-8")
        apply_patch(src, "x = 2\n", line_start=1, line_end=1)

        assert not (tmp_path / "app.py.tmp").exists()
        assert src.read_text() == "x = 2\n"


# ─────────────────────────────────────────────────────────────
# checkpoint + rollback
# ─────────────────────────────────────────────────────────────

class TestCheckpointRollback:
    def test_checkpoint_creates_copy(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("original content\n", encoding="utf-8")

        checkpoint = checkpoint_file(src, tmp_path, repair_id="test01")

        assert checkpoint.exists()
        assert checkpoint.read_text() == "original content\n"

    def test_rollback_restores_original(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("original\n", encoding="utf-8")

        checkpoint = checkpoint_file(src, tmp_path, repair_id="test02")

        # Simulate a bad patch
        src.write_text("broken buggy code\n", encoding="utf-8")
        assert src.read_text() == "broken buggy code\n"

        rollback(src, checkpoint)

        assert src.read_text() == "original\n"
