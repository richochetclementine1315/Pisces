"""Tests for pisces.context_manager — discovery, hashing, incremental updates."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from pisces.context_manager import (
    ContextManager,
    discover_python_files,
    hash_file,
)


class TestDiscoverPythonFiles:
    def test_finds_py_files_recursively(self, tmp_path):
        (tmp_path / "a.py").write_text("x=1")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.py").write_text("y=2")
        (tmp_path / "sub" / "c.txt").write_text("not python")

        files = discover_python_files(tmp_path)
        names = {f.name for f in files}

        assert "a.py" in names
        assert "b.py" in names
        assert "c.txt" not in names

    def test_excludes_default_dirs(self, tmp_path):
        excluded = [".venv", "__pycache__", ".git", "node_modules"]
        for d in excluded:
            d_path = tmp_path / d
            d_path.mkdir()
            (d_path / "secret.py").write_text("x=1")

        (tmp_path / "real.py").write_text("x=1")
        files = discover_python_files(tmp_path)

        assert all(f.name == "real.py" for f in files)

    
    def test_extra_excludes_respected(self, tmp_path):
         build_dir = tmp_path / "build"
         build_dir.mkdir()

         (build_dir / "out.py").write_text(
           "x = 1\n",
           encoding="utf-8",
        )
         (tmp_path / "main.py").write_text(
           "x = 1\n",
           encoding="utf-8",
        )

         files = discover_python_files(
            tmp_path,
            extra_excludes=["build"],
        )
         names = {f.name for f in files}

         assert "out.py" not in names
         assert "main.py" in names


    def test_returns_sorted_list(self, tmp_path):
        for name in ["z.py", "a.py", "m.py"]:
            (tmp_path / name).write_text("")
        files = discover_python_files(tmp_path)
        names = [f.name for f in files]
        assert names == sorted(names)


class TestHashFile:
    def test_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("x = 1\n")
        f2.write_text("x = 1\n")
        assert hash_file(f1) == hash_file(f2)

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("x = 1\n")
        f2.write_text("x = 2\n")
        assert hash_file(f1) != hash_file(f2)

    def test_hash_is_64_char_hex(self, tmp_path):
        f = tmp_path / "f.py"
        f.write_text("print('hello')\n")
        h = hash_file(f)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestContextManager:
    def test_update_indexes_files(self, project_root):
        (project_root / "app.py").write_text("x = 1\n")
        (project_root / "utils.py").write_text("def helper(): pass\n")

        cm    = ContextManager(project_root)
        stats = cm.update(verbose=False)

        assert stats["discovered"] >= 2
        assert stats["updated"]    >= 2
        assert stats["errors"]     == 0

    def test_incremental_update_skips_unchanged(self, project_root):
        (project_root / "app.py").write_text("x = 1\n")

        cm = ContextManager(project_root)
        cm.update(verbose=False)

        # Second update — file unchanged → skipped
        stats2 = cm.update(verbose=False)
        assert stats2["skipped"] >= 1
        assert stats2["updated"] == 0

    def test_incremental_update_reparsed_on_change(self, project_root):
        f = project_root / "app.py"
        f.write_text("x = 1\n")

        cm = ContextManager(project_root)
        cm.update(verbose=False)

        # Modify the file
        time.sleep(0.01)
        f.write_text("x = 2\n")

        stats2 = cm.update(verbose=False)
        assert stats2["updated"] >= 1

    def test_deleted_file_removed_from_context(self, project_root):
        f = project_root / "temp.py"
        f.write_text("temp = True\n")

        cm = ContextManager(project_root)
        cm.update(verbose=False)

        # Delete the file
        f.unlink()

        cm.update(verbose=False)
        cm.load()
        assert cm.get_file_context("temp.py") is None

    def test_get_file_context_returns_none_for_unknown(self, project_root):
        cm = ContextManager(project_root)
        cm.load()
        assert cm.get_file_context("does_not_exist.py") is None

    def test_context_json_is_valid_after_update(self, project_root):
        (project_root / "x.py").write_text("a = 1\n")
        cm = ContextManager(project_root)
        cm.update(verbose=False)

        ctx_path = project_root / ".pisces" / "context.json"
        assert ctx_path.exists()
        data = json.loads(ctx_path.read_text())
        assert "files" in data
        assert "x.py"  in data["files"]

    def test_update_single_file_detects_change(self, project_root):
        f = project_root / "single.py"
        f.write_text("a = 1\n")

        cm = ContextManager(project_root)
        cm.update(verbose=False)

        f.write_text("a = 2\n")
        changed = cm.update_single_file(f)
        assert changed is True

    def test_update_single_file_no_change_returns_false(self, project_root):
        f = project_root / "single.py"
        f.write_text("a = 1\n")

        cm = ContextManager(project_root)
        cm.update(verbose=False)

        # No modification — hash is same
        changed = cm.update_single_file(f)
        assert changed is False
