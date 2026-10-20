"""
Tests for pisces.scanner — all 7 security rules, both AST and regex paths.

Structure per rule:
    - test_detects_<rule>     — vulnerable code → finding produced
    - test_ignores_safe_<rule> — clean code    → no finding produced
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from pisces.scanner import Scanner

scanner = Scanner()


def _scan(tmp_path: Path, source: str) -> list:
    """Write source to a temp .py file and scan it."""
    f = tmp_path / "test_target.py"
    f.write_text(textwrap.dedent(source), encoding="utf-8")
    return scanner.scan_file(f, project_root=tmp_path, source=textwrap.dedent(source))


def _rules(findings: list) -> set[str]:
    return {f.rule for f in findings}


# ─────────────────────────────────────────────────────────────
# S001 — Hardcoded Secret
# ─────────────────────────────────────────────────────────────

class TestHardcodedSecret:
    def test_detects_api_key_literal(self, tmp_path):
        findings = _scan(tmp_path, """
            api_key = "sk-proj-abc123defghijk"
        """)
        assert any("S001" in f.rule for f in findings)

    def test_detects_password_assignment(self, tmp_path):
        findings = _scan(tmp_path, """
            password = "correct-horse-battery-staple"
        """)
        assert any("S001" in f.rule for f in findings)

    def test_ignores_env_var_lookup(self, tmp_path):
        findings = _scan(tmp_path, """
            import os
            api_key = os.environ.get("OPENAI_API_KEY")
        """)
        assert not any("S001" in f.rule for f in findings)

    def test_ignores_placeholder_value(self, tmp_path):
        findings = _scan(tmp_path, """
            password = "changeme"
        """)
        assert not any("S001" in f.rule for f in findings)

    def test_ignores_short_value(self, tmp_path):
        findings = _scan(tmp_path, """
            api_key = "key"
        """)
        assert not any("S001" in f.rule for f in findings)


# ─────────────────────────────────────────────────────────────
# S002 — Command Injection
# ─────────────────────────────────────────────────────────────

class TestCommandInjection:
    def test_detects_fstring_shell_true(self, tmp_path):
        findings = _scan(tmp_path, """
            import subprocess
            def run(user_input):
                subprocess.run(f"ls {user_input}", shell=True)
        """)
        assert any("S002" in f.rule for f in findings)

    def test_detects_os_system_with_variable(self, tmp_path):
        findings = _scan(tmp_path, """
            import os
            def run(cmd):
                os.system(cmd)
        """)
        assert any("S002" in f.rule for f in findings)

    def test_detects_string_concat_shell_true(self, tmp_path):
        findings = _scan(tmp_path, """
            import subprocess
            def run(path):
                subprocess.run("ls " + path, shell=True)
        """)
        assert any("S002" in f.rule for f in findings)

    def test_ignores_list_args_no_shell(self, tmp_path):
        findings = _scan(tmp_path, """
            import subprocess
            def run(path):
                subprocess.run(["ls", path], shell=False)
        """)
        assert not any("S002" in f.rule for f in findings)


# ─────────────────────────────────────────────────────────────
# S003 — Unsafe Subprocess (shell=True with static string)
# ─────────────────────────────────────────────────────────────

class TestUnsafeSubprocess:
    def test_detects_shell_true_static_string(self, tmp_path):
        findings = _scan(tmp_path, """
            import subprocess
            subprocess.run("ls -la", shell=True)
        """)
        # May be S002 or S003 depending on argument type
        assert any(f.rule.startswith("S00") for f in findings)

    def test_ignores_shell_false(self, tmp_path):
        findings = _scan(tmp_path, """
            import subprocess
            subprocess.run(["ls", "-la"], shell=False)
        """)
        assert not any("S003" in f.rule for f in findings)


# ─────────────────────────────────────────────────────────────
# S004 — Unsafe Deserialization
# ─────────────────────────────────────────────────────────────

class TestUnsafeDeserialization:
    def test_detects_pickle_load(self, tmp_path):
        findings = _scan(tmp_path, """
            import pickle
            def load(f):
                return pickle.load(f)
        """)
        assert any("S004" in f.rule for f in findings)

    def test_detects_pickle_loads(self, tmp_path):
        findings = _scan(tmp_path, """
            import pickle
            data = pickle.loads(b"...")
        """)
        assert any("S004" in f.rule for f in findings)

    def test_detects_yaml_load_without_safe_loader(self, tmp_path):
        findings = _scan(tmp_path, """
            import yaml
            data = yaml.load(stream)
        """)
        assert any("S004" in f.rule for f in findings)

    def test_ignores_yaml_safe_load(self, tmp_path):
        findings = _scan(tmp_path, """
            import yaml
            data = yaml.safe_load(stream)
        """)
        assert not any("S004" in f.rule for f in findings)

    def test_ignores_json_load(self, tmp_path):
        findings = _scan(tmp_path, """
            import json
            with open("data.json") as f:
                data = json.load(f)
        """)
        assert not any("S004" in f.rule for f in findings)


# ─────────────────────────────────────────────────────────────
# S005 — TLS Verify Disabled
# ─────────────────────────────────────────────────────────────

class TestTLSVerifyDisabled:
    def test_detects_requests_verify_false(self, tmp_path):
        findings = _scan(tmp_path, """
            import requests
            r = requests.get("https://example.com", verify=False)
        """)
        assert any("S005" in f.rule for f in findings)

    def test_ignores_verify_true(self, tmp_path):
        findings = _scan(tmp_path, """
            import requests
            r = requests.get("https://example.com", verify=True)
        """)
        assert not any("S005" in f.rule for f in findings)

    def test_ignores_no_verify_kwarg(self, tmp_path):
        findings = _scan(tmp_path, """
            import requests
            r = requests.get("https://example.com")
        """)
        assert not any("S005" in f.rule for f in findings)


# ─────────────────────────────────────────────────────────────
# S006 — Code Injection (eval/exec)
# ─────────────────────────────────────────────────────────────

class TestCodeInjection:
    def test_detects_eval_with_variable(self, tmp_path):
        findings = _scan(tmp_path, """
            def compute(expr):
                return eval(expr)
        """)
        assert any("S006" in f.rule for f in findings)

    def test_detects_exec_with_variable(self, tmp_path):
        findings = _scan(tmp_path, """
            def run_code(code_str):
                exec(code_str)
        """)
        assert any("S006" in f.rule for f in findings)

    def test_ignores_eval_with_literal(self, tmp_path):
        # eval("1 + 1") — static literal, no injection opportunity
        findings = _scan(tmp_path, """
            result = eval("1 + 1")
        """)
        assert not any("S006" in f.rule for f in findings)

    def test_ignores_ast_literal_eval(self, tmp_path):
        findings = _scan(tmp_path, """
            import ast
            data = ast.literal_eval(user_input)
        """)
        assert not any("S006" in f.rule for f in findings)


# ─────────────────────────────────────────────────────────────
# S007 — Dangerous Filesystem
# ─────────────────────────────────────────────────────────────

class TestDangerousFilesystem:
    def test_detects_rmtree_with_variable(self, tmp_path):
        findings = _scan(tmp_path, """
            import shutil
            def clean(path):
                shutil.rmtree(path)
        """)
        assert any("S007" in f.rule for f in findings)

    def test_ignores_rmtree_with_literal(self, tmp_path):
        findings = _scan(tmp_path, """
            import shutil
            shutil.rmtree("/tmp/build_artifacts")
        """)
        # Literal path — no finding
        assert not any("S007" in f.rule for f in findings)


# ─────────────────────────────────────────────────────────────
# Scanner-level: deduplication and full scan
# ─────────────────────────────────────────────────────────────

class TestScannerDeduplication:
    def test_no_duplicate_findings(self, tmp_path, vuln_file):
        findings = scanner.scan_file(vuln_file, project_root=tmp_path)
        ids = [(f.rule, f.file, f.line) for f in findings]
        assert len(ids) == len(set(ids)), "Duplicate findings detected"

    def test_clean_file_produces_no_findings(self, tmp_path, clean_file):
        findings = scanner.scan_file(clean_file, project_root=tmp_path)
        assert findings == []

    def test_scan_project_aggregates(self, tmp_path, vuln_file, clean_file):
        findings = scanner.scan_project(tmp_path, [vuln_file, clean_file])
        # vuln_file has findings, clean_file has none
        assert len(findings) > 0
        file_names = {f.file for f in findings}
        assert "vuln.py" in file_names
        assert "clean.py" not in file_names
