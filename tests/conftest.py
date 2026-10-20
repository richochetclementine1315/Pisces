"""
conftest.py — Shared pytest fixtures for pisces tests.

Key fixtures:
    project_root   — tmp_path initialised as a real pisces project
    vuln_file      — a .py file with known vulnerabilities
    clean_file     — a .py file with no vulnerabilities
    pisces_toml    — a minimal pisces.toml in tmp_path
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

# ─────────────────────────────────────────────────────────────
# Project skeleton fixtures
# ─────────────────────────────────────────────────────────────


@pytest.fixture
def pisces_toml(tmp_path: Path) -> Path:
    """Write a minimal pisces.toml to tmp_path and return its path."""
    toml = tmp_path / "pisces.toml"
    toml.write_text(
        textwrap.dedent("""\
            [llm]
            provider = "groq"
            model    = "llama-3.3-70b-versatile"

            [repair]
            max_attempts     = 3
            require_approval = true

            [validation]
            test_command = "pytest"

            [scan]
            exclude = [".git", ".venv", "__pycache__", ".pisces"]
        """),
        encoding="utf-8",
    )
    return toml


@pytest.fixture
def project_root(tmp_path: Path, pisces_toml: Path) -> Path:
    """
    A tmp_path that looks like an initialised pisces project.
    Contains pisces.toml and the .pisces/ state directory.
    """
    pisces_dir = tmp_path / ".pisces"
    (pisces_dir / "history").mkdir(parents=True)
    (pisces_dir / "cache").mkdir()
    (pisces_dir / "context.json").write_text(
        '{"schema_version": "1", "project": {"root": "."}, "files": {}}',
        encoding="utf-8",
    )
    return tmp_path


# ─────────────────────────────────────────────────────────────
# Source file fixtures
# ─────────────────────────────────────────────────────────────

VULN_SOURCE = textwrap.dedent("""\
    import subprocess
    import pickle
    import requests

    # S001: hardcoded secret
    api_key = "sk-super-secret-abc123"

    # S002: command injection
    def run_cmd(user_input):
        subprocess.run(f"ls {user_input}", shell=True)

    # S003: shell=True with static string
    def list_files():
        subprocess.run("ls -la", shell=True)

    # S004: unsafe deserialization
    def load_data(file_obj):
        return pickle.load(file_obj)

    # S005: TLS verification disabled
    def fetch(url):
        return requests.get(url, verify=False)

    # S006: code injection
    def eval_expr(expr):
        return eval(expr)
""")

CLEAN_SOURCE = textwrap.dedent("""\
    import subprocess
    import json
    import os

    def run_safe(cmd_list):
        # shell=False, arguments as list — correct
        return subprocess.run(cmd_list, shell=False, capture_output=True)

    def load_data(path):
        with open(path) as f:
            return json.load(f)   # JSON, not pickle

    def fetch(url, session):
        return session.get(url)   # no verify=False

    def parse_expr(s):
        import ast
        return ast.literal_eval(s)  # safe alternative to eval
""")


@pytest.fixture
def vuln_file(tmp_path: Path) -> Path:
    """A .py file containing known vulnerabilities."""
    p = tmp_path / "vuln.py"
    p.write_text(VULN_SOURCE, encoding="utf-8")
    return p


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    """A .py file with no known vulnerabilities."""
    p = tmp_path / "clean.py"
    p.write_text(CLEAN_SOURCE, encoding="utf-8")
    return p
