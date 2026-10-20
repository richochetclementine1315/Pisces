"""Tests for pisces.models — dataclasses, Severity ordering, serialisation."""
from __future__ import annotations

import pytest

from pisces.models import (
    FileContext,
    Finding,
    FunctionInfo,
    ImportInfo,
    JudgeResult,
    RepairRecord,
    RepairState,
    Severity,
)


class TestSeverity:
    def test_from_str_valid(self):
        assert Severity.from_str("critical") == Severity.CRITICAL
        assert Severity.from_str("HIGH")     == Severity.HIGH
        assert Severity.from_str("medium")   == Severity.MEDIUM

    def test_from_str_invalid_falls_back_to_info(self):
        assert Severity.from_str("unknown") == Severity.INFO
        assert Severity.from_str("")        == Severity.INFO

    def test_ordering_critical_is_highest(self):
        assert Severity.CRITICAL < Severity.HIGH
        assert Severity.HIGH     < Severity.MEDIUM
        assert Severity.MEDIUM   < Severity.LOW
        assert Severity.LOW      < Severity.INFO

    def test_str_equality(self):
        # str(Enum) works because Severity inherits from str
        assert Severity.HIGH == "HIGH"
        assert Severity.CRITICAL == "CRITICAL"

    def test_sort_severities(self):
        unsorted = [Severity.LOW, Severity.CRITICAL, Severity.HIGH, Severity.INFO]
        assert sorted(unsorted)[0] == Severity.CRITICAL


class TestFinding:
    def test_auto_id_generation(self):
        f = Finding(
            rule="S001_HARDCODED_SECRET",
            severity=Severity.HIGH,
            file="auth.py",
            line=10,
            code="password = 'secret'",
            description="Hardcoded secret",
        )
        assert f.id == "S001_HARDCODED_SECRET:auth.py:10"

    def test_explicit_id_not_overridden(self):
        f = Finding(
            id="custom_id",
            rule="S001_HARDCODED_SECRET",
            severity=Severity.HIGH,
            file="auth.py",
            line=10,
            code="x = 1",
            description="test",
        )
        assert f.id == "custom_id"

    def test_to_dict_round_trip(self):
        original = Finding(
            rule="S006_CODE_INJECTION",
            severity=Severity.CRITICAL,
            file="app.py",
            line=42,
            code="eval(user_input)",
            description="eval() with dynamic arg",
            impact="RCE",
            remediation="Use ast.literal_eval",
        )
        d = original.to_dict()
        restored = Finding.from_dict(d)

        assert restored.rule        == original.rule
        assert restored.severity    == original.severity
        assert restored.file        == original.file
        assert restored.line        == original.line
        assert restored.description == original.description

    def test_severity_preserved_as_enum_after_from_dict(self):
        f = Finding.from_dict({
            "id": "x", "rule": "S001", "severity": "HIGH",
            "file": "f.py", "line": 1, "code": "x",
            "description": "d",
        })
        assert isinstance(f.severity, Severity)
        assert f.severity == Severity.HIGH


class TestFileContext:
    def test_to_from_dict_round_trip(self):
        fc = FileContext(path="src/app.py", hash="abc123")
        fc.functions = [
            FunctionInfo(name="main", line_start=1, line_end=10, is_async=False)
        ]
        fc.imports = [
            ImportInfo(module="os", names=["os"], line=1, is_from=False)
        ]

        d       = fc.to_dict()
        restored = FileContext.from_dict(d)

        assert restored.path              == "src/app.py"
        assert restored.hash              == "abc123"
        assert len(restored.functions)    == 1
        assert restored.functions[0].name == "main"
        assert restored.imports[0].module == "os"

    def test_parse_error_preserved(self):
        fc = FileContext(path="bad.py", hash="xyz", parse_error="SyntaxError at line 1")
        d  = fc.to_dict()
        assert d["parse_error"] == "SyntaxError at line 1"


class TestJudgeResult:
    def test_approved_property(self):
        j = JudgeResult(
            decision="APPROVED", security_ok=True, functionality_ok=True,
            scope_ok=True, regression_risk="LOW", patch_quality="GOOD",
            completeness="COMPLETE", reasoning="Looks good.",
        )
        assert j.approved is True

    def test_rejected_property(self):
        j = JudgeResult(
            decision="REJECTED", security_ok=False, functionality_ok=True,
            scope_ok=True, regression_risk="HIGH", patch_quality="POOR",
            completeness="INCOMPLETE", reasoning="Doesn't fix the issue.",
        )
        assert j.approved is False
        assert j.to_dict()["decision"] == "REJECTED"


class TestRepairRecord:
    def test_defaults(self):
        r = RepairRecord()
        assert r.state    == RepairState.DETECTED
        assert r.attempts == 0
        assert len(r.repair_id) == 8  # uuid4()[:8]

    def test_to_dict_state_is_string(self):
        r = RepairRecord(state=RepairState.SUCCEEDED)
        d = r.to_dict()
        assert d["state"] == "SUCCEEDED"
        assert isinstance(d["state"], str)
