"""
pisces.models
~~~~~~~~~~~~~
All shared data models for pisces.

Rule: every other module imports FROM here. Nothing in here imports
from other pisces modules. This prevents circular imports.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────
# Severity
# ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """
    Security finding severity levels.

    Inherits from str so Severity.HIGH == "HIGH" works,
    and JSON serialisation is automatic.
    """
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls(value.upper())
        except ValueError:
            return cls.INFO

    def __lt__(self, other: "Severity") -> bool:
        _order = {
            Severity.CRITICAL: 0,
            Severity.HIGH:     1,
            Severity.MEDIUM:   2,
            Severity.LOW:      3,
            Severity.INFO:     4,
        }
        return _order[self] < _order[other]


# ─────────────────────────────────────────────────────────────
# Repair state machine
# ─────────────────────────────────────────────────────────────

class RepairState(str, Enum):
    """
    Lifecycle states of a single repair attempt.

    DETECTED → EXPLAINED → PROPOSED → JUDGED → AWAITING_APPROVAL
    → APPROVED → CHECKPOINTED → APPLIED → VALIDATING
    → SUCCEEDED  (terminal ✓)
    → FAILED → HEALING → PROPOSED  (retry loop)
    → ROLLED_BACK  (terminal, all attempts exhausted)
    → REJECTED     (terminal, human said N)
    """
    DETECTED          = "DETECTED"
    EXPLAINED         = "EXPLAINED"
    PROPOSED          = "PROPOSED"
    JUDGED            = "JUDGED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED          = "APPROVED"
    CHECKPOINTED      = "CHECKPOINTED"
    APPLIED           = "APPLIED"
    VALIDATING        = "VALIDATING"
    SUCCEEDED         = "SUCCEEDED"
    FAILED            = "FAILED"
    HEALING           = "HEALING"
    REJECTED          = "REJECTED"
    ROLLED_BACK       = "ROLLED_BACK"


# ─────────────────────────────────────────────────────────────
# AST-extracted file intelligence
# ─────────────────────────────────────────────────────────────

@dataclass
class FunctionInfo:
    """Information extracted from a function definition."""
    name:        str
    line_start:  int
    line_end:    int
    is_async:    bool                = False
    decorators:  list[str]           = field(default_factory=list)
    calls:       list[str]           = field(default_factory=list)   # function names called inside
    args:        list[str]           = field(default_factory=list)   # parameter names
    docstring:   Optional[str]       = None


@dataclass
class ClassInfo:
    """Information extracted from a class definition."""
    name:       str
    line_start: int
    line_end:   int
    bases:      list[str]            = field(default_factory=list)
    methods:    list[str]            = field(default_factory=list)
    decorators: list[str]            = field(default_factory=list)


@dataclass
class ImportInfo:
    """A single import statement."""
    module:    str          # e.g. "os.path" or "subprocess"
    names:     list[str]    # e.g. ["run", "Popen"] or ["*"]
    line:      int
    is_from:   bool = False  # True = "from X import Y"


@dataclass
class SecurityConstruct:
    """
    A security-relevant code construct spotted during AST analysis.
    Not a full finding — just a hint for the scanner.
    """
    kind:     str    # e.g. "subprocess_call", "pickle_load", "eval_call"
    line:     int
    code:     str    # source snippet (best-effort)
    details:  str = ""


@dataclass
class FileContext:
    """
    Serialised intelligence for a single Python file.
    Stored as one entry in context.json["files"].
    """
    path:                str                        # relative to project root
    hash:                str                        # SHA-256 hex digest
    functions:           list[FunctionInfo]         = field(default_factory=list)
    classes:             list[ClassInfo]            = field(default_factory=list)
    imports:             list[ImportInfo]            = field(default_factory=list)
    calls:               list[str]                  = field(default_factory=list)
    security_constructs: list[SecurityConstruct]   = field(default_factory=list)
    parse_error:         Optional[str]             = None   # set if AST failed

    def to_dict(self) -> dict:
        return {
            "path":   self.path,
            "hash":   self.hash,
            "functions": [
                {
                    "name":        f.name,
                    "line_start":  f.line_start,
                    "line_end":    f.line_end,
                    "is_async":    f.is_async,
                    "decorators":  f.decorators,
                    "calls":       f.calls,
                    "args":        f.args,
                    "docstring":   f.docstring,
                }
                for f in self.functions
            ],
            "classes": [
                {
                    "name":       c.name,
                    "line_start": c.line_start,
                    "line_end":   c.line_end,
                    "bases":      c.bases,
                    "methods":    c.methods,
                    "decorators": c.decorators,
                }
                for c in self.classes
            ],
            "imports": [
                {
                    "module":  i.module,
                    "names":   i.names,
                    "line":    i.line,
                    "is_from": i.is_from,
                }
                for i in self.imports
            ],
            "calls":               self.calls,
            "security_constructs": [
                {
                    "kind":    s.kind,
                    "line":    s.line,
                    "code":    s.code,
                    "details": s.details,
                }
                for s in self.security_constructs
            ],
            "parse_error": self.parse_error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FileContext":
        fc = cls(path=data["path"], hash=data["hash"])
        fc.functions = [
            FunctionInfo(
                name=f["name"],
                line_start=f["line_start"],
                line_end=f["line_end"],
                is_async=f.get("is_async", False),
                decorators=f.get("decorators", []),
                calls=f.get("calls", []),
                args=f.get("args", []),
                docstring=f.get("docstring"),
            )
            for f in data.get("functions", [])
        ]
        fc.classes = [
            ClassInfo(
                name=c["name"],
                line_start=c["line_start"],
                line_end=c["line_end"],
                bases=c.get("bases", []),
                methods=c.get("methods", []),
                decorators=c.get("decorators", []),
            )
            for c in data.get("classes", [])
        ]
        fc.imports = [
            ImportInfo(
                module=i["module"],
                names=i["names"],
                line=i["line"],
                is_from=i.get("is_from", False),
            )
            for i in data.get("imports", [])
        ]
        fc.calls = data.get("calls", [])
        fc.security_constructs = [
            SecurityConstruct(
                kind=s["kind"],
                line=s["line"],
                code=s["code"],
                details=s.get("details", ""),
            )
            for s in data.get("security_constructs", [])
        ]
        fc.parse_error = data.get("parse_error")
        return fc


# ─────────────────────────────────────────────────────────────
# Finding (security scanner output)
# ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    A single security finding produced by the scanner.

    id          — unique, stable identifier: "<rule>:<file>:<line>"
    rule        — rule name, e.g. "HARDCODED_SECRET"
    severity    — Severity enum value
    file        — relative path to the file
    line        — line number (1-indexed)
    code        — the offending source line(s)
    description — short one-line description
    impact      — why this matters
    remediation — what to do about it
    """
    rule:         str
    severity:     Severity
    file:         str
    line:         int
    code:         str
    description:  str
    impact:       str        = ""
    remediation:  str        = ""
    id:           str        = field(default_factory=lambda: "")

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"{self.rule}:{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "rule":        self.rule,
            "severity":    self.severity.value,
            "file":        self.file,
            "line":        self.line,
            "code":        self.code,
            "description": self.description,
            "impact":      self.impact,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(
            id=data.get("id", ""),
            rule=data["rule"],
            severity=Severity.from_str(data["severity"]),
            file=data["file"],
            line=data["line"],
            code=data["code"],
            description=data["description"],
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
        )


# ─────────────────────────────────────────────────────────────
# LLM request / response
# ─────────────────────────────────────────────────────────────

@dataclass
class LLMRequest:
    system_prompt: str
    user_prompt:   str
    temperature:   float = 0.2   # low temp for deterministic patches
    max_tokens:    int   = 4096


@dataclass
class LLMResponse:
    content:      str
    model:        str
    provider:     str
    input_tokens: int = 0
    output_tokens: int = 0


# ─────────────────────────────────────────────────────────────
# Judge result
# ─────────────────────────────────────────────────────────────

@dataclass
class JudgeResult:
    decision:          str    # "APPROVED" | "REJECTED"
    security_ok:       bool
    functionality_ok:  bool
    scope_ok:          bool
    regression_risk:   str    # "LOW" | "MEDIUM" | "HIGH"
    patch_quality:     str    # "GOOD" | "ACCEPTABLE" | "POOR"
    completeness:      str    # "COMPLETE" | "PARTIAL" | "INCOMPLETE"
    reasoning:         str

    @property
    def approved(self) -> bool:
        return self.decision.upper() == "APPROVED"

    def to_dict(self) -> dict:
        return {
            "decision":         self.decision,
            "security_ok":      self.security_ok,
            "functionality_ok": self.functionality_ok,
            "scope_ok":         self.scope_ok,
            "regression_risk":  self.regression_risk,
            "patch_quality":    self.patch_quality,
            "completeness":     self.completeness,
            "reasoning":        self.reasoning,
        }


# ─────────────────────────────────────────────────────────────
# Repair record (history entry)
# ─────────────────────────────────────────────────────────────

@dataclass
class RepairRecord:
    """Stored in .pisces/history/<repair_id>/metadata.json"""
    repair_id:      str                = field(default_factory=lambda: str(uuid.uuid4())[:8])
    state:          RepairState        = RepairState.DETECTED
    finding_id:     str                = ""
    file:           str                = ""
    rule:           str                = ""
    severity:       str                = Severity.HIGH.value
    provider:       str                = ""
    model:          str                = ""
    judge_result:   Optional[dict]     = None
    human_approved: Optional[bool]     = None
    attempts:       int                = 0
    started_at:     str                = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at:    Optional[str]      = None

    def to_dict(self) -> dict:
        return {
            "repair_id":     self.repair_id,
            "state":         self.state.value,
            "finding_id":    self.finding_id,
            "file":          self.file,
            "rule":          self.rule,
            "severity":      self.severity,
            "provider":      self.provider,
            "model":         self.model,
            "judge_result":  self.judge_result,
            "human_approved": self.human_approved,
            "attempts":      self.attempts,
            "started_at":    self.started_at,
            "finished_at":   self.finished_at,
        }