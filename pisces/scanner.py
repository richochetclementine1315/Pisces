"""
pisces.scanner
~~~~~~~~~~~~~~
Deterministic security rule engine.

Rules:
    S001  HARDCODED_SECRET         — string literals assigned to secret-named vars
    S002  COMMAND_INJECTION        — shell=True with string formatting/concatenation
    S003  UNSAFE_SUBPROCESS        — any subprocess usage with shell=True
    S004  UNSAFE_DESERIALIZATION   — pickle/marshal/yaml.load without safe loader
    S005  TLS_VERIFY_DISABLED      — requests/httpx calls with verify=False
    S006  CODE_INJECTION           — eval()/exec() with non-literal arguments
    S007  DANGEROUS_FILESYSTEM     — shutil.rmtree / os.remove with variable paths

Design rules:
    - No LLM calls. Ever. This is pure static analysis.
    - AST-based checks preferred over regex.
    - Regex fallback when AST parse fails.
    - Every finding carries: id, rule, severity, file, line, code,
      description, impact, remediation.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional

from pisces.models import FileContext, Finding, Severity

# ─────────────────────────────────────────────────────────────
# Rule metadata registry
# ─────────────────────────────────────────────────────────────

RULE_META: dict[str, dict] = {
    "S001_HARDCODED_SECRET": {
        "severity":    Severity.HIGH,
        "description": "Hardcoded secret or credential in source code",
        "impact":      "Credentials exposed in version control or logs",
        "remediation": (
            "Move secrets to environment variables. "
            "Use os.environ.get('MY_SECRET') or a secrets manager."
        ),
    },
    "S002_COMMAND_INJECTION": {
        "severity":    Severity.CRITICAL,
        "description": "Potential command injection via shell=True with dynamic input",
        "impact":      "Attacker-controlled input may execute arbitrary OS commands",
        "remediation": (
            "Use shell=False (default) and pass arguments as a list: "
            "subprocess.run(['cmd', arg], shell=False). "
            "Never pass unsanitised user input to shell commands."
        ),
    },
    "S003_UNSAFE_SUBPROCESS": {
        "severity":    Severity.HIGH,
        "description": "subprocess call with shell=True",
        "impact":      "shell=True expands shell metacharacters — use only with trusted, static strings",
        "remediation": (
            "Replace shell=True with a list of arguments: "
            "subprocess.run(['cmd', '--flag', value], shell=False)"
        ),
    },
    "S004_UNSAFE_DESERIALIZATION": {
        "severity":    Severity.HIGH,
        "description": "Unsafe deserialization of untrusted data",
        "impact":      "Maliciously crafted data can execute arbitrary code during unpickling",
        "remediation": (
            "Never unpickle data from untrusted sources. "
            "Use JSON/msgpack for serialisation. "
            "For yaml.load, use yaml.safe_load(stream) instead."
        ),
    },
    "S005_TLS_VERIFY_DISABLED": {
        "severity":    Severity.MEDIUM,
        "description": "TLS certificate verification disabled (verify=False)",
        "impact":      "Disabling TLS verification allows man-in-the-middle attacks",
        "remediation": (
            "Remove verify=False. If using a self-signed cert, "
            "pass verify='/path/to/ca-bundle.crt' instead."
        ),
    },
    "S006_CODE_INJECTION": {
        "severity":    Severity.CRITICAL,
        "description": "eval() or exec() called with non-literal (potentially dynamic) argument",
        "impact":      "Dynamic code execution — arbitrary Python can be injected and executed",
        "remediation": (
            "Avoid eval()/exec() entirely. "
            "Use ast.literal_eval() for safe constant parsing, "
            "or restructure logic to remove dynamic execution."
        ),
    },
    "S007_DANGEROUS_FILESYSTEM": {
        "severity":    Severity.MEDIUM,
        "description": "Potentially dangerous filesystem operation with variable path",
        "impact":      "Path traversal or unintended deletion of files/directories",
        "remediation": (
            "Validate and sanitise paths before use. "
            "Use pathlib.Path.resolve() and check the result is within expected root. "
            "Prefer specific targeted operations over recursive deletes."
        ),
    },
}


# ─────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────

def _make_finding(
    rule_id: str,
    file: str,
    line: int,
    code: str,
    override_severity: Optional[Severity] = None,
) -> Finding:
    meta = RULE_META[rule_id]
    return Finding(
        rule=rule_id,
        severity=override_severity or meta["severity"],
        file=file,
        line=line,
        code=code.strip()[:200],
        description=meta["description"],
        impact=meta["impact"],
        remediation=meta["remediation"],
    )


def _source_line(source_lines: list[str], lineno: int) -> str:
    """Return the source line for a 1-indexed line number."""
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()
    return ""


def _is_literal(node: ast.AST) -> bool:
    """Return True if *node* is a compile-time constant (string/number/bytes)."""
    return isinstance(node, ast.Constant)


def _is_dynamic(node: ast.AST) -> bool:
    """Return True if *node* is not a pure literal (i.e. has runtime dependencies)."""
    return not _is_literal(node)


# ─────────────────────────────────────────────────────────────
# Rule: S001 — Hardcoded Secrets
# ─────────────────────────────────────────────────────────────

_SECRET_VAR_NAMES = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|auth_token|"
    r"access_token|private_key|secret_key|db_pass|database_pass|"
    r"credentials|credential|auth_secret|client_secret)",
    re.IGNORECASE,
)

# Regex for finding secret-like assignments when AST parse fails
_SECRET_REGEX = re.compile(
    r"""^\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>['"])(?P<val>.{3,}?)(?P=quote)""",
    re.MULTILINE,
)

# High-entropy string heuristic (skip very short or obviously placeholder values)
_PLACEHOLDER_VALUES = {
    "changeme", "password", "secret", "example", "test",
    "your_key_here", "xxx", "yyy", "zzz", "<your-key>", "",
    "placeholder", "todo", "fill-me-in",
}


def _looks_like_real_secret(value: str) -> bool:
    """Heuristic: is this string plausibly a real credential?"""
    v = value.strip()
    if len(v) < 4:
        return False
    if v.lower() in _PLACEHOLDER_VALUES:
        return False
    # Real secrets tend to have mixed chars or be long
    return True


def check_hardcoded_secrets_ast(
    tree: ast.AST, source_lines: list[str], rel_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        # Pattern: VAR = "string_literal"
        if not isinstance(node, ast.Assign):
            continue
        if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            continue
        value = node.value.value
        if not _looks_like_real_secret(value):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if _SECRET_VAR_NAMES.search(target.id):
                findings.append(_make_finding(
                    "S001_HARDCODED_SECRET",
                    rel_path,
                    node.lineno,
                    _source_line(source_lines, node.lineno),
                ))
    return findings


def check_hardcoded_secrets_regex(source: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _SECRET_REGEX.finditer(source):
        var   = m.group("var")
        value = m.group("val")
        line  = source[: m.start()].count("\n") + 1
        if _SECRET_VAR_NAMES.search(var) and _looks_like_real_secret(value):
            findings.append(_make_finding(
                "S001_HARDCODED_SECRET",
                rel_path,
                line,
                m.group(0).strip()[:200],
            ))
    return findings


# ─────────────────────────────────────────────────────────────
# Rule: S002/S003 — Command Injection / Unsafe Subprocess
# ─────────────────────────────────────────────────────────────

_SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
}


def _has_shell_true(call_node: ast.Call) -> bool:
    """Return True if the call has shell=True keyword argument."""
    for kw in call_node.keywords:
        if kw.arg == "shell":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
            # shell=True via variable — treat as potentially True
            if isinstance(kw.value, ast.Name):
                return True
    return False


def _first_arg_is_dynamic(call_node: ast.Call) -> bool:
    """Return True if the first arg is not a static string literal."""
    if not call_node.args:
        return False
    arg0 = call_node.args[0]
    # f-string, BinOp (string concat), Name (variable), etc.
    if isinstance(arg0, ast.JoinedStr):  # f"..."
        return True
    if isinstance(arg0, ast.BinOp):     # "cmd " + var
        return True
    if isinstance(arg0, ast.Name):      # variable
        return True
    if isinstance(arg0, ast.Call):      # format()/join()
        return True
    return False


def check_subprocess_ast(
    tree: ast.AST, source_lines: list[str], rel_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Resolve function name
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            fname = f"{func.value.id}.{func.attr}"
        elif isinstance(func, ast.Name):
            fname = func.id
        else:
            continue

        if fname not in _SUBPROCESS_FUNCS:
            # Also catch os.system / os.popen
            if fname in ("os.system", "os.popen"):
                code = _source_line(source_lines, node.lineno)
                # os.system is always shell=True effectively
                if node.args and _is_dynamic(node.args[0]):
                    findings.append(_make_finding(
                        "S002_COMMAND_INJECTION", rel_path, node.lineno, code
                    ))
                else:
                    findings.append(_make_finding(
                        "S003_UNSAFE_SUBPROCESS", rel_path, node.lineno, code
                    ))
            continue

        if not _has_shell_true(node):
            continue

        code = _source_line(source_lines, node.lineno)

        if _first_arg_is_dynamic(node):
            # shell=True + dynamic first arg = command injection risk
            findings.append(_make_finding(
                "S002_COMMAND_INJECTION", rel_path, node.lineno, code
            ))
        else:
            # shell=True with static string — still bad practice
            findings.append(_make_finding(
                "S003_UNSAFE_SUBPROCESS", rel_path, node.lineno, code
            ))

    return findings


_SUBPROCESS_REGEX = re.compile(r"shell\s*=\s*True", re.IGNORECASE)
_OS_SYSTEM_REGEX  = re.compile(r"os\.(system|popen)\s*\(")


def check_subprocess_regex(source: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _SUBPROCESS_REGEX.search(line):
            findings.append(_make_finding(
                "S003_UNSAFE_SUBPROCESS", rel_path, i, stripped
            ))
        elif _OS_SYSTEM_REGEX.search(line):
            findings.append(_make_finding(
                "S002_COMMAND_INJECTION", rel_path, i, stripped
            ))
    return findings


# ─────────────────────────────────────────────────────────────
# Rule: S004 — Unsafe Deserialization
# ─────────────────────────────────────────────────────────────

_DESER_CALL_NAMES = {
    "pickle.load", "pickle.loads", "pickle.Unpickler",
    "marshal.load", "marshal.loads",
    "shelve.open",
}
_YAML_UNSAFE = {"yaml.load"}


def check_deserialization_ast(
    tree: ast.AST, source_lines: list[str], rel_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            fname = f"{func.value.id}.{func.attr}"
        elif isinstance(func, ast.Name):
            fname = func.id
        else:
            continue

        if fname in _DESER_CALL_NAMES:
            findings.append(_make_finding(
                "S004_UNSAFE_DESERIALIZATION",
                rel_path,
                node.lineno,
                _source_line(source_lines, node.lineno),
            ))

        # yaml.load without Loader=yaml.SafeLoader
        if fname in _YAML_UNSAFE:
            has_safe_loader = any(
                kw.arg == "Loader" and (
                    (isinstance(kw.value, ast.Attribute) and "Safe" in (kw.value.attr or ""))
                    or (isinstance(kw.value, ast.Name) and "Safe" in kw.value.id)
                )
                for kw in node.keywords
            )
            if not has_safe_loader:
                findings.append(_make_finding(
                    "S004_UNSAFE_DESERIALIZATION",
                    rel_path,
                    node.lineno,
                    _source_line(source_lines, node.lineno),
                    override_severity=Severity.HIGH,
                ))

    return findings


_DESER_REGEX = re.compile(
    r"(pickle\.(load|loads|Unpickler)|marshal\.load|yaml\.load\s*\((?![^)]*SafeLoader))"
)


def check_deserialization_regex(source: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _DESER_REGEX.search(line):
            findings.append(_make_finding(
                "S004_UNSAFE_DESERIALIZATION", rel_path, i, stripped
            ))
    return findings


# ─────────────────────────────────────────────────────────────
# Rule: S005 — TLS Verification Disabled
# ─────────────────────────────────────────────────────────────

def check_tls_verify_ast(
    tree: ast.AST, source_lines: list[str], rel_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg == "verify":
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    findings.append(_make_finding(
                        "S005_TLS_VERIFY_DISABLED",
                        rel_path,
                        node.lineno,
                        _source_line(source_lines, node.lineno),
                    ))
                    break

    # Also check ssl._create_unverified_context
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = ""
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            name = f"{func.value.id}.{func.attr}"
        elif isinstance(func, ast.Name):
            name = func.id
        if "unverified" in name.lower() or "no_verify" in name.lower():
            findings.append(_make_finding(
                "S005_TLS_VERIFY_DISABLED",
                rel_path,
                node.lineno,
                _source_line(source_lines, node.lineno),
            ))

    return findings


_TLS_REGEX = re.compile(r"verify\s*=\s*False|_create_unverified_context|CERT_NONE")


def check_tls_verify_regex(source: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _TLS_REGEX.search(line):
            findings.append(_make_finding(
                "S005_TLS_VERIFY_DISABLED", rel_path, i, stripped
            ))
    return findings


# ─────────────────────────────────────────────────────────────
# Rule: S006 — Code Injection (eval/exec)
# ─────────────────────────────────────────────────────────────

def check_code_injection_ast(
    tree: ast.AST, source_lines: list[str], rel_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id in ("eval", "exec")):
            continue
        # eval/exec with a non-literal first arg → code injection risk
        if node.args and _is_dynamic(node.args[0]):
            findings.append(_make_finding(
                "S006_CODE_INJECTION",
                rel_path,
                node.lineno,
                _source_line(source_lines, node.lineno),
            ))
        elif not node.args:
            # eval() with no args (unusual but flag for review)
            pass

    return findings


_EVAL_REGEX = re.compile(r"\beval\s*\(|\bexec\s*\(")


def check_code_injection_regex(source: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _EVAL_REGEX.search(line):
            findings.append(_make_finding(
                "S006_CODE_INJECTION", rel_path, i, stripped
            ))
    return findings


# ─────────────────────────────────────────────────────────────
# Rule: S007 — Dangerous Filesystem Operations
# ─────────────────────────────────────────────────────────────

_FS_DANGER_FUNCS = {
    "shutil.rmtree", "os.remove", "os.unlink",
    "os.rmdir", "shutil.move", "os.rename",
}


def check_dangerous_fs_ast(
    tree: ast.AST, source_lines: list[str], rel_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            fname = f"{func.value.id}.{func.attr}"
        else:
            continue

        if fname not in _FS_DANGER_FUNCS:
            continue

        # Only flag if the path argument is dynamic (variable, not literal)
        if node.args and _is_dynamic(node.args[0]):
            findings.append(_make_finding(
                "S007_DANGEROUS_FILESYSTEM",
                rel_path,
                node.lineno,
                _source_line(source_lines, node.lineno),
            ))

    return findings


_FS_REGEX = re.compile(r"shutil\.(rmtree|move)|os\.(remove|unlink|rmdir|rename)\s*\(")


def check_dangerous_fs_regex(source: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _FS_REGEX.search(line):
            findings.append(_make_finding(
                "S007_DANGEROUS_FILESYSTEM", rel_path, i, stripped
            ))
    return findings


# ─────────────────────────────────────────────────────────────
# Master Scanner
# ─────────────────────────────────────────────────────────────

class Scanner:
    """
    Runs all deterministic security rules against a Python source file.

    Usage:
        scanner = Scanner()
        findings = scanner.scan_file(path, project_root)
    """

    def scan_file(
        self,
        file_path: Path,
        project_root: Path,
        source: Optional[str] = None,
    ) -> list[Finding]:
        """
        Scan a single .py file and return all findings.

        *source* can be passed to avoid re-reading from disk (e.g. in watch mode).
        """
        if source is None:
            try:
                source = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return []

        rel_path = str(file_path.relative_to(project_root))
        source_lines = source.splitlines()

        # Try AST parse
        try:
            tree: Optional[ast.AST] = ast.parse(source, filename=rel_path)
            parse_ok = True
        except SyntaxError:
            tree = None
            parse_ok = False

        findings: list[Finding] = []

        if parse_ok and tree is not None:
            findings += check_hardcoded_secrets_ast(tree, source_lines, rel_path)
            findings += check_subprocess_ast(tree, source_lines, rel_path)
            findings += check_deserialization_ast(tree, source_lines, rel_path)
            findings += check_tls_verify_ast(tree, source_lines, rel_path)
            findings += check_code_injection_ast(tree, source_lines, rel_path)
            findings += check_dangerous_fs_ast(tree, source_lines, rel_path)
        else:
            # Regex fallback for files with syntax errors
            findings += check_hardcoded_secrets_regex(source, rel_path)
            findings += check_subprocess_regex(source, rel_path)
            findings += check_deserialization_regex(source, rel_path)
            findings += check_tls_verify_regex(source, rel_path)
            findings += check_code_injection_regex(source, rel_path)
            findings += check_dangerous_fs_regex(source, rel_path)

        # Deduplicate by (rule, file, line) — multiple passes may overlap
        seen: set[tuple] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = (f.rule, f.file, f.line)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped

    def scan_project(
        self,
        project_root: Path,
        py_files: list[Path],
    ) -> list[Finding]:
        """Scan all *py_files* and return combined findings."""
        all_findings: list[Finding] = []
        for f in py_files:
            all_findings.extend(self.scan_file(f, project_root))
        return all_findings