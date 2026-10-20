"""
pisces.ast_visitor
~~~~~~~~~~~~~~~~~~
AST-based code intelligence extractor.

Uses Python's stdlib `ast` module. Extracts structured information
without serialising raw AST nodes (those are huge and not useful).

What we extract per file:
    - functions  (name, lines, calls, args, async, decorators)
    - classes    (name, lines, bases, methods)
    - imports    (module, names, line)
    - all calls  (top-level call names for quick callee graph)
    - security_constructs  (patterns the scanner will refine further)
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from pisces.models import (
    ClassInfo,
    FileContext,
    FunctionInfo,
    ImportInfo,
    SecurityConstruct,
)

# ─────────────────────────────────────────────────────────────
# Security-relevant call patterns
# ─────────────────────────────────────────────────────────────
# The scanner does the authoritative detection; the visitor just
# flags patterns of interest so the scanner knows where to look.

_SECURITY_CALLS: dict[str, str] = {
    # subprocess
    "subprocess.run": "subprocess_call",
    "subprocess.call": "subprocess_call",
    "subprocess.Popen": "subprocess_popen",
    "subprocess.check_output": "subprocess_call",
    "subprocess.check_call": "subprocess_call",
    # os execution
    "os.system": "os_system",
    "os.popen": "os_popen",
    "os.execv": "os_exec",
    "os.execve": "os_exec",
    # deserialization
    "pickle.load": "pickle_load",
    "pickle.loads": "pickle_load",
    "pickle.Unpickler": "pickle_load",
    "marshal.load": "marshal_load",
    "marshal.loads": "marshal_load",
    "yaml.load": "yaml_unsafe_load",  # without Loader=safe
    "shelve.open": "shelve_open",
    # code execution
    "eval": "eval_call",
    "exec": "exec_call",
    "compile": "compile_call",
    "__import__": "dynamic_import",
    # filesystem
    "open": "file_open",
    "shutil.rmtree": "dangerous_fs",
    "os.remove": "dangerous_fs",
    "os.unlink": "dangerous_fs",
    # network / TLS
    "ssl.wrap_socket": "ssl_call",
    "urllib.request.urlopen": "url_open",
    "requests.get": "requests_call",
    "requests.post": "requests_call",
    "httpx.get": "httpx_call",
    "httpx.post": "httpx_call",
}


# ─────────────────────────────────────────────────────────────
# Helper: resolve a Call node to a dotted name string
# ─────────────────────────────────────────────────────────────


def _call_name(node: ast.Call) -> str:
    """Return best-effort string name for a Call node, e.g. 'subprocess.run'."""
    func = node.func
    if isinstance(func, ast.Attribute):
        value = func.value
        if isinstance(value, ast.Name):
            return f"{value.id}.{func.attr}"
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            return f"{value.value.id}.{value.attr}.{func.attr}"
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _node_source(source_lines: list[str], node: ast.AST) -> str:
    """Return a short (~120 char) source snippet for a node."""
    lineno = getattr(node, "lineno", None)
    if lineno is None or lineno > len(source_lines):
        return ""
    line = source_lines[lineno - 1].strip()
    return line[:120]


# ─────────────────────────────────────────────────────────────
# Main visitor
# ─────────────────────────────────────────────────────────────


class PiscesASTVisitor(ast.NodeVisitor):
    """
    Walk a Python AST and extract structured intelligence.

    Usage:
        visitor = PiscesASTVisitor(source_lines)
        visitor.visit(tree)
        functions  = visitor.functions
        classes    = visitor.classes
        imports    = visitor.imports
        calls      = visitor.calls
        security   = visitor.security_constructs
    """

    def __init__(self, source_lines: list[str]) -> None:
        self._lines = source_lines
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.imports: list[ImportInfo] = []
        self.calls: list[str] = []  # deduplicated
        self.security_constructs: list[SecurityConstruct] = []

        self._seen_calls: set[str] = set()
        # Track current function scope for nested call attribution
        self._current_function: FunctionInfo | None = None

    # ── Functions ─────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._process_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._process_function(node, is_async=True)

    def _process_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_async: bool,
    ) -> None:
        decorators = [ast.unparse(d) for d in node.decorator_list]
        args = [a.arg for a in node.args.args]

        # Docstring
        docstring: str | None = None
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            raw_doc = node.body[0].value.value
            # Truncate long docstrings
            docstring = textwrap.shorten(raw_doc, width=200, placeholder="...")

        fn = FunctionInfo(
            name=node.name,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            is_async=is_async,
            decorators=decorators,
            args=args,
            docstring=docstring,
        )

        prev = self._current_function
        self._current_function = fn
        self.generic_visit(node)  # visit children → populates fn.calls
        self._current_function = prev

        self.functions.append(fn)

    # ── Classes ───────────────────────────────────────────

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = []
        for b in node.bases:
            try:
                base = ast.unparse(b)
            except (ValueError, RecursionError):
                base = None
            if base is not None:
                bases.append(base)

        decorators = [ast.unparse(d) for d in node.decorator_list]
        methods = [
            n.name for n in ast.walk(node) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        cls = ClassInfo(
            name=node.name,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            bases=bases,
            methods=methods,
            decorators=decorators,
        )
        self.classes.append(cls)
        self.generic_visit(node)

    # ── Imports ───────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(
                ImportInfo(
                    module=alias.name,
                    names=[alias.asname or alias.name],
                    line=node.lineno,
                    is_from=False,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        names = [alias.asname or alias.name for alias in node.names]
        self.imports.append(
            ImportInfo(
                module=module,
                names=names,
                line=node.lineno,
                is_from=True,
            )
        )
        self.generic_visit(node)

    # ── Calls ─────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if not name:
            self.generic_visit(node)
            return

        # Add to global deduplicated call set
        if name not in self._seen_calls:
            self._seen_calls.add(name)
            self.calls.append(name)

        # Add to current function's call list
        if self._current_function is not None and name not in self._current_function.calls:
            self._current_function.calls.append(name)

        # Check for security-relevant patterns
        kind = _SECURITY_CALLS.get(name)
        if kind:
            snippet = _node_source(self._lines, node)
            self.security_constructs.append(
                SecurityConstruct(
                    kind=kind,
                    line=node.lineno,
                    code=snippet,
                )
            )

        self.generic_visit(node)

    # ── String constants — hardcoded secret hints ─────────

    def visit_Assign(self, node: ast.Assign) -> None:
        """Flag assignments that may be hardcoded secrets."""
        _SECRET_NAMES = {
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "token",
            "auth_token",
            "access_token",
            "private_key",
            "secret_key",
            "db_password",
            "database_password",
        }
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id.lower()
            # Variable name looks like a secret
            if (
                any(s in var_name for s in _SECRET_NAMES)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value.strip()
            ):
                snippet = _node_source(self._lines, node)
                self.security_constructs.append(
                    SecurityConstruct(
                        kind="hardcoded_secret_assignment",
                        line=node.lineno,
                        code=snippet,
                        details=f"Variable '{target.id}' assigned a string literal",
                    )
                )
        self.generic_visit(node)


# ─────────────────────────────────────────────────────────────
# Public extraction function
# ─────────────────────────────────────────────────────────────


def extract_file_context(
    file_path: Path,
    relative_path: str,
    file_hash: str,
    source: str,
) -> FileContext:
    """
    Parse *source* with Python's ast module and return a FileContext.

    If parsing fails (e.g. syntax error), returns a FileContext with
    parse_error set — the scanner can still run regex rules on the raw source.
    """
    fc = FileContext(path=relative_path, hash=file_hash)
    source_lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as e:
        fc.parse_error = str(e)
        return fc
    except (TypeError, ValueError, RecursionError) as e:
        fc.parse_error = f"Unexpected parse error: {e}"
        return fc

    visitor = PiscesASTVisitor(source_lines)
    visitor.visit(tree)

    fc.functions = visitor.functions
    fc.classes = visitor.classes
    fc.imports = visitor.imports
    fc.calls = visitor.calls
    fc.security_constructs = visitor.security_constructs

    return fc
