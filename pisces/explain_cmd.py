"""
pisces.explain_cmd
~~~~~~~~~~~~~~~~~~
Implements `pisces explain <file:line>` — AI-powered vulnerability analysis.

What it does (in order):
    1. Parse the "file:line" reference from the user
    2. Load the Finding from .pisces/cache/findings.json
    3. Read ±20 lines of surrounding source code for context
    4. Load the file's AST context (imports, functions, calls)
    5. Build a structured prompt with all of that context
    6. Call the configured LLM provider
    7. Parse and render the explanation as a rich, formatted panel
"""

from __future__ import annotations

import re
from pathlib import Path

from rich import box
from rich.console import Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from pisces.config_manager import load_config
from pisces.context_manager import ContextManager
from pisces.llm_client import call_llm
from pisces.models import FileContext, Finding, LLMRequest
from pisces.scan_cmd import load_finding_by_ref
from pisces.tui import (
    console,
    print_error,
    print_finding_detail,
    print_section,
    print_warning,
    spinner,
)

# Number of lines of source context to send to the LLM (above + below the finding)
_CONTEXT_LINES = 20


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────


def run_explain(
    ref: str,
    project_root: Path,
) -> int:
    """
    Entry point for `pisces explain <ref>`.
    ref format: "path/to/file.py:42"

    Returns 0 on success, 1 on error.
    """
    print_section("pisces explain")

    # ── Parse reference ──────────────────────────────────────
    file_path, line_no = _parse_ref(ref, project_root)
    if file_path is None:
        print_error(
            f"Invalid reference: '{ref}'\n  Expected format: pisces explain path/to/file.py:42"
        )
        return 1

    rel_path = str(file_path.relative_to(project_root))
    lookup = f"{rel_path}:{line_no}"

    # ── Load finding from cache ───────────────────────────────
    finding = load_finding_by_ref(project_root, lookup)
    if finding is None:
        print_warning(
            f"No cached finding at '{lookup}'.\n"
            "  Run 'pisces scan .' first to populate the findings cache."
        )
        return 1

    # ── Load surrounding source lines ─────────────────────────
    source_snippet = _get_source_snippet(file_path, line_no, context=_CONTEXT_LINES)
    if not source_snippet:
        print_warning(f"Could not read source from {rel_path}")
        # Continue anyway — LLM can still help with what we know

    # ── Load AST file context ─────────────────────────────────
    file_ctx = _get_file_context(project_root, rel_path)

    # ── Load config ───────────────────────────────────────────
    try:
        cfg = load_config(project_root)
    except RuntimeError as e:
        print_error(str(e))
        return 1

    provider = cfg.llm.provider
    model = cfg.llm.model

    console.print(f"  [dim]Using[/] [magenta]{provider}[/] / [cyan]{model}[/]")
    console.print()

    # ── Build and send LLM request ────────────────────────────
    request = _build_explain_request(finding, source_snippet, file_ctx, rel_path)

    try:
        with spinner(f"Asking {provider} to analyse the vulnerability..."):
            response = call_llm(request, provider=provider, model=model)
    except OSError as e:
        print_error(str(e), hint=f"Set the API key env var for '{provider}'.")
        return 1
    except RuntimeError as e:
        print_error(str(e))
        return 1

    # ── Parse LLM response ────────────────────────────────────
    try:
        explanation = _parse_llm_response(response.content)
    except ValueError as e:
        print_error(f"Could not parse the LLM response: {e}")
        console.print(response.content)
        return 1

    # ── Display structured explanation ────────────────────────
    _display_explanation(
        finding=finding,
        explanation=explanation,
        response=response,
        rel_path=rel_path,
        line_no=line_no,
        source_snippet=source_snippet,
    )

    # ── Token usage ───────────────────────────────────────────
    console.print(
        f"\n  [dim]Tokens used:[/] "
        f"[cyan]{response.input_tokens}[/] in / "
        f"[cyan]{response.output_tokens}[/] out"
    )

    # ── Suggested next steps ──────────────────────────────────
    console.print(
        Panel(
            "[bold]Preview the proposed patch:[/]\n"
            f"[cyan]pisces fix {rel_path}:{line_no} --dry-run[/]\n\n"
            "[bold]Start the remediation workflow:[/]\n"
            f"[green]pisces fix {rel_path}:{line_no}[/]",
            title="[bold magenta]NEXT STEP[/]",
            border_style="magenta",
            padding=(1, 2),
        )
    )

    return 0


def _display_explanation(
    finding: Finding,
    explanation: dict[str, str],
    response: object,
    rel_path: str,
    line_no: int,
    source_snippet: str,
) -> None:
    """Render a structured, readable security analysis in the terminal."""

    severity = str(finding.severity.value).upper()

    severity_styles = {
        "CRITICAL": ("bold white on red", "red"),
        "HIGH": ("bold red", "red"),
        "MEDIUM": ("bold yellow", "yellow"),
        "LOW": ("bold green", "green"),
        "INFO": ("bold cyan", "cyan"),
    }

    severity_style, border_style = severity_styles.get(severity, ("bold white", "cyan"))

    console.print()

    # ── Header ────────────────────────────────────────────────
    console.print(
        Panel(
            Text.from_markup(
                f"[bold]SECURITY ANALYSIS[/]\n"
                f"[dim]{rel_path}:{line_no}[/]\n\n"
                f"[{severity_style}] {severity} [/]"
                f"  [bold]{finding.rule}[/]\n"
                f"[dim]{finding.description}[/]"
            ),
            border_style=border_style,
            box=box.DOUBLE,
            padding=(1, 2),
            title="[bold magenta]PISCES[/]",
            subtitle="[dim]AI-assisted vulnerability analysis[/]",
        )
    )

    # ── Summary ───────────────────────────────────────────────
    summary = explanation.get("Summary", "")
    if summary:
        console.print(
            Panel(
                Markdown(summary),
                title="[bold cyan]01 · Executive Summary[/]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

    # ── Finding metadata ──────────────────────────────────────
    metadata = Table(
        show_header=False,
        box=box.SIMPLE,
        expand=True,
        padding=(0, 1),
    )
    metadata.add_column("Property", style="dim", width=18)
    metadata.add_column("Value", style="bold")

    metadata.add_row("Severity", f"[{severity_style}]{severity}[/]")
    metadata.add_row("Rule", finding.rule)
    metadata.add_row("Location", f"{rel_path}:{line_no}")

    if finding.impact:
        metadata.add_row("Potential impact", finding.impact)

    console.print(
        Panel(
            metadata,
            title="[bold]Finding Details[/]",
            border_style="dim",
            padding=(0, 1),
        )
    )

    # ── Explanation ───────────────────────────────────────────
    if explanation.get("Vulnerability Explained"):
        console.print(
            Panel(
                Markdown(explanation["Vulnerability Explained"]),
                title="[bold cyan]02 · How the Vulnerability Works[/]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

    # ── Attack scenario ───────────────────────────────────────
    if explanation.get("Attack Scenario"):
        console.print(
            Panel(
                Markdown(explanation["Attack Scenario"]),
                title="[bold yellow]03 · Attack Scenario[/]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

    # ── Root cause ────────────────────────────────────────────
    if explanation.get("Root Cause"):
        console.print(
            Panel(
                Markdown(explanation["Root Cause"]),
                title="[bold red]04 · Root Cause[/]",
                border_style="red",
                padding=(1, 2),
            )
        )

    # ── Recommended fix ───────────────────────────────────────
    fix_text = explanation.get("Recommended Fix", "")

    if fix_text:
        code_match = re.search(
            r"```(?:python|py)?\s*\n(.*?)```",
            fix_text,
            re.DOTALL | re.IGNORECASE,
        )

        if code_match:
            before_code = fix_text[: code_match.start()].strip()
            code = code_match.group(1).strip()
            after_code = fix_text[code_match.end() :].strip()

            fix_content = []

            if before_code:
                fix_content.append(Markdown(before_code))

            fix_content.append(
                Syntax(
                    code,
                    "python",
                    theme="monokai",
                    line_numbers=True,
                    word_wrap=True,
                    padding=1,
                )
            )

            if after_code:
                fix_content.append(Markdown(after_code))

            console.print(
                Panel(
                    Group(*fix_content),
                    title="[bold green]05 · Recommended Fix[/]",
                    border_style="green",
                    padding=(1, 2),
                )
            )
        else:
            console.print(
                Panel(
                    Markdown(fix_text),
                    title="[bold green]05 · Recommended Fix[/]",
                    border_style="green",
                    padding=(1, 2),
                )
            )

    # ── References ────────────────────────────────────────────
    if explanation.get("References"):
        console.print(
            Panel(
                Markdown(explanation["References"]),
                title="[bold blue]06 · References & Standards[/]",
                border_style="blue",
                padding=(1, 2),
            )
        )

    console.print()
    console.print(
        "[dim]Analysis complete · Review the suggested patch before applying it.[/]",
        justify="center",
    )
    console.print()


# ─────────────────────────────────────────────────────────────
# Reference parsing
# ─────────────────────────────────────────────────────────────


def _parse_ref(ref: str, project_root: Path) -> tuple[Path | None, int]:
    """
    Parse a 'file.py:42' reference into (Path, line_number).

    Handles both:
      - relative:  pisces/scanner.py:100
      - absolute:  /home/user/project/pisces/scanner.py:100
    """
    # Split on last colon — handles Windows paths like C:\foo\bar.py:10
    match = re.match(r"^(.+):(\d+)$", ref.strip())
    if not match:
        return None, 0

    file_str = match.group(1)
    line_no = int(match.group(2))

    # Try as-is, then relative to project_root
    candidates = [
        Path(file_str),
        project_root / file_str,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.suffix == ".py":
            return candidate.resolve(), line_no

    return None, 0


# ─────────────────────────────────────────────────────────────
# Source snippet extraction
# ─────────────────────────────────────────────────────────────


def _get_source_snippet(
    file_path: Path,
    line_no: int,
    context: int = _CONTEXT_LINES,
) -> str:
    """
    Return lines [line_no - context, line_no + context] from *file_path*,
    with line numbers prepended as: ' 42 | source code here'
    """
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    start = max(1, line_no - context)
    end = min(len(lines), line_no + context)

    result_lines = []
    for i in range(start, end + 1):
        marker = "→" if i == line_no else " "
        result_lines.append(f"{marker} {i:4d} | {lines[i - 1]}")

    return "\n".join(result_lines)


# ─────────────────────────────────────────────────────────────
# File context loading
# ─────────────────────────────────────────────────────────────


def _get_file_context(project_root: Path, rel_path: str) -> FileContext | None:
    """Load the FileContext from .pisces/context.json, if available."""
    try:
        cm = ContextManager(project_root)
        cm.load()
        return cm.get_file_context(rel_path)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        return None


# ─────────────────────────────────────────────────────────────
# Prompt engineering
# ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an expert Python security engineer performing a code security review.
You will be given:
  1. A security finding detected by static analysis
  2. The surrounding source code with line numbers
  3. File-level context: imports, functions, classes, related calls

Your task: produce a structured, thorough security analysis.

Respond ONLY in the following format with these exact section headers:

## Summary
One sentence: what is wrong and why it matters.

## Vulnerability Explained
2-4 paragraphs explaining:
  - How this vulnerability works technically
  - What an attacker could do to exploit it
  - Real-world impact (data breach, RCE, privilege escalation, etc.)

## Attack Scenario
A concrete, step-by-step scenario showing how an attacker would exploit this.
Be specific to the actual code shown.

## Root Cause
Identify the exact line(s) and the underlying programming mistake.

## Recommended Fix
Provide the corrected Python code as a fenced code block (```python ... ```).
The fix must:
  - Be minimal — change only what is necessary
  - Preserve the original logic and function signature
  - Follow security best practices
  - Include a brief comment explaining WHY each change was made

## References
2-3 relevant references: CWE number, OWASP category, or CVE if applicable.
"""


def _build_explain_request(
    finding: Finding,
    source_snippet: str,
    file_ctx: FileContext | None,
    rel_path: str,
) -> LLMRequest:
    """Construct the LLMRequest for the explain command."""

    # Build file context summary (from AST analysis)
    ctx_lines: list[str] = []
    if file_ctx:
        if file_ctx.imports:
            mods = [i.module for i in file_ctx.imports[:15]]
            ctx_lines.append(f"Imports: {', '.join(mods)}")
        if file_ctx.functions:
            fns = [f.name for f in file_ctx.functions[:10]]
            ctx_lines.append(f"Functions defined: {', '.join(fns)}")
        if file_ctx.classes:
            cls = [c.name for c in file_ctx.classes[:5]]
            ctx_lines.append(f"Classes defined: {', '.join(cls)}")
        if file_ctx.security_constructs:
            kinds = [s.kind for s in file_ctx.security_constructs[:8]]
            ctx_lines.append(f"Other security-relevant calls: {', '.join(set(kinds))}")

    file_ctx_str = (
        "\n".join(ctx_lines)
        if ctx_lines
        else "Context not available (context.json not found or file not indexed)."
    )

    user_prompt = f"""\
## Security Finding

- **File:** `{rel_path}`
- **Line:** {finding.line}
- **Rule:** `{finding.rule}`
- **Severity:** {finding.severity.value}
- **Description:** {finding.description}
- **Impact:** {finding.impact}
- **Offending code:** `{finding.code}`

---

## Surrounding Source Code (±{_CONTEXT_LINES} lines, line {finding.line} marked with →)

```python
{source_snippet if source_snippet else "(source not available)"}
```

## File Context (AST Analysis)

{file_ctx_str}

---

Analyze the finding using the source code and context above.
Be accurate and specific to the actual code. If the finding is a false
positive, explain why rather than recommending an unnecessary change.
"""

    return LLMRequest(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
    )


# ─────────────────────────────────────────────────────────────
# Response parsing
# ─────────────────────────────────────────────────────────────

_SECTION_PATTERN = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)

_REQUIRED_SECTIONS = (
    "Summary",
    "Vulnerability Explained",
    "Attack Scenario",
    "Root Cause",
    "Recommended Fix",
    "References",
)


def _parse_llm_response(content: str) -> dict[str, str]:
    """Parse the structured Markdown response into named sections."""
    matches = list(_SECTION_PATTERN.finditer(content))
    sections: dict[str, str] = {}

    for index, match in enumerate(matches):
        heading = match.group(1).strip()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(content)

        sections[heading] = content[start:end].strip()

    if not sections:
        raise ValueError("The LLM response contains no Markdown section headings.")

    return sections


# ─────────────────────────────────────────────────────────────
# Response display
# ─────────────────────────────────────────────────────────────


def _display_explanation(
    finding: Finding,
    explanation: dict[str, str],
    response: object,
    rel_path: str,
    line_no: int,
    source_snippet: str,
) -> None:

    console.print()
    finding_data = {
        "rule": finding.rule,
        "file": rel_path,
        "line": line_no,
        "severity": str(finding.severity.value).upper(),
        "description": finding.description,
        "impact": finding.impact or "Not specified",
        "remediation": getattr(finding, "remediation", None) or "See the recommended fix below.",
    }

    print_finding_detail(finding_data, source_snippet=source_snippet)

    for heading in _REQUIRED_SECTIONS:
        body = explanation.get(heading)

        if not body:
            print_warning(f"LLM response omitted section: {heading}")
            continue

        console.print(
            Panel(
                Markdown(body),
                title=f"[bold cyan]{heading}[/]",
                border_style="cyan",
                expand=True,
                padding=(1, 2),
            )
        )
