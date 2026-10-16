"""
pisces.scan_cmd
~~~~~~~~~~~~~~~
Implements `pisces scan` — discovery, context update, scanning, output.

After scanning, findings are cached in .pisces/cache/findings.json so
`pisces explain` and `pisces fix` can resolve them by file:line reference.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from pisces.config_manager import load_config
from pisces.context_manager import ContextManager, discover_python_files
from pisces.models import Finding, Severity
from pisces.scanner import Scanner
from pisces.tui import (
    console,
    make_scan_progress,
    print_error,
    print_findings_table,
    print_section,
    print_step_ok,
    print_warning,
    spinner,
)

# Where we persist findings between commands
_FINDINGS_CACHE = ".pisces/cache/findings.json"


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def run_scan(
    target: Path,
    output: Optional[Path] = None,
    min_severity: str = "LOW",
) -> int:
    """
    Entry point for `pisces scan`.

    Returns 0 if no findings (or only below threshold), 1 if findings exist.
    """
    print_section("pisces Security Scanner")

    # ── Load config ──────────────────────────────────────────
    try:
        cfg = load_config(target)
        excludes = cfg.scan.exclude
    except RuntimeError:
        # Might be scanning a single file without init — allow it
        excludes = []
        print_warning("No pisces.toml found — using default exclusions.")

    # ── Discover Python files ────────────────────────────────
    with spinner("Discovering Python files..."):
        if target.is_file() and target.suffix == ".py":
            py_files = [target]
            project_root = target.parent
        else:
            project_root = target
            py_files = discover_python_files(target, extra_excludes=excludes)

    print_step_ok(f"Discovered [cyan]{len(py_files)}[/] Python file(s)")

    if not py_files:
        console.print()
        console.print("[muted]No Python files found to scan.[/]")
        return 0

    # ── Update context ───────────────────────────────────────
    with spinner("Updating project context..."):
        try:
            cm = ContextManager(project_root, extra_excludes=excludes)
            cm.update(verbose=False)
        except Exception as e:
            print_warning(f"Context update skipped: {e}")

    print_step_ok("Project context updated")

    # ── Run security rules with progress bar ─────────────────
    console.print()
    scanner = Scanner()
    all_findings: list[Finding] = []

    _RULE_LABELS = [
        "Checking hardcoded secrets",
        "Checking command injection",
        "Checking unsafe subprocess usage",
        "Checking unsafe deserialization",
        "Checking TLS verification",
        "Checking code injection (eval/exec)",
        "Checking filesystem operations",
    ]

    with make_scan_progress() as progress:
        task = progress.add_task(
            "Running security rules...", total=len(py_files) + len(_RULE_LABELS)
        )

        # Show rule-level steps briefly
        for label in _RULE_LABELS:
            progress.update(task, description=label, advance=1)

        # Scan files
        for py_file in py_files:
            progress.update(
                task,
                description=f"Scanning [cyan]{py_file.name}[/]...",
                advance=1,
            )
            all_findings.extend(scanner.scan_file(py_file, project_root))

    console.print()
    print_step_ok("Scan complete")
    console.print()

    # ── Filter by minimum severity ───────────────────────────
    try:
        min_sev = Severity.from_str(min_severity)
    except Exception:
        min_sev = Severity.LOW

    _sev_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2,   Severity.LOW: 3,
        Severity.INFO: 4,
    }
    threshold = _sev_order[min_sev]
    filtered = [
        f for f in all_findings
        if _sev_order.get(f.severity, 99) <= threshold
    ]

    # ── Save findings cache ───────────────────────────────────
    _save_findings_cache(project_root, all_findings)

    # ── Display results ───────────────────────────────────────
    findings_as_dicts = [
        {
            "severity":    f.severity.value,
            "file":        f.file,
            "line":        f.line,
            "rule":        f.rule,
            "description": f.description,
        }
        for f in filtered
    ]
    print_findings_table(findings_as_dicts)

    # ── Summary line ─────────────────────────────────────────
    total = len(all_findings)
    if total > 0:
        above = len(filtered)
        console.print(
            f"  Found [bold red]{total}[/] vulnerability/vulnerabilities total "
            f"([cyan]{above}[/] at or above [bold]{min_severity}[/] severity).\n"
        )

        if filtered:
            console.print(
                "  [dim]Run[/] [cyan]pisces explain <file>:<line>[/] "
                "[dim]for detail on any finding.[/]"
            )
            console.print(
                "  [dim]Run[/] [cyan]pisces fix <file>:<line>[/] "
                "[dim]to generate and apply a security patch.[/]"
            )
            console.print()

    # ── Optional JSON output ──────────────────────────────────
    if output:
        _write_json_output(output, all_findings)

    # Exit code: 1 if any findings at/above threshold, else 0
    return 1 if filtered else 0


# ─────────────────────────────────────────────────────────────
# Findings cache (used by explain + fix commands)
# ─────────────────────────────────────────────────────────────

def _save_findings_cache(project_root: Path, findings: list[Finding]) -> None:
    """Save findings to .pisces/cache/findings.json for lookup by other commands."""
    cache_path = project_root / _FINDINGS_CACHE
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = {
            "findings": [f.to_dict() for f in findings],
            # Index by "file:line" for O(1) lookup
            "index": {
                f"{f.file}:{f.line}": f.to_dict()
                for f in findings
            },
        }
        cache_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError as e:
        print_warning(f"Could not save findings cache: {e}")


def load_finding_by_ref(project_root: Path, ref: str) -> Optional[Finding]:
    """
    Load a specific finding by its 'file:line' reference.

    Called by `pisces explain` and `pisces fix`.
    """
    cache_path = project_root / _FINDINGS_CACHE
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        entry = data.get("index", {}).get(ref)
        if entry:
            return Finding.from_dict(entry)
    except (json.JSONDecodeError, KeyError, OSError):
        pass
    return None


def _write_json_output(output: Path, findings: list[Finding]) -> None:
    """Write findings as JSON to a user-specified file."""
    try:
        output.write_text(
            json.dumps([f.to_dict() for f in findings], indent=2),
            encoding="utf-8",
        )
        print_step_ok(f"Findings saved to [cyan]{output}[/]")
    except OSError as e:
        print_warning(f"Could not write output file: {e}")