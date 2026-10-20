"""
pisces.history_cmd
~~~~~~~~~~~~~~~~~~
Implements `pisces history` — browse and inspect past repair attempts.

Storage layout:
    .pisces/history/
        <repair_id>/
            metadata.json   ← state, finding, judge result, timestamps
            original.py     ← file content BEFORE the patch
            patch.py        ← the proposed replacement code block

Commands:
    pisces history           — list all repairs, newest first
    pisces history <id>      — show full detail + diff for one repair
"""

from __future__ import annotations

import difflib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich import box
from rich.table import Table

from pisces.tui import (
    _sev_badge,
    console,
    print_diff,
    print_error,
    print_section,
    print_warning,
)

_HISTORY_DIR = ".pisces/history"

# State → display colour
_STATE_COLORS = {
    "SUCCEEDED": "bold green",
    "ROLLED_BACK": "bold red",
    "REJECTED": "red",
    "FAILED": "dim red",
    "HEALING": "yellow",
    "APPLIED": "cyan",
    "DETECTED": "dim",
    "PROPOSED": "dim",
}


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────


def run_history(
    project_root: Path,
    repair_id: str | None = None,
    limit: int = 20,
) -> int:
    """
    Entry point for `pisces history`.

    If `repair_id` is given, show full detail for that repair.
    Otherwise list all repairs, newest first.

    Returns 0 on success, 1 on error.
    """
    print_section("pisces history")

    history_root = project_root / _HISTORY_DIR

    if not history_root.exists():
        console.print("[muted]No repair history found. Run 'pisces fix <file:line>' first.[/]")
        return 0

    records = _load_all_records(history_root)

    if not records:
        console.print("[muted]No repair records found.[/]")
        return 0

    if repair_id:
        # Detail view for one repair
        record = next((r for r in records if r["repair_id"] == repair_id), None)
        if record is None:
            print_error(f"Repair ID '{repair_id}' not found.")
            return 1
        _show_detail(record, history_root)
        return 0

    # List view
    _show_list(records, limit=limit)
    console.print(
        "  [dim]Tip:[/] [cyan]pisces history <repair_id>[/] "
        "[dim]to see diff + full details for any repair.[/]"
    )
    return 0


# ─────────────────────────────────────────────────────────────
# List view
# ─────────────────────────────────────────────────────────────


def _show_list(records: list[dict], limit: int) -> None:
    """Render a table of all repair records."""
    sorted_records = sorted(
        records,
        key=lambda r: r.get("created_at", ""),
        reverse=True,
    )[:limit]

    table = Table(
        title=f"[bold]Repair History[/] [dim]({len(records)} total, showing {len(sorted_records)})[/]",
        title_justify="left",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold cyan",
        show_lines=False,
        padding=(0, 1),
    )

    table.add_column("Repair ID", style="code", width=10, no_wrap=True)
    table.add_column("State", style="bold", min_width=14)
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Rule", style="code", min_width=25)
    table.add_column("File", style="cyan", min_width=25, max_width=40)
    table.add_column("When", style="dim", min_width=16)

    for r in sorted_records:
        state = r.get("state", "?")
        finding = r.get("finding", {})
        sev = finding.get("severity", "INFO").upper()
        ts = _fmt_time(r.get("created_at", ""))
        color = _STATE_COLORS.get(state, "white")

        table.add_row(
            r.get("repair_id", "?"),
            f"[{color}]{state}[/]",
            _sev_badge(sev),
            finding.get("rule", "?"),
            f"{finding.get('file', '?')}:{finding.get('line', '?')}",
            ts,
        )

    console.print(table)
    console.print()

    # Summary counts
    states = [r.get("state", "?") for r in records]
    succeeded = states.count("SUCCEEDED")
    failed = states.count("ROLLED_BACK") + states.count("FAILED")
    rejected = states.count("REJECTED")

    console.print(
        f"  [success]✓ {succeeded} succeeded[/]  "
        f"[high]✗ {failed} failed/rolled back[/]  "
        f"[dim]⊘ {rejected} rejected[/]"
    )
    console.print()


# ─────────────────────────────────────────────────────────────
# Detail view
# ─────────────────────────────────────────────────────────────


def _show_detail(record: dict, history_root: Path) -> None:
    """Render the full detail panel for one repair record."""
    from rich.panel import Panel
    from rich.table import Table

    repair_id = record.get("repair_id", "?")
    state = record.get("state", "?")
    finding = record.get("finding", {})
    judge = record.get("judge_result") or {}
    color = _STATE_COLORS.get(state, "white")

    # ── Metadata grid ─────────────────────────────────────────
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", min_width=18)
    grid.add_column(style="white", min_width=30)

    grid.add_row("Repair ID", f"[code]{repair_id}[/]")
    grid.add_row("State", f"[{color}]{state}[/]")
    grid.add_row("Rule", f"[code]{finding.get('rule', '?')}[/]")
    grid.add_row("Severity", _sev_badge(finding.get("severity", "INFO")))
    grid.add_row("File", f"[cyan]{finding.get('file', '?')}:{finding.get('line', '?')}[/]")
    grid.add_row("Description", finding.get("description", ""))
    grid.add_row("Created", _fmt_time(record.get("created_at", "")))
    grid.add_row(
        "Human approved",
        "[success]Yes[/]"
        if record.get("human_approved") is True
        else "[high]No[/]"
        if record.get("human_approved") is False
        else "[dim]N/A[/]",
    )

    console.print(
        Panel(
            grid,
            title=f"[bold]Repair Detail — {repair_id}[/]",
            border_style="blue",
            padding=(0, 2),
        )
    )
    console.print()

    # ── Judge result ──────────────────────────────────────────
    if judge:
        jt = Table.grid(padding=(0, 2))
        jt.add_column(style="dim", min_width=20)
        jt.add_column(style="white", min_width=20)

        dec = judge.get("decision", "?")
        dcol = "success" if dec == "APPROVED" else "high"

        jt.add_row("Decision", f"[{dcol}]{dec}[/]")
        jt.add_row("Security fixed", _badge(judge.get("security_ok")))
        jt.add_row("Functionality ok", _badge(judge.get("functionality_ok")))
        jt.add_row("Regression risk", judge.get("regression_risk", "?"))
        jt.add_row("Quality", judge.get("patch_quality", "?"))
        jt.add_row("Completeness", judge.get("completeness", "?"))
        jt.add_row("Reasoning", f"[dim]{judge.get('reasoning', '')[:200]}[/]")

        console.print(
            Panel(
                jt,
                title="[bold]Judge Score[/]",
                border_style="dim green",
                padding=(0, 2),
            )
        )
        console.print()

    # ── Diff ──────────────────────────────────────────────────
    repair_dir = history_root / repair_id
    original_file = repair_dir / "original.py"
    patch_file = repair_dir / "patch.py"

    if original_file.exists() and patch_file.exists():
        original = original_file.read_text(encoding="utf-8")
        patched = patch_file.read_text(encoding="utf-8")
        console.print("[bold]Patch Diff:[/]")

        diff_text = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{finding.get('file', 'original.py')}",
                tofile=f"b/{finding.get('file', 'patched.py')}",
            )
        )

        print_diff(
            diff_text=diff_text or "No differences detected.\n",
            filename=finding.get("file", ""),
        )
    else:
        console.print("[muted]No patch diff available (files not found).[/]")
        console.print()


# ─────────────────────────────────────────────────────────────
# Record loading
# ─────────────────────────────────────────────────────────────


def _load_all_records(history_root: Path) -> list[dict]:
    """Load all metadata.json files from .pisces/history/*/."""
    records: list[dict] = []
    for meta_file in history_root.glob("*/metadata.json"):
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
            records.append(data)
        except (json.JSONDecodeError, OSError):
            print_warning(f"Skipping corrupt record: {meta_file}")
    return records


# ─────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────


def _fmt_time(iso: str) -> str:
    """Convert an ISO timestamp to a human-readable relative string."""
    try:
        dt = datetime.fromisoformat(iso)
        now = datetime.now(timezone.utc)
        diff_s = (now - dt).total_seconds()

        if diff_s < 60:
            return "just now"
        if diff_s < 3600:
            return f"{int(diff_s // 60)}m ago"
        if diff_s < 86400:
            return f"{int(diff_s // 3600)}h ago"
        if diff_s < 604800:
            return f"{int(diff_s // 86400)}d ago"
        return dt.strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError):
        return iso[:16] if len(iso) >= 16 else iso


def _badge(val: Any) -> str:
    if val is True or str(val).lower() == "true":
        return "[success]✓ yes[/]"
    return "[high]✗ no[/]"
