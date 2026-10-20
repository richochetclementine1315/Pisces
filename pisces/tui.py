""" All terminal UI primitives for pisces.
Rich is our only TUI dependency """

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ─────────────────────────────────────────────────────────────
# Global Rich console with custom theme
# ─────────────────────────────────────────────────────────────

PISCES_THEME = Theme(
    {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "blue",
        "success": "bold green",
        "warning": "bold yellow",
        "muted": "dim white",
        "brand": "bold magenta",
        "brand2": "bold cyan",
        "header": "bold white on dark_magenta",
        "code": "green",
        "diff.add": "bold green",
        "diff.del": "bold red",
        "diff.hunk": "bold cyan",
    }
)
console = Console(theme=PISCES_THEME, highlight=True)


# ─────────────────────────────────────────────────────────────
# ASCII Banner
# ─────────────────────────────────────────────────────────────
_BANNER_LINES = [
    ("  ██████╗  ██╗ ███████╗  ██████╗  ███████╗ ███████╗", "bold magenta"),
    ("  ██╔══██╗ ██║ ██╔════╝ ██╔════╝  ██╔════╝ ██╔════╝", "bold magenta"),
    ("  ██████╔╝ ██║ ███████╗ ██║       █████╗   ███████╗ ", "bold cyan"),
    ("  ██╔═══╝  ██║ ╚════██║ ██║       ██╔══╝   ╚════██║ ", "bold cyan"),
    ("  ██║      ██║ ███████║ ╚██████╗  ███████╗ ███████║ ", "bold blue"),
    ("  ╚═╝      ╚═╝ ╚══════╝  ╚═════╝  ╚══════╝ ╚══════╝ ", "bold blue"),
]
_TAGLINE = "  AI-assisted Python Security · Detect · Patch · Validate · Self-Heal"
_VERSION_LINE = "  v0.1.0  ·  MIT License  ·  pip install pisces"


def print_banner() -> None:

    console.print()
    banner_text = Text()
    for line, style in _BANNER_LINES:
        banner_text.append(line + "\n", style=style)
    console.print(banner_text)
    console.print(f"[bold yellow]{_TAGLINE}[/]")
    console.print(f"[dim]{_VERSION_LINE}[/]")
    console.print()


    ### Severity badge helperz:###

_SEVERITY_STYLES: dict[str, tuple[str, str]]={
    "CRITICAL": ("critical", "● CRITICAL"),
    "HIGH":     ("high",     "▲ HIGH    "),
    "MEDIUM":   ("medium",   "◆ MEDIUM  "),
    "LOW":      ("low",      "▼ LOW     "),
    "INFO":     ("info",     "ℹ INFO    "),
}    

def severity_badge(severity: str) -> Text:
    # Rich severity badge returns.
    severity=severity.upper()
    style, label = _SEVERITY_STYLES.get(severity, ("muted", f"  {severity}"))
    return Text(label, style=style)

    ### Spinners: for actually indicatijg loading or progress

@contextmanager
def spinner(message:str, success_message: str = "") -> Generator[None, None, None] :
    with console.status(
        f"[brand] {message}[/]",
        spinner="dots",
        spinner_style="bold magenta",
    ):
        yield
    if success_message:
        console.print(f" [success]✓[/] {success_message}")    

def make_scan_progress() -> Progress:
    """Progress bar forscan steps"""
    return Progress(
        SpinnerColumn(spinner_name="dots", style="bold magenta"),
        TextColumn("[brand]{task.description}[/]", justify="left"),
        BarColumn(bar_width=30, style="magenta", complete_style="cyan"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

     ### Finding table:###
def print_findings_table(findings: list[dict]) -> None:
    """Print a colorful findings table.
    Each finding dict needs: severity, file, line, rule, description."""
    if not findings:
        console.print()
        console.print(Panel(
            "[success]✓ No security vulnerabilities found.[/]\n"
            "[dim]Your project looks clean![/]",
            title="[bold green]Scan Complete[/]",
            border_style="green",
            padding=(1, 4),
        ))
        return 
        
    table = Table(
        title=(
            f"[bold red]⚠  {len(findings)} Security "
            f"Finding{'s' if len(findings) > 1 else ''} Detected[/]"
        ),
        title_justify="left",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold white",
        show_lines=True,
        padding=(0, 1),
    )    

    table.add_column("Severity", style="bold", width=12, justify="center")
    table.add_column("Location", style="cyan", min_width=22)
    table.add_column("Rule ID", style="yellow", min_width=20)
    table.add_column("Description", min_width=40)

    _order = {"CRITICAL":0, "HIGH": 1, "MEDIUM":2, "LOW":3, "INFO": 4}
    sorted_findings = sorted(
        findings, key= lambda f: _order.get(f["severity"].upper(), 5)
    )

    for f in sorted_findings:
        table.add_row(
            severity_badge(f["severity"]),
            f"{f['file']}:{f['line']}",
            f["rule"],
            f["description"],
        )
    console.print()
    console.print(table)
    console.print()   


     ### Finding detail panel for Pisces Explainations### 

def print_finding_detail(finding: dict, source_snippet: str="") -> None:
     """Print a detail panel for a single finding"""   
     info = Table.grid(padding=(0, 2))
     info.add_column(style="dim", justify="right")
     info.add_column(style="white")

     info.add_row("Rule:",   f"[yellow]{finding['rule']}[/]") 
     info.add_row("File:",   f"[cyan]{finding['file']}:{finding['line']}[/]")

     info.add_row("Severity:", severity_badge(finding["severity"]))
     info.add_row("Description:", finding.get("description", "_"))
     info.add_row("Impact:", finding.get("impact", "_"))
     info.add_row("Remediation:", finding.get("remediation", "_"))

     console.print()
     console.print(Panel(
        info,
        title=f"[bold]Finding Detail-[yellow]{finding['rule']}[/][/]",
        border_style="yellow",
        padding=(1, 2),
     ))

     if source_snippet:
        console.print(Panel(
            Syntax(
                source_snippet, "python", theme="monokai",
                line_numbers=True, highlight_lines={finding["line"]},
            ),
            title="[bold]Vulnerable Code[/]",
            border_style="red",
            padding=(0, 1),
        ))
     console.print("[dim italic]ℹ  No source modifications have been made.[/]")
     console.print()

     ### Diff viewer: ###

def print_diff(diff_text: str, filename: str = "") -> None:
       """Display a unified diff with syntax highlighting."""
       console.print()
       console.print(Panel(
        Syntax(diff_text, "diff", theme="monokai", line_numbers=False),
        title=f"[bold]Proposed Patch{'-' + filename if filename else ''}[/]",
        border_style="cyan",
        padding=(0, 1),
       ))  
       console.print()

     ### HITL approval panel ###
def print_hitl_panel(
    filename: str,
    rule: str,
    severity: str,
    files_modified: int,
    judge_decision: str,
    risk: str,
) -> None:
    ### Print the HITL proposal + approval options. ###
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", justify="right", min_width=18)
    grid.add_column(style="white")

    judge_color = "green" if judge_decision.upper() == "APPROVED" else "red"
    risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(
        risk.upper(), "white"
    )

    grid.add_row("File:",   f"[cyan]{filename}[/]")
    grid.add_row("Issue:",  f"[yellow]{rule}[/]")
    grid.add_row("Severity:", severity_badge(severity))
    grid.add_row("Files Modified:", str(files_modified))
    grid.add_row("LLM Judge:", f"[{judge_color}]{judge_decision.upper()}[/]")
    grid.add_row("Risk:",  f"[{risk_color}]{risk.upper()}[/]")

    console.print()
    console.print(Panel(
        grid,
        title="[bold white on dark_magenta] PROPOSED SECURITY PATCH [/]",
        border_style="magenta",
        padding=(1, 2),
    ))

    options = Table.grid(padding=(0, 3))
    options.add_column(justify="center")
    options.add_column(justify="center")
    options.add_column(justify="center")
    options.add_row(
        "[bold green on black] Y [/][green] Apply patch[/]",
        "[bold red on black] N [/][red] Reject[/]",
        "[bold cyan on black] D [/][cyan] Show detailed diff[/]",
    )
    console.print(options)
    console.print()

def prompt_hitl() -> str:
      """Prompt user for HITL decision. Returns 'y', 'n', or 'd'."""
      while True:
        console.print("[dim]Enter you choice:[/]", end="")
        choice = input().strip().lower()
        if choice in ("y", "n", "d"):
            return choice
        console.print("[warning]Please Y, N, or D[/]")


      """Step level status lines"""

def print_step_ok(message: str)      -> None: console.print(f"  [success]✓[/] [white]{message}[/]")
def print_step_running(message: str) -> None: console.print(f"  [brand]◌[/] [dim]{message}[/]")
def print_step_fail(message: str)    -> None: console.print(f"  [high]✗[/] [high]{message}[/]")
def print_section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold magenta]{title}[/]", style="magenta"))
    console.print()
def print_success(message: str) -> None:
    console.print()
    console.print(Panel(f"[bold green]{message}[/]", border_style="green", padding=(0, 2)))
    console.print()
def print_error(message: str, hint: str = "") -> None:
    body = f"[high]{message}[/]"
    if hint:
        body += f"\n\n[dim]{hint}[/]"
    console.print()
    console.print(Panel(body, title="[bold red]Error[/]", border_style="red", padding=(0, 2)))
    console.print()
def print_warning(message: str) -> None:
    console.print(f"[warning]⚠  {message}[/]")

    """History Table"""

def print_history_table(records: list[dict]) -> None:
    if not records:
        console.print(Panel(
            "[dim]No repair history found.\nRun [cyan]pisces fix <finding>[/] to start.[/]",
            title="[bold]Repair History[/]",
            border_style="blue",
        ))
        return
    table = Table(
        title="[bold]Repair History[/]",
        box=box.SIMPLE_HEAD,
        border_style="blue",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("ID",       style="dim",    width=10)
    table.add_column("File",     style="cyan")
    table.add_column("Rule",     style="yellow")
    table.add_column("Status",   justify="center")
    table.add_column("Attempts", justify="center")
    table.add_column("Date",     style="dim")
    _status = {
        "SUCCEEDED":   "[success]SUCCEEDED[/]",
        "FAILED":      "[high]FAILED[/]",
        "ROLLED_BACK": "[warning]ROLLED BACK[/]",
        "REJECTED":    "[muted]REJECTED[/]",
    }
    for r in records:
        table.add_row(
            r.get("id", "—")[:8],
            r.get("file", "—"),
            r.get("rule", "—"),
            _status.get(r.get("status", ""), r.get("status", "—")),
            str(r.get("attempts", 1)),
            r.get("date", "—"),
        )
    console.print()
    console.print(table)
    console.print()


    """Judge Result panel"""

def print_judge_result(result: dict) -> None:
    decision = result.get("decision", "UNKNOWN").upper()
    color    = "green" if decision == "APPROVED" else "red"
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", justify="right", min_width=22)
    grid.add_column()
    _yn = lambda v: "[success]✓ PASS[/]" if v else "[high]✗ FAIL[/]"  # noqa: E731
    grid.add_row("Decision:",               f"[bold {color}]{decision}[/]")
    grid.add_row("Security remediated:",    _yn(result.get("security_ok")))
    grid.add_row("Functionality preserved:", _yn(result.get("functionality_ok")))
    grid.add_row("Scope correct:",          _yn(result.get("scope_ok")))
    grid.add_row("Regression risk:",        result.get("regression_risk", "—"))
    grid.add_row("Reasoning:",              result.get("reasoning", "—"))
    console.print()
    console.print(Panel(
        grid,
        title=f"[bold]LLM Judge Result — [{color}]{decision}[/][/]",
        border_style=color,
        padding=(1, 2),
    ))
    console.print()

    """Self-Healing messages"""

def print_self_healing_start(attempt: int, max_attempts: int) -> None:
    console.print()
    console.print(Panel(
        f"[warning]Validation failed. Starting self-healing attempt "
        f"[bold]{attempt}/{max_attempts}[/]...[/]",
        border_style="yellow",
        padding=(0, 2),
    ))
    console.print()
def print_self_healing_failed_all(max_attempts: int) -> None:
    console.print()
    console.print(Panel(
        f"[high]Self-healing failed after {max_attempts} attempt(s).\n\n"
        "[bold]Your original code has been restored.[/]\n"
        "[dim]No changes were left in the project.[/]",
        title="[bold red]❌ Self-Healing Exhausted[/]",
        border_style="red",
        padding=(1, 3),
    ))
    console.print()     


    
def print_hitl_approval(
    finding: dict,
    patch_summary: str,
    judge_result: dict,
) -> bool:
    """Display the judge's assessment and ask the user to approve the patch."""
    from rich.prompt import Confirm
    from rich.table import Table
    from rich.panel import Panel

    console.print()

    # Display the finding.
    details = Table.grid(padding=(0, 2))
    details.add_column(style="dim", justify="right")
    details.add_column()

    details.add_row("Rule:", str(finding.get("rule", "Unknown")))
    details.add_row("File:", str(finding.get("file", "Unknown")))
    details.add_row("Line:", str(finding.get("line", "Unknown")))
    details.add_row("Severity:", str(finding.get("severity", "Unknown")))
    details.add_row("Issue:", str(finding.get("description", "Not available")))

    console.print(
        Panel(
            details,
            title="[bold yellow]Human Review Required[/]",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    # Display the judge's decision.
    judge_table = Table.grid(padding=(0, 2))
    judge_table.add_column(style="dim", justify="right")
    judge_table.add_column()

    judge_table.add_row(
        "Decision:",
        str(judge_result.get("decision", "Unknown")),
    )
    judge_table.add_row(
        "Security OK:",
        str(judge_result.get("security_ok", "Unknown")),
    )
    judge_table.add_row(
        "Functionality OK:",
        str(judge_result.get("functionality_ok", "Unknown")),
    )
    judge_table.add_row(
        "Scope OK:",
        str(judge_result.get("scope_ok", "Unknown")),
    )
    judge_table.add_row(
        "Regression risk:",
        str(judge_result.get("regression_risk", "Unknown")),
    )
    judge_table.add_row(
        "Patch quality:",
        str(judge_result.get("patch_quality", "Unknown")),
    )
    judge_table.add_row(
        "Completeness:",
        str(judge_result.get("completeness", "Unknown")),
    )

    console.print(
        Panel(
            judge_table,
            title="[bold cyan]LLM Judge Assessment[/]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    console.print(
        Panel(
            str(judge_result.get("reasoning", "No reasoning provided.")),
            title="[bold]Judge Reasoning[/]",
            border_style="dim",
            padding=(1, 2),
        )
    )

    console.print(f"\n  [bold]Proposed patch:[/] {patch_summary}")

    # Default to rejection if the user presses Enter.
    return Confirm.ask(
        "\n[bold yellow]Do you approve applying this patch?[/]",
        default=False,
    )
   
def _sev_badge(severity: str) -> str:
    """Return a Rich-styled badge for a finding severity."""
    colors = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold cyan",
        "INFO": "dim",
    }

    severity = str(severity).upper()
    color = colors.get(severity, "white")
    return f"[{color}]{severity}[/]"








