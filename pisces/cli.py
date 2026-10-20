"""Typer CLI entrypoint, all commands here actually. Only the commands, logics in another module"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from typing_extensions import Annotated

from pisces import __version__
from pisces.tui import console, print_banner

app = typer.Typer(
    name="pisces",
    help=(
        "[bold magenta]Pisces[/]-AI-assisted,self healing"
         "human-governed security remediation patcher.\n\n"
         "Workflow: [cyan]scan → explain → fix → validate → self-heal[/]"
    ),
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
    no_args_is_help=False,
    invoke_without_command=True,
    add_completion=True,
)

def _version_callback(value: bool)-> None:
    if value:
        console.print(f"[bold magenta]Pisces[/] [dim]v{__version__}[/]")
        raise typer.Exit()

@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", "-v",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ]=None,
) -> None:
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())

"""init command"""
@app.command()
def init(
    path: Annotated[
        Path,
        typer.Argument(help="Project root to be initialized."),
    ]=Path("."),
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite existing pisces.toml")
    ] = False,
) -> None:   

    print_banner()
    from pisces.init_cmd import run_init
    raise typer.Exit(run_init(path.resolve(), force=force))

"""config commands"""
@app.command()
def config(
    path: Annotated[
        Path,
        typer.Argument(help="Project root directory")
    ] = Path("."),
    show: Annotated[
        bool,
        typer.Option("--show","-s", help="Print current configuration and exit."),
    ]=False,
)->None:

    print_banner()
    from pisces.config_cmd import run_config
    raise typer.Exit(run_config(path.resolve(), show_only=show))

"""Scan command"""
@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(help="Directory or file to scan."),
    ] = Path("."),
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Save the findings to a JSON file"),
    ]=None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity", "-s",
            help="Minimum severity to report (CRITICAL/HIGH/MEDIUM/LOW/INFO).",
        ),
    ]="LOW",
)->None:

    """Scan Python files for security vulnerabilities."""
    print_banner()
    from pisces.scan_cmd import run_scan
    raise typer.Exit(run_scan(target.resolve(), output=output, min_severity= min_severity))   


"""explain command"""
@app.command()
def explain(
    finding: Annotated[
        str,
        typer.Argument(
            help="Finding reference, e.g. auth.py:42."
        ),
    ],
) -> None:
    """Explain a security finding using the configured LLM."""
    print_banner()

    from pisces.explain_cmd import run_explain

    raise typer.Exit(
        run_explain(
            finding,
            project_root=Path.cwd(),
        )
    )


"""Fix command"""

@app.command()
def fix(
    finding: Annotated[
        str,
        typer.Argument(help="Finding reference, e.g. auth.py:45."),
    ],
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show the proposed patch without modifying the file.",
        ),
    ] = False,
    no_judge: Annotated[
        bool,
        typer.Option(
            "--no-judge",
            help="Skip LLM judge evaluation (not recommended).",
        ),
    ] = False,
    max_attempts: Annotated[
        Optional[int],
        typer.Option(
            "--max-attempts",
            "-m",
            help="Override the maximum self-healing attempts.",
            min=1,
        ),
    ] = None,
) -> None:
    """Generate, review, apply, and validate a security patch."""
    print_banner()

    from pisces.fix_cmd import run_fix

    raise typer.Exit(
        run_fix(
            finding,
            project_root=Path.cwd(),
            dry_run=dry_run,
            skip_judge=no_judge,
            max_attempts=max_attempts,
        )
    )


"""watch command"""
@app.command()
def watch(
    path: Annotated[
        Path,
        typer.Argument(help="Directory to watch."),
    ]=Path(".")
)  -> None:

    """Watch for Python file changes and auto-update project context. Uses [cyan]watchdog[/] for filesystem events"""

    print_banner()
    from pisces.watcher import run_watch
    try:
        run_watch(path.resolve())
    except KeyboardInterrupt:
        console.print("\n[muted]Watch mode stopped.[/]")
        raise typer.Exit(0)    

    """History command"""   
@app.command()
def history(
    path: Annotated[
        Path,
        typer.Argument(help="Project root directory."),
    ]=Path("."),
    detail:Annotated[
        Optional[str],
        typer.Option("--detail", "-d", help="Show detail for a specific repair ID."),
    ]=None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Number of records to show."),
    ]=20,
) -> None:
    """Show repair history for this project."""
    print_banner()
    from pisces.history_cmd import run_history
    raise typer.Exit(
    run_history(
        path.resolve(),
        repair_id=detail,
        limit=limit,
    )
)

if __name__ == "__main__":
    app()