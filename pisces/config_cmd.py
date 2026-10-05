"""
pisces.config_cmd
~~~~~~~~~~~~~~~~~
Implements `pisces config` — interactive configuration wizard.

What it does:
    - Shows current configuration (with --show)
    - Interactively updates provider, model, repair, validation settings
    - Validates that the chosen provider has a key available in the environment
    - Never reads or writes API keys to pisces.toml
"""
from __future__ import annotations

from pathlib import Path

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich import box

from pisces.config_manager import (
    PROVIDER_DEFAULTS,
    SUPPORTED_PROVIDERS,
    PiscesConfig,
    check_api_key_available,
    load_config,
    write_config,
)
from pisces.tui import (
    console,
    print_error,
    print_section,
    print_step_ok,
    print_success,
    print_warning,
)


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def run_config(project_root: Path, *, show_only: bool = False) -> int:
    """
    Entry point for `pisces config`.

    Returns 0 on success, 1 on error.
    """
    print_section("pisces config")

    # Load existing config (requires pisces init to have been run)
    try:
        cfg = load_config(project_root)
    except RuntimeError as e:
        print_error(str(e), hint="Run 'pisces init' first.")
        return 1
    except ValueError as e:
        print_error(f"Invalid configuration: {e}")
        return 1

    if show_only:
        _print_config_table(cfg, project_root)
        return 0

    # Interactive wizard
    _print_config_table(cfg, project_root)
    console.print()

    try:
        cfg = _run_wizard(cfg)
    except KeyboardInterrupt:
        console.print("\n[muted]Configuration cancelled.[/]")
        return 0

    # Save
    try:
        write_config(project_root, cfg)
    except OSError as e:
        print_error(f"Could not save configuration: {e}")
        return 1

    print_success("✓  Configuration saved to pisces.toml")

    # Key check
    _check_provider_key(cfg.llm.provider)

    return 0


# ─────────────────────────────────────────────────────────────
# Current config display table
# ─────────────────────────────────────────────────────────────

def _print_config_table(cfg: PiscesConfig, project_root: Path) -> None:
    """Print a rich table showing the current configuration."""
    table = Table(
        title="[bold]Current Configuration[/]",
        title_justify="left",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold cyan",
        show_lines=False,
        padding=(0, 2),
    )
    table.add_column("Setting",  style="dim",   min_width=22)
    table.add_column("Value",    style="white",  min_width=30)
    table.add_column("Source",   style="muted",  min_width=16)

    # API key status (env var check)
    has_key = check_api_key_available(cfg.llm.provider)
    key_status = "[success]✓ Found in env[/]" if has_key else "[high]✗ Not set[/]"

    table.add_row("llm.provider",          f"[magenta]{cfg.llm.provider}[/]",         "pisces.toml")
    table.add_row("llm.model",             f"[cyan]{cfg.llm.model}[/]",               "pisces.toml")
    table.add_row("API key",               key_status,                                 "env var")
    table.add_row("repair.max_attempts",   str(cfg.repair.max_attempts),               "pisces.toml")
    table.add_row("repair.require_approval",
                  "[success]true[/]" if cfg.repair.require_approval else "[high]false[/]",
                  "pisces.toml")
    table.add_row("validation.test_command", f"[code]{cfg.validation.test_command}[/]","pisces.toml")
    table.add_row("Config file",           str(project_root / "pisces.toml"),          "—")

    console.print()
    console.print(table)
    console.print()


# ─────────────────────────────────────────────────────────────
# Interactive wizard
# ─────────────────────────────────────────────────────────────

def _run_wizard(cfg: PiscesConfig) -> PiscesConfig:
    """Run an interactive prompt-based config wizard. Returns updated cfg."""
    console.print("[bold]Configure pisces[/] [dim](<press Enter to keep current value>)[/]")
    console.print()

    # ── LLM Provider ────────────────────────────────────────
    console.print(f"[dim]Supported providers:[/] {', '.join(SUPPORTED_PROVIDERS)}")
    provider = Prompt.ask(
        "  [bold magenta]LLM provider[/]",
        default=cfg.llm.provider,
        console=console,
    ).lower().strip()

    if provider not in SUPPORTED_PROVIDERS:
        print_warning(
            f"Unknown provider '{provider}'. Keeping current: {cfg.llm.provider}"
        )
        provider = cfg.llm.provider

    # ── Model ────────────────────────────────────────────────
    default_model = PROVIDER_DEFAULTS.get(provider, cfg.llm.model)
    if provider != cfg.llm.provider:
        # Provider changed → suggest new provider's default model
        console.print(
            f"  [dim]Default model for {provider}:[/] [cyan]{default_model}[/]"
        )

    model = Prompt.ask(
        "  [bold cyan]Model name[/]",
        default=cfg.llm.model if provider == cfg.llm.provider else default_model,
        console=console,
    ).strip()

    # ── Max repair attempts ──────────────────────────────────
    attempts_str = Prompt.ask(
        "  [bold]Max self-healing attempts[/]",
        default=str(cfg.repair.max_attempts),
        console=console,
    ).strip()
    try:
        max_attempts = int(attempts_str)
        if max_attempts < 1:
            raise ValueError
    except ValueError:
        print_warning(f"Invalid value '{attempts_str}'. Keeping: {cfg.repair.max_attempts}")
        max_attempts = cfg.repair.max_attempts

    # ── Require HITL approval ────────────────────────────────
    console.print()
    console.print(
        "  [dim]Human approval (HITL) means pisces will ask before modifying source.[/]"
    )
    require_approval = Confirm.ask(
        "  [bold]Require human approval before patching?[/]",
        default=cfg.repair.require_approval,
        console=console,
    )

    # ── Test command ─────────────────────────────────────────
    console.print()
    test_command = Prompt.ask(
        "  [bold]Test command[/] [dim](<used to validate patches>)[/]",
        default=cfg.validation.test_command,
        console=console,
    ).strip()

    # ── Apply ────────────────────────────────────────────────
    cfg.llm.provider             = provider
    cfg.llm.model                = model
    cfg.repair.max_attempts      = max_attempts
    cfg.repair.require_approval  = require_approval
    cfg.validation.test_command  = test_command

    return cfg


# ─────────────────────────────────────────────────────────────
# API key availability check (advisory only)
# ─────────────────────────────────────────────────────────────

def _check_provider_key(provider: str) -> None:
    """Print a reminder if the provider's API key is not set."""
    has_key = check_api_key_available(provider)
    if has_key:
        print_step_ok(f"API key for '{provider}' found in environment ✓")
    else:
        # Local providers don't need keys
        if provider in ("ollama", "lmstudio"):
            print_step_ok(f"'{provider}' is a local provider — no API key needed ✓")
        else:
            from pisces.config_manager import _PROVIDER_ENV_VARS
            env_var = _PROVIDER_ENV_VARS.get(provider, ["?"])[0]
            print_warning(
                f"API key for '{provider}' not found.\n"
                f"  Set it before running 'pisces fix':\n"
                f"    export {env_var}=your_key_here"
            )