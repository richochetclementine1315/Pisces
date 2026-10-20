from __future__ import annotations

import threading
import time
from pathlib import Path

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from pisces.context_manager import ContextManager
from pisces.tui import (
    console,
    print_section,
    print_step_fail,
    print_step_ok,
    print_step_running,
    print_warning,
)

# Configurations #
# basically how long to wait after the last event before processing called 'debouncing'
DEBOUNCE_SECONDS: float = 0.8

# the file and directories to never watch
# Especially .pisces folder to prevent rescans
_HARD_EXCLUDE_DIRS = frozenset(
    [
        ".pisces",
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
    ]
)

# Debouncer #


class Debouncer:
    def __init__(self, callback: Callable[[Path], None], delay: float = DEBOUNCE_SECONDS) -> None:  # noqa: F821
        self._callback = callback
        self._delay = delay
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()  # protects _timers dict

    def event(self, path: Path) -> None:
        """Register a debounced event for *path*."""
        key = str(path)
        with self._lock:
            # Cancel any previously scheduled timer for this path
            existing = self._timers.get(key)
            if existing is not None:
                existing.cancel()
            # Schedule a new timer
            timer = threading.Timer(
                self._delay,
                self._fire,
                args=(path, key),
            )
            timer.daemon = True  # don't block process exit
            self._timers[key] = timer
            timer.start()

    def _fire(self, path: Path, key: str) -> None:
        """Called by threading.Timer when debounce period elapses."""
        with self._lock:
            self._timers.pop(key, None)
        try:
            self._callback(path)
        except (OSError, RuntimeError, TypeError, ValueError) as e:
            print_warning(f"Error processing {path.name}: {e}")

    def cancel_all(self) -> None:
        """Cancel all pending timers (call on shutdown)."""
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()


# Event Handler #


class PiscesEventHandler(FileSystemEventHandler):
    # This is basically watchdog event handler.
    # This only filters out the .py files and ignores the excluded directories and routes events through the debouncer.
    def __init__(
        self,
        project_root: Path,
        context_manager: ContextManager,
        extra_excludes: list[str] | None = None,
    ) -> None:
        super().__init__()
        self._root = project_root
        self._cm = context_manager
        self._excludes = _HARD_EXCLUDE_DIRS | frozenset(extra_excludes or [])

        # Debouncer calls self._process when files settles
        self._debouncer = Debouncer(callback=self._process)

    # Watchdog entry points
    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileMovedEvent):
            src = FileDeletedEvent(event.src_path)
            dst = FileCreatedEvent(event.dest_path)
            self._handle(src)
            self._handle(dst)

    # Internal routing
    def _handle(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        path = Path(event.src_path)

        # must be a .py file
        if path.suffix != ".py":
            return
        # Must be reachable from the project root
        try:
            rel = path.relative_to(self._root)
        except ValueError:
            return

        # Check every path components against exlusions
        if any(part in self._excludes for part in rel.parts):
            return

        # Route through debouncer no direct action here
        self._debouncer.event(path)

    def _process(self, path: Path) -> None:
        """
        Called by the Debouncer when a file has settled.
        This runs in a daemon thread — keep it fast and thread-safe.
        """
        try:
            rel = path.relative_to(self._root)
        except ValueError:
            return
        rel_str = str(rel)
        if not path.exists():
            # File was deleted
            console.print(f"  [high]✗[/] [dim]Removed from context:[/] [cyan]{rel_str}[/]")
        else:
            print_step_running(f"Change detected: [cyan]{rel_str}[/]")
        changed = self._cm.update_single_file(path)
        if changed:
            if path.exists():
                print_step_ok(f"Context updated: [cyan]{rel_str}[/]")
            # File deleted case already printed above
        else:
            console.print(f"  [muted]No change (hash identical): {rel_str}[/]")

    def shutdown(self) -> None:
        """Cancel all pending debounce timers."""
        self._debouncer.cancel_all()


# Entry Point #
def run_watch(
    project_root: Path,
    extra_excludes: list[str] | None = None,
) -> None:
    """
    Start watch mode. Blocks until Ctrl+C.
    Called by cli.py which wraps this in a KeyboardInterrupt handler.
    """

    print_section("pisces watch")

    # validate project root
    if not (project_root / "pisces.toml").exists():
        print_step_fail("pisces.toml file not found. Run 'pisces init' first.")
        return
    # Load config to get exclusions
    try:
        from pisces.config_manager import load_config

        cfg = load_config(project_root)
        configured_excludes = cfg.scan.exclude
    except (OSError, RuntimeError, TypeError, ValueError):
        configured_excludes = []
    all_excludes = list(_HARD_EXCLUDE_DIRS) + (extra_excludes or []) + configured_excludes
    # Initial full context update before starting the watcher
    console.print("  [dim]Running initial context update...[/]")
    cm = ContextManager(project_root, extra_excludes=all_excludes)
    stats = cm.update(verbose=False)
    console.print(
        f"  [success]✓[/] Context ready — "
        f"[cyan]{stats['discovered']}[/] files indexed "
        f"([cyan]{stats['updated']}[/] updated, "
        f"[cyan]{stats['skipped']}[/] unchanged)"
    )
    console.print()
    # Set up event handler and observer
    handler = PiscesEventHandler(project_root, cm, extra_excludes=all_excludes)
    observer = Observer()
    observer.schedule(handler, str(project_root), recursive=True)
    # Start
    observer.start()
    console.print(f"  [bold magenta]👁  Watching[/] [cyan]{project_root}[/]")
    console.print("  [dim]Edit any .py file and save — context updates automatically.[/]")
    console.print("  [dim]Press Ctrl+C to stop.[/]")
    console.print()
    try:
        _watch_loop(observer)
    finally:
        handler.shutdown()  # cancel pending debounce timers
        observer.stop()
        observer.join(timeout=5)
        console.print("[muted]Observer stopped.[/]")


def _watch_loop(observer: Observer) -> None:
    """
    Main watch loop. Blocks until the observer dies or KeyboardInterrupt.
    We use a tight sleep loop instead of observer.join() so that
    KeyboardInterrupt is caught quickly.
    """
    while observer.is_alive():
        time.sleep(0.25)
