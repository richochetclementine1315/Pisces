"""This implements the pisces init command for project initialization"""
# Can be run multiple times(idempotent).abs
# creates pisces.toml and the .pisces/ state directory
# NEVER destructively overwrites without --force
# Adds .pisces to .gitignore if it exists.abs
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pisces.tui import(
    console,
    print_section,
    print_step_fail,
    print_step_ok,
    print_step_running,
    print_success,
    print_warning,
    spinner,
)

## default pisces.toml template

_DEFAULT_PISCES_TOML = """\
# pisces project configuration
# API keys MUST come from environment variables — never put them here.
# See: https://github.com/richochetclementine1315/pisces#configuration
[llm]
# Supported providers: openai, anthropic, gemini, groq, ollama, lmstudio
provider = "groq"
model    = "llama-3.3-70b-versatile"
[repair]
max_attempts     = 3
require_approval = true   # HITL — always ask before modifying source
[validation]
# Command used to run your project's test suite after patching.
# pisces will detect 'pytest' automatically if you leave this empty.
test_command = "pytest"
[scan]
# Paths to exclude from scanning (relative globs)
exclude = [
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pisces",
    "dist",
    "build",
]
"""

"""Default context.json template"""
def _default_context(project_root: Path)->dict:
    return {
        "schema_version" : "1",
        "project":{
            "root": str(project_root),
            "initialized_at": datetime.now(timezone.utc).isoformat(),
        },
        "files":{},
    }

"""Main init logic"""
def run_init(project_root: Path, *, force: bool=False)-> int:
    """initialize pisces in *project_root*. , return 0 as success and 1 as errror."""  
    print_section("pisces init")
    console.print(f" [dim]Project root:[/] [cyan]{project_root}[/]")  
    console.print()

    # 1.Validation of the project root very important bro!
    if not project_root.exists():
        print_step_fail(f"Directory does not exists: {project_root}")
        return 1
    if not project_root.is_dir():
        print_step_fail(f"Not a directory: {project_root}")   
        return 1
    
    # 2.pisces.toml
    toml_path= project_root / "pisces.toml"
    _init_pisces_toml(toml_path, force=force)

    #3. .pisces/ state directories basically like cache, history context.json etc 
    pisces_dir = project_root / ".pisces"
    history_dir= pisces_dir / "history"
    cache_dir = pisces_dir / "cache"
    context_file = pisces_dir / "context.json"

    # Creating the files
    ok= all([
        _create_dir(pisces_dir),
        _create_dir(history_dir),
        _create_dir(cache_dir),
        _init_context_json(context_file, project_root, force=force),
    ])
    if not ok:
        return 1 #error creating directories or context.json
    #4. .gitignore(means we are adding the .pisces in the .gitignore)
    _update_gitignore(project_root)

    #5. Done
    console.print()
    print_success(
       "✓  pisces initialized successfully!\n\n"
        "  Next steps:\n"
        "    1. [cyan]pisces config[/]   — set your LLM provider\n"
        "    2. [cyan]pisces scan .[/]   — detect security vulnerabilities\n"
        "    3. [cyan]pisces fix <finding>[/] — generate and apply a patch" 
    )

    return 0 #successfully created

"""Some Helper Functions"""    
def _init_pisces_toml(path: Path, *, force: bool)->None:
    existed = path.exists()
    if existed and not force:
        print_step_ok(f"pisces.toml already exists - skipping (use --force)")
        return 

    action = "Overwriting" if existed else "creating"  
    print_step_running(f"{action} pisces.toml ...") 
    try:
        path.write_text(_DEFAULT_PISCES_TOML, encoding="utf-8")
        print_step_ok(f"pisces.toml {'overwritten' if existed else 'created'}")
    except OSError as e:
        print_step_fail(f"Could not write pisces.toml: {e}") 


def _create_dir(path: Path)->None:
    if path.exists():
        print_step_ok(f"{path.name}/ already exists - skipping")
        return True
    try:
        path.mkdir(parents= True, exist_ok=True)
        print_step_ok(f"Created {path.name}/")
        return True
    except OSError as e:
        print_step_fail(f"Could not create {path}: {e}")
        return False


def _init_context_json(path: Path, project_root: Path, *, force: bool)-> None:
    if path.exists() and not force:
        print_step_ok("context.json already exists - skipping")
        return

    print_step_running("Writing context.json ...") 
    try:
        path.write_text(
            json.dumps(_default_context(project_root), indent=2),
            encoding="utf-8",
        )      
        print_step_ok("context.json initialized")
    except OSError as e:
        print_step_fail(f"Could not write context.json: {e}")

def _update_gitignore(project_root: Path)->None:
    """Ensure .pisces/ is listed in .gitignore."""    
    gitignore =  project_root / ".gitignore"
    entry = ".pisces/"  

    if not gitignore.exists():
        print_step_running("No .ignore found - creating one ...")  
        try:
            gitignore.write_text(f"# pisces state directory\n{entry}\n", encoding="utf-8")
            print_step_ok(".gitignore created with .pisces/entry")
        except OSError as e:
            print_warning(f"could not create .gitignore: {e}") 
        return

    content = gitignore.read_text(encoding="utf-8")
    if entry in content or ".pisces" in content:
        print_step_ok(".gitignore already contains .pisces entry - skipping")
        return

    try:
        with gitignore.open("a", encoding="utf-8") as f:
            f.write(f"\n# pisces state directory\n{entry}\n")
        print_step_ok("Added .pisces/ to .gitignore")
    except OSError as e:
        print_warning(f"Could not update .gitignore: {e}")                                                   
