"""loads, merges, and validates pisces configuration
# pisces.toml should not and never contain sensitive config(eg: API key or maybe cerdentials)
# it may contain things like say provider name, model, settings or models
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError as e:
        raise ImportError(
            "Install 'tomli' for Python < 3.11: pip install tomli"
        ) from e

    """Environment Variable names for each of the provider"""
_PROVIDER_ENV_VARS: dict[str, list[str]]={
    "openai": ["OPENAI_API_KEY"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "gemini": ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
    "groq": ["GROQ_API_KEY"],
    "ollama": [],     #key not needed cos local
    "lmstudio": [],   #key not needed cos local
}    

# Supported provider and their default models
PROVIDER_DEFAULTS: dict[str, str]={
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
    "gemini":    "gemini-2.0-flash",
    "groq":      "llama-3.3-70b-versatile",
    "ollama":    "llama3.2",
    "lmstudio":  "local-model",
}

SUPPORTED_PROVIDERS = list(PROVIDER_DEFAULTS.keys())

"""Config Dataclasses"""
@dataclass 
class LLMConfig:
    provider: str = "groq"
    model: str = "llama-3.3-70b-versatile"  

@dataclass
class RepairConfig:
    max_attempts: int = 3
    require_approval: bool = True #HITL always onn by default

@dataclass
class ValidationConfig:
    test_command: str = "pytest"         

@dataclass
class ScanConfig:
    exclude: list[str] = field(default_factory=lambda: [
        ".git", ".venv", "venv", "__pycache__",
        "node_modules", ".pisces", "dist", "build",
    ])    

@dataclass
class PiscesConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)  
    repair: RepairConfig = field(default_factory=RepairConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)  
    scan: ScanConfig = field(default_factory=ScanConfig)

    _project_root: Optional[Path] = field(default=None, repr=False, compare=False)

    """Loader"""
def load_config(project_root: Path) -> PiscesConfig:
    """
    Load configuration from *project_root*/pisces.toml.
    Falls back to defaults for any missing keys.
    Raises RuntimeError if pisces has not been initialized.
    """
    toml_path= project_root / "pisces.toml"

    if not toml_path.exists():
        raise RuntimeError(
            f"pisces.toml not found in {project_root}\n"
            "Run 'pisces init' first."
        )
    with toml_path.open("rb") as f:
        raw: dict[str, Any]= tomllib.load(f)

    cfg= PiscesConfig()   
    cfg._project_root= project_root

        # [llm]
    llm = raw.get("llm", {})
    if "provider" in llm:
        cfg.llm.provider = llm["provider"].lower().strip()
    if "model" in llm:
        cfg.llm.model = llm["model"].strip()
    # [repair]
    repair = raw.get("repair", {})
    if "max_attempts" in repair:
        cfg.repair.max_attempts = int(repair["max_attempts"])
    if "require_approval" in repair:
        cfg.repair.require_approval = bool(repair["require_approval"])
    # [validation]
    validation = raw.get("validation", {})
    if "test_command" in validation:
        cfg.validation.test_command = validation["test_command"].strip()
    # [scan]
    scan = raw.get("scan", {})
    if "exclude" in scan:
        cfg.scan.exclude = [str(e) for e in scan["exclude"]]
    _validate_config(cfg)
    return cfg
def _validate_config(cfg: PiscesConfig) -> None:
    """Raise ValueError for clearly invalid config values."""
    if cfg.llm.provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported provider '{cfg.llm.provider}'. "
            f"Choose from: {', '.join(SUPPORTED_PROVIDERS)}"
        )
    if cfg.repair.max_attempts < 1:
        raise ValueError("repair.max_attempts must be >= 1")
# ─────────────────────────────────────────────────────────────
# Credential lookup — env vars ONLY
# ─────────────────────────────────────────────────────────────
def get_api_key(provider: str) -> Optional[str]:
    """
    Return the API key for *provider* from environment variables.
    Returns None for local providers (ollama, lmstudio) that need no key.
    Raises EnvironmentError if the key is required but missing.
    """
    provider = provider.lower()
    env_vars = _PROVIDER_ENV_VARS.get(provider, [])
    if not env_vars:
        return None   # local provider — no key needed
    for var in env_vars:
        value = os.environ.get(var, "").strip()
        if value:
            return value
    raise EnvironmentError(
        f"No API key found for provider '{provider}'.\n"
        f"Set one of these environment variables: {', '.join(env_vars)}\n\n"
        f"Example (Linux/macOS/WSL):\n"
        f"  export {env_vars[0]}=your_key_here\n\n"
        f"Example (Windows CMD):\n"
        f"  set {env_vars[0]}=your_key_here\n\n"
        f"Example (Windows PowerShell):\n"
        f"  $env:{env_vars[0]}='your_key_here'"
    )
def check_api_key_available(provider: str) -> bool:
    """Return True if an API key is available (or not required)."""
    try:
        get_api_key(provider)
        return True
    except EnvironmentError:
        return False
# ─────────────────────────────────────────────────────────────
# Config writer (non-sensitive fields only)
# ─────────────────────────────────────────────────────────────
def write_config(project_root: Path, cfg: PiscesConfig) -> None:
    """
    Write *cfg* to pisces.toml.
    NEVER writes credentials. Only writes provider name, model, and settings.
    """
    toml_path = project_root / "pisces.toml"
    # Build exclude list as TOML inline array
    excludes = ", ".join(f'"{e}"' for e in cfg.scan.exclude)
    content = f"""\
# pisces project configuration
# API keys MUST come from environment variables — never put them here.
[llm]
provider = "{cfg.llm.provider}"
model    = "{cfg.llm.model}"
[repair]
max_attempts     = {cfg.repair.max_attempts}
require_approval = {"true" if cfg.repair.require_approval else "false"}
[validation]
test_command = "{cfg.validation.test_command}"
[scan]
exclude = [
    {excludes}
]
"""
    toml_path.write_text(content, encoding="utf-8") 