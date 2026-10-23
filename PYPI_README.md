<p align="center">
  <img src="https://github.com/user-attachments/assets/66723bfc-b15b-44bb-8dfa-cc74ff298ade"
       width="280"
       height="100"
       alt="Pisces Banner">
</p>

<h1 align="center">PISCES</h1>

<p align="center">
  <b>AI-Assisted · Self-Healing · Human-Governed Python Security Remediation Patcher</b>
</p>

## Overview

Pisces is a Python security CLI that detects common vulnerabilities, explains
findings with an LLM, proposes minimal patches, validates them with your test
suite, and rolls them back when validation fails. Source changes remain
human-approved by default.

## Key Features

- AST-first and regex-fallback security scanning.
- Seven built-in rules for secrets, command injection, unsafe subprocesses,
  unsafe deserialization, disabled TLS verification, code injection, and
  dangerous filesystem operations.
- Excludes `.venv`, `.venv-test`, `.venv310`, and other `.venv*` directories.
- LLM explanations with source snippets and AST context.
- Human-in-the-loop patch approval.
- Atomic patching, checkpoints, rollback, and self-healing retries.
- Local repair history and a debounced watch mode.
- OpenAI, Anthropic, Gemini, Groq, Ollama, and LM Studio support.

## Installation

Pisces requires Python 3.10 or newer.

```bash
pip install pisces-cli
```

## Quick Usage

```bash
pisces init
pisces config
pisces scan .
pisces explain path/to/file.py:42
pisces fix path/to/file.py:42
pisces history
```

Set the API key for the provider configured in `pisces.toml`, for example:

```bash
export GROQ_API_KEY="your-key"
```

On Windows PowerShell:

```powershell
$env:GROQ_API_KEY = "your-key"
```

Ollama and LM Studio use local endpoints and do not require an API key.

## Configuration

Run `pisces init` to create a project configuration:

```toml
[llm]
provider = "groq"
model = "llama-3.3-70b-versatile"

[repair]
max_attempts = 3
require_approval = true

[validation]
test_command = "pytest"

[scan]
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
```

Do not put API keys in this file. Use environment variables instead.

## CLI Reference

| Command | Purpose |
|---|---|
| `pisces init [PATH]` | Initialize `pisces.toml` and `.pisces/`. |
| `pisces config [PATH] --show` | Configure or display project settings. |
| `pisces scan [TARGET] -o FILE -s LEVEL` | Scan a directory or Python file. |
| `pisces explain FILE:LINE` | Explain a cached finding with an LLM. |
| `pisces fix FILE:LINE` | Generate, approve, apply, and validate a patch. |
| `pisces watch [PATH]` | Update project context as files change. |
| `pisces history [PATH]` | Browse repair records and diffs. |
| `pisces --version` | Show the installed version. |

`pisces fix` also supports `--dry-run`, `--no-judge`, and
`--max-attempts N`. `pisces scan` returns exit code `1` when findings meet
the selected severity threshold.

## Built-in Security Rules

| Rule | ID | Severity | Detects |
|---|---|---|---|
| Hardcoded Secret | `S001` | HIGH | API keys, passwords, and tokens |
| Command Injection | `S002` | CRITICAL | Dynamic `shell=True` subprocess calls |
| Unsafe Subprocess | `S003` | HIGH | `shell=True` subprocess calls |
| Unsafe Deserialization | `S004` | HIGH | Unsafe pickle, marshal, or YAML loading |
| TLS Verify Disabled | `S005` | MEDIUM | Network calls using `verify=False` |
| Code Injection | `S006` | CRITICAL | Dynamic `eval()` or `exec()` |
| Dangerous Filesystem | `S007` | MEDIUM | Destructive operations on variable paths |

## Architecture and Workflow
<p align="center">

```mermaid
<img width="1312" height="1199" alt="Pisces Workflow Flowchart" src="https://github.com/user-attachments/assets/c463cbf3-73f8-4c5e-b251-f1acd6ab1b86" />

```
</p>

The deterministic scanner does not call an LLM. LLMs are used for explanations,
patch generation, and optional patch judging.

## Links

- **GitHub:** https://github.com/richochetclementine1315/pisces
- **Issues:** https://github.com/richochetclementine1315/pisces/issues
- **PyPI:** https://pypi.org/project/pisces-cli/

## License

MIT © [Mrinmoy Matilal](https://github.com/richochetclementine1315/pisces)
