# Contributing to Pisces

Thank you for helping improve Pisces. Contributions should preserve the
project's security-first behavior, human approval workflow, and support for
Python 3.10 and newer.

## Development Setup

```bash
git clone https://github.com/richochetclementine1315/pisces.git
cd pisces
python -m venv .venv
```

Activate the environment and install the package with development tools:

```bash
pip install -e ".[dev]"
```

The package is installed as `pisces-cli`; the command is `pisces`.

## Before Opening a Pull Request

Run the project checks:

```bash
ruff check pisces/ tests/
pytest tests/ -v
python -m build
```

Add or update tests for behavior changes. Keep changes focused and update the
README or configuration documentation when CLI behavior changes.

## Code Guidelines

- Reuse existing helpers, models, and project patterns.
- Keep changes small, type-safe, and cross-platform.
- Avoid broad exception handling and silent failures.
- Keep scanner rules deterministic and free of network calls.
- Preserve the human approval gate before source modification.
- Never commit API keys, tokens, virtual environments, `.pisces` state, or
  generated build artifacts.

## Pull Requests

1. Create a feature branch from `main`.
2. Describe the problem, solution, and user-visible impact.
3. Include tests for new or changed behavior.
4. Mention any CLI, configuration, compatibility, or security implications.
5. Request review after linting, tests, and package build pass.

For larger changes, open an issue first to discuss the approach.
