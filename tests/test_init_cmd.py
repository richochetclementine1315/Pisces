from pathlib import Path

from pisces.init_cmd import run_init


def test_run_init_adds_generated_files_to_new_gitignore(tmp_path: Path) -> None:
    assert run_init(tmp_path) == 0

    gitignore = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".pisces/" in gitignore.splitlines()
    assert "pisces.toml" in gitignore.splitlines()


def test_run_init_adds_pisces_toml_to_existing_gitignore(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".venv/\n", encoding="utf-8")

    assert run_init(tmp_path) == 0

    lines = (tmp_path / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert lines.count(".pisces/") == 1
    assert lines.count("pisces.toml") == 1


def test_run_init_does_not_duplicate_gitignore_entries(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(
        "# pisces generated files\n.pisces/\npisces.toml\n",
        encoding="utf-8",
    )

    assert run_init(tmp_path) == 0

    content = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert content.count(".pisces/") == 1
    assert content.count("pisces.toml") == 1
