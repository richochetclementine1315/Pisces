"""Tests for pisces.config_manager — load, write, credential lookup."""

from __future__ import annotations

import pytest

from pisces.config_manager import (
    check_api_key_available,
    get_api_key,
    load_config,
    write_config,
)


class TestLoadConfig:
    def test_loads_valid_toml(self, tmp_path, pisces_toml):
        cfg = load_config(tmp_path)
        assert cfg.llm.provider == "groq"
        assert cfg.llm.model == "llama-3.3-70b-versatile"
        assert cfg.repair.max_attempts == 3
        assert cfg.repair.require_approval is True
        assert cfg.validation.test_command == "pytest"

    def test_raises_when_no_toml(self, tmp_path):
        with pytest.raises(RuntimeError, match="pisces.toml not found"):
            load_config(tmp_path)

    def test_raises_on_unsupported_provider(self, tmp_path):
        (tmp_path / "pisces.toml").write_text(
            '[llm]\nprovider = "invalid_provider"\nmodel = "x"\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Unsupported provider"):
            load_config(tmp_path)

    def test_defaults_fill_missing_sections(self, tmp_path):
        (tmp_path / "pisces.toml").write_text(
            '[llm]\nprovider = "openai"\nmodel = "gpt-4o"\n',
            encoding="utf-8",
        )
        cfg = load_config(tmp_path)
        # repair section missing → defaults apply
        assert cfg.repair.max_attempts == 3
        assert cfg.repair.require_approval is True

    @pytest.mark.parametrize(
        "provider", ["openai", "anthropic", "gemini", "groq", "ollama", "lmstudio"]
    )
    def test_all_providers_accepted(self, tmp_path, provider):
        (tmp_path / "pisces.toml").write_text(
            f'[llm]\nprovider = "{provider}"\nmodel = "some-model"\n',
            encoding="utf-8",
        )
        cfg = load_config(tmp_path)
        assert cfg.llm.provider == provider


class TestWriteConfig:
    def test_round_trip(self, tmp_path, pisces_toml):
        original = load_config(tmp_path)
        original.llm.model = "gpt-4o"
        original.repair.max_attempts = 5

        write_config(tmp_path, original)

        reloaded = load_config(tmp_path)
        assert reloaded.llm.model == "gpt-4o"
        assert reloaded.repair.max_attempts == 5

    def test_does_not_write_credentials(self, tmp_path, pisces_toml):
        cfg = load_config(tmp_path)
        write_config(tmp_path, cfg)

        content = (tmp_path / "pisces.toml").read_text()
        assert "api_key" not in content.lower()
        assert "password" not in content.lower()
        assert "sk-" not in content


class TestGetApiKey:
    def test_reads_env_var(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-123")
        key = get_api_key("openai")
        assert key == "test-key-123"

    def test_raises_when_env_var_missing(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        with pytest.raises(EnvironmentError, match="No API key found"):
            get_api_key("groq")

    def test_local_providers_return_none(self):
        assert get_api_key("ollama") is None
        assert get_api_key("lmstudio") is None

    def test_check_api_key_available_true(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
        assert check_api_key_available("groq") is True

    def test_check_api_key_available_false(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        assert check_api_key_available("groq") is False

    def test_local_provider_always_available(self):
        assert check_api_key_available("ollama") is True
