"""
pisces.llm_client
~~~~~~~~~~~~~~~~~
Multi-provider LLM client abstraction.

Supported providers:
    openai     — OpenAI API (GPT-4o, GPT-4o-mini, o1, ...)
    anthropic  — Anthropic API (Claude 3.5 Haiku/Sonnet, ...)
    gemini     — Google Gemini API (gemini-2.0-flash, ...)
    groq       — Groq API (llama-3.3-70b, mixtral, ...) [OpenAI-compatible]
    ollama     — Local Ollama server [OpenAI-compatible]
    lmstudio   — Local LM Studio server [OpenAI-compatible]

Security: credentials come from environment only (see config_manager.get_api_key).

Design:
    - Lazy imports: only import a provider's SDK when it's actually used.
    - Single unified LLMRequest / LLMResponse model.
    - Retry with exponential backoff for rate-limit / transient errors.
    - Timeout enforced on every call.
"""
from __future__ import annotations

import time
from typing import Optional

from pisces.config_manager import get_api_key
from pisces.models import LLMRequest, LLMResponse

# ─────────────────────────────────────────────────────────────
# Provider base URLs for OpenAI-compatible providers
# ─────────────────────────────────────────────────────────────

_OPENAI_COMPAT_BASE_URLS: dict[str, str] = {
    "groq":     "https://api.groq.com/openai/v1",
    "ollama":   "http://localhost:11434/v1",
    "lmstudio": "http://localhost:1234/v1",
}

# ─────────────────────────────────────────────────────────────
# Retry settings
# ─────────────────────────────────────────────────────────────

_MAX_RETRIES     = 3
_RETRY_DELAY_S   = 2.0     # seconds, doubled on each retry
_REQUEST_TIMEOUT = 120     # seconds


# ─────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────

def call_llm(
    request: LLMRequest,
    provider: str,
    model: str,
) -> LLMResponse:
    """
    Dispatch an LLM call to the correct provider function.

    Raises:
        EnvironmentError  — API key not found
        RuntimeError      — SDK not installed, or all retries exhausted
    """
    provider = provider.lower()

    dispatch = {
        "openai":    _call_openai_compat,
        "groq":      _call_openai_compat,
        "ollama":    _call_openai_compat,
        "lmstudio":  _call_openai_compat,
        "anthropic": _call_anthropic,
        "gemini":    _call_gemini,
    }

    fn = dispatch.get(provider)
    if fn is None:
        raise RuntimeError(f"Unknown provider: '{provider}'")

    return fn(request, provider=provider, model=model)


# ─────────────────────────────────────────────────────────────
# OpenAI-compatible (openai, groq, ollama, lmstudio)
# ─────────────────────────────────────────────────────────────

def _call_openai_compat(
    request: LLMRequest,
    provider: str,
    model: str,
) -> LLMResponse:
    try:
        from openai import OpenAI, RateLimitError, APIError  # lazy import
    except ImportError:
        raise RuntimeError(
            "openai SDK not installed. Run: pip install openai"
        )

    api_key  = get_api_key(provider) or "ollama"  # ollama/lmstudio don't need a key
    base_url = _OPENAI_COMPAT_BASE_URLS.get(provider)

    client_kwargs: dict = {
        "api_key": api_key,
        "timeout": _REQUEST_TIMEOUT,
    }
    if base_url:
        client_kwargs["base_url"] = base_url

    client = OpenAI(**client_kwargs)

    delay = _RETRY_DELAY_S
    last_error: Optional[Exception] = None

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": request.system_prompt},
                    {"role": "user",   "content": request.user_prompt},
                ],
                temperature=request.temperature,
                max_tokens=request.max_tokens,
            )
            content = response.choices[0].message.content or ""
            usage   = response.usage

            return LLMResponse(
                content=content,
                model=model,
                provider=provider,
                input_tokens=usage.prompt_tokens     if usage else 0,
                output_tokens=usage.completion_tokens if usage else 0,
            )

        except RateLimitError as e:
            last_error = e
            if attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= 2
            continue
        except APIError as e:
            raise RuntimeError(f"[{provider}] API error: {e}") from e

    raise RuntimeError(
        f"[{provider}] Rate limit hit — all {_MAX_RETRIES} retries exhausted. "
        f"Last error: {last_error}"
    )


# ─────────────────────────────────────────────────────────────
# Anthropic
# ─────────────────────────────────────────────────────────────

def _call_anthropic(
    request: LLMRequest,
    provider: str,
    model: str,
) -> LLMResponse:
    try:
        import anthropic as ant  # lazy import
    except ImportError:
        raise RuntimeError(
            "anthropic SDK not installed. Run: pip install anthropic"
        )

    api_key = get_api_key("anthropic")
    client  = ant.Anthropic(api_key=api_key, timeout=_REQUEST_TIMEOUT)

    delay     = _RETRY_DELAY_S
    last_error: Optional[Exception] = None

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            msg = client.messages.create(
                model=model,
                max_tokens=request.max_tokens,
                system=request.system_prompt,
                messages=[{"role": "user", "content": request.user_prompt}],
                temperature=request.temperature,
            )
            content = msg.content[0].text if msg.content else ""
            return LLMResponse(
                content=content,
                model=model,
                provider="anthropic",
                input_tokens=msg.usage.input_tokens,
                output_tokens=msg.usage.output_tokens,
            )
        except ant.RateLimitError as e:
            last_error = e
            if attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= 2
            continue
        except ant.APIError as e:
            raise RuntimeError(f"[anthropic] API error: {e}") from e

    raise RuntimeError(
        f"[anthropic] Rate limit hit — {_MAX_RETRIES} retries exhausted. "
        f"Last: {last_error}"
    )


# ─────────────────────────────────────────────────────────────
# Google Gemini
# ─────────────────────────────────────────────────────────────

def _call_gemini(
    request: LLMRequest,
    provider: str,
    model: str,
) -> LLMResponse:
    try:
        import google.generativeai as genai  # lazy import
    except ImportError:
        raise RuntimeError(
            "google-generativeai SDK not installed. "
            "Run: pip install google-generativeai"
        )

    api_key = get_api_key("gemini")
    genai.configure(api_key=api_key)

    generation_config = genai.types.GenerationConfig(
        temperature=request.temperature,
        max_output_tokens=request.max_tokens,
    )

    gemini_model = genai.GenerativeModel(
        model_name=model,
        system_instruction=request.system_prompt,
        generation_config=generation_config,
    )

    delay     = _RETRY_DELAY_S
    last_error: Optional[Exception] = None

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            response = gemini_model.generate_content(request.user_prompt)
            content  = response.text or ""
            return LLMResponse(
                content=content,
                model=model,
                provider="gemini",
                input_tokens=response.usage_metadata.prompt_token_count     if response.usage_metadata else 0,
                output_tokens=response.usage_metadata.candidates_token_count if response.usage_metadata else 0,
            )
        except Exception as e:
            if "quota" in str(e).lower() or "rate" in str(e).lower():
                last_error = e
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= 2
                continue
            raise RuntimeError(f"[gemini] API error: {e}") from e

    raise RuntimeError(
        f"[gemini] Rate limit hit — {_MAX_RETRIES} retries exhausted. "
        f"Last: {last_error}"
    )