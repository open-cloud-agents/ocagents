"""
Open Cloud Agents: Model Provider Factory (Milestone v2.0 - TASK-4.1).

Provides centralized provider instantiation and automatic environment discovery.
"""

from __future__ import annotations

import os
from typing import Any

from ocagents.providers.anthropic import AnthropicProvider
from ocagents.providers.base import ModelProvider, ProviderConfig
from ocagents.providers.gemini import GeminiProvider
from ocagents.providers.ollama import OllamaProvider
from ocagents.providers.openai import OpenAIProvider


def detect_default_provider() -> str:
    """
    Auto-detects the best available model provider based on environment variables.
    Follows local-first philosophy: prefers local Ollama if specified, then cloud APIs,
    defaulting to local Ollama.
    """
    explicit = os.environ.get("OCAGENTS_PROVIDER", "").strip().lower()
    if explicit in ("openai", "anthropic", "gemini", "ollama", "vllm"):
        return explicit

    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("VLLM_BASE_URL"):
        return "vllm"

    # Local-first default
    return "ollama"


def get_provider(
    provider_type: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    **kwargs: Any,
) -> ModelProvider:
    """
    Factory function returning an initialized ModelProvider instance.
    """
    provider_name = (provider_type or detect_default_provider()).lower()

    if provider_name == "openai":
        config = ProviderConfig(
            provider="openai",
            model=model or os.environ.get("OPENAI_MODEL", "gpt-4o"),
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=base_url or os.environ.get("OPENAI_BASE_URL"),
            **kwargs,
        )
        return OpenAIProvider(config)

    elif provider_name == "anthropic":
        config = ProviderConfig(
            provider="anthropic",
            model=model or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
            base_url=base_url or os.environ.get("ANTHROPIC_BASE_URL"),
            **kwargs,
        )
        return AnthropicProvider(config)

    elif provider_name == "gemini":
        config = ProviderConfig(
            provider="gemini",
            model=model or os.environ.get("GEMINI_MODEL", "gemini-1.5-pro"),
            api_key=api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"),
            base_url=base_url or os.environ.get("GEMINI_BASE_URL"),
            **kwargs,
        )
        return GeminiProvider(config)

    elif provider_name == "vllm":
        vllm_url = base_url or os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
        config = ProviderConfig(
            provider="vllm",
            model=model or os.environ.get("VLLM_MODEL", "meta-llama/Llama-3.1-8B-Instruct"),
            api_key=api_key or os.environ.get("VLLM_API_KEY", "EMPTY"),
            base_url=vllm_url,
            **kwargs,
        )
        return OpenAIProvider(config)

    elif provider_name == "ollama":
        config = ProviderConfig(
            provider="ollama",
            model=model or os.environ.get("OLLAMA_MODEL", "llama3.2"),
            base_url=base_url or os.environ.get("OLLAMA_HOST"),
            api_key=api_key,
            **kwargs,
        )
        return OllamaProvider(config)

    else:
        raise ValueError(
            f"Unsupported provider '{provider_name}'. "
            f"Supported providers: 'openai', 'anthropic', 'gemini', 'ollama', 'vllm'."
        )
