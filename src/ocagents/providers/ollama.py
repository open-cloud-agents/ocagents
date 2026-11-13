"""
Open Cloud Agents: Ollama & Local vLLM Provider Adapter (Milestone v2.0 - TASK-4.1).

Implements local-first client adapter for Ollama and vLLM runtimes with native
schema format enforcement.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ocagents.providers.base import (
    ConstrainedDecodingError,
    ModelProvider,
    ProviderConfig,
    ProviderResponse,
)

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2"


class OllamaProvider(ModelProvider):
    """Provider adapter for local Ollama instances with schema constrained output."""

    def __init__(self, config: ProviderConfig | None = None) -> None:
        if config is None:
            base_url = os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)
            model = os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
            config = ProviderConfig(
                provider="ollama",
                model=model,
                base_url=base_url,
            )
        super().__init__(config)

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        schema: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ProviderResponse:
        base_url = (self.config.base_url or os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)).rstrip("/")
        chat_url = f"{base_url}/api/chat"

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature if temperature is None else temperature,
                "num_predict": self.config.max_tokens if max_tokens is None else max_tokens,
            },
        }

        if schema:
            # Ollama 0.5+ accepts schema object directly in format
            payload["format"] = schema

        headers = {}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        raw_response = self._http_request(url=chat_url, payload=payload, headers=headers)

        message = raw_response.get("message", {})
        content_text = message.get("content", "")

        parsed_json: Any | None = None
        if schema and content_text:
            try:
                parsed_json = json.loads(content_text)
            except json.JSONDecodeError as exc:
                raise ConstrainedDecodingError(
                    f"Ollama failed to emit valid JSON under schema constraint: {exc}. Content: {content_text[:200]}"
                ) from exc

        prompt_tokens = raw_response.get("prompt_eval_count", 0)
        completion_tokens = raw_response.get("eval_count", 0)

        return ProviderResponse(
            content=content_text,
            parsed_json=parsed_json,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            model=raw_response.get("model", self.config.model),
            provider="ollama",
            raw=raw_response,
        )
