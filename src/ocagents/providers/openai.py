"""
Open Cloud Agents: OpenAI & Compatible Provider Adapter (Milestone v2.0 - TASK-4.1).

Implements client adapter for OpenAI, vLLM, and OpenAI-compatible endpoints with
native JSON Schema constrained decoding (response_format: json_schema).
"""

from __future__ import annotations

import json
import os
import urllib.parse
from typing import Any

from ocagents.providers.base import (
    AuthenticationError,
    ConstrainedDecodingError,
    ModelProvider,
    ProviderConfig,
    ProviderResponse,
)

DEFAULT_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_OPENAI_MODEL = "gpt-4o"


class OpenAIProvider(ModelProvider):
    """Provider adapter for OpenAI and OpenAI-compatible endpoints (vLLM, LocalAI)."""

    def __init__(self, config: ProviderConfig | None = None) -> None:
        if config is None:
            api_key = os.environ.get("OPENAI_API_KEY")
            base_url = os.environ.get("OPENAI_BASE_URL", DEFAULT_OPENAI_URL)
            model = os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL)
            config = ProviderConfig(
                provider="openai",
                model=model,
                api_key=api_key,
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
        api_key = self.config.api_key or os.environ.get("OPENAI_API_KEY")
        base_url = self.config.base_url or os.environ.get("OPENAI_BASE_URL", DEFAULT_OPENAI_URL)

        # Normalize URL to chat completions if bare host was provided
        if not base_url.endswith("/chat/completions"):
            base_url = f"{base_url.rstrip('/')}/chat/completions"

        parsed_host = urllib.parse.urlparse(base_url).hostname or ""
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        elif parsed_host == "api.openai.com" or parsed_host.endswith(".openai.com"):
            raise AuthenticationError("OpenAI API key missing. Set OPENAI_API_KEY environment variable.")

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature if temperature is None else temperature,
            "max_tokens": self.config.max_tokens if max_tokens is None else max_tokens,
        }

        if schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "structured_findings",
                    "strict": True,
                    "schema": schema,
                },
            }

        raw_response = self._http_request(url=base_url, payload=payload, headers=headers)

        choices = raw_response.get("choices", [])
        if not choices:
            raise ConstrainedDecodingError(f"OpenAI returned empty choices in response: {raw_response}")

        message = choices[0].get("message", {})
        content = message.get("content", "")

        parsed_json: Any | None = None
        if schema and content:
            try:
                parsed_json = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ConstrainedDecodingError(
                    f"OpenAI failed to emit valid JSON under constrained decoding: {exc}. Content: {content[:200]}"
                ) from exc

        usage = raw_response.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        return ProviderResponse(
            content=content,
            parsed_json=parsed_json,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=raw_response.get("model", self.config.model),
            provider="openai",
            raw=raw_response,
        )
