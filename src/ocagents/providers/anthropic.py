"""
Open Cloud Agents: Anthropic Claude Provider Adapter (Milestone v2.0 - TASK-4.1).

Implements client adapter for Anthropic Claude with tool-constrained schema decoding.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ocagents.providers.base import (
    AuthenticationError,
    ConstrainedDecodingError,
    ModelProvider,
    ProviderConfig,
    ProviderResponse,
)

DEFAULT_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(ModelProvider):
    """Provider adapter for Anthropic Claude models using tool-constrained output."""

    def __init__(self, config: ProviderConfig | None = None) -> None:
        if config is None:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            base_url = os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_ANTHROPIC_URL)
            model = os.environ.get("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL)
            config = ProviderConfig(
                provider="anthropic",
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
        api_key = self.config.api_key or os.environ.get("ANTHROPIC_API_KEY")
        base_url = self.config.base_url or os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_ANTHROPIC_URL)

        if not api_key:
            raise AuthenticationError(
                "Anthropic API key missing. Set ANTHROPIC_API_KEY environment variable."
            )

        headers = {
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.config.temperature if temperature is None else temperature,
            "max_tokens": self.config.max_tokens if max_tokens is None else max_tokens,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if schema:
            payload["tools"] = [
                {
                    "name": "emit_findings",
                    "description": "Emit structured cloud architecture and security findings adhering strictly to schema.",
                    "input_schema": schema,
                }
            ]
            payload["tool_choice"] = {"type": "tool", "name": "emit_findings"}

        raw_response = self._http_request(url=base_url, payload=payload, headers=headers)

        content_blocks = raw_response.get("content", [])
        content_text = ""
        parsed_json: Any | None = None

        if schema:
            tool_use_found = False
            for block in content_blocks:
                if block.get("type") == "tool_use" and block.get("name") == "emit_findings":
                    tool_use_found = True
                    parsed_json = block.get("input", {})
                    content_text = json.dumps(parsed_json)
                    break
                elif block.get("type") == "text":
                    content_text += block.get("text", "")

            if not tool_use_found:
                # Fallback: attempt to parse text content if model emitted json in text
                if content_text:
                    try:
                        parsed_json = json.loads(content_text)
                    except json.JSONDecodeError as exc:
                        raise ConstrainedDecodingError(
                            f"Anthropic did not invoke 'emit_findings' tool and returned non-JSON text: {exc}. Content: {content_text[:200]}"
                        ) from exc
                else:
                    raise ConstrainedDecodingError(
                        f"Anthropic returned no tool_use block and no text content in response: {raw_response}"
                    )
        else:
            for block in content_blocks:
                if block.get("type") == "text":
                    content_text += block.get("text", "")

        usage = raw_response.get("usage", {})
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)

        return ProviderResponse(
            content=content_text,
            parsed_json=parsed_json,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            model=raw_response.get("model", self.config.model),
            provider="anthropic",
            raw=raw_response,
        )
