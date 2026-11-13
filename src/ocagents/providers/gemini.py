"""
Open Cloud Agents: Google Gemini Provider Adapter (Milestone v2.0 - TASK-4.1).

Implements client adapter for Google Gemini models with native responseSchema
constrained decoding.
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

DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_GEMINI_MODEL = "gemini-1.5-pro"


class GeminiProvider(ModelProvider):
    """Provider adapter for Google Gemini models using native responseSchema decoding."""

    def __init__(self, config: ProviderConfig | None = None) -> None:
        if config is None:
            api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            base_url = os.environ.get("GEMINI_BASE_URL", DEFAULT_GEMINI_BASE_URL)
            model = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
            config = ProviderConfig(
                provider="gemini",
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
        api_key = self.config.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        base_url = (self.config.base_url or os.environ.get("GEMINI_BASE_URL", DEFAULT_GEMINI_BASE_URL)).rstrip("/")

        if not api_key:
            raise AuthenticationError(
                "Gemini API key missing. Set GEMINI_API_KEY or GOOGLE_API_KEY environment variable."
            )

        model = self.config.model
        url = f"{base_url}/{model}:generateContent?key={urllib.parse.quote(api_key)}"

        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        payload: dict[str, Any] = {"contents": contents}

        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        generation_config: dict[str, Any] = {
            "temperature": self.config.temperature if temperature is None else temperature,
            "maxOutputTokens": self.config.max_tokens if max_tokens is None else max_tokens,
        }

        if schema:
            generation_config["responseMimeType"] = "application/json"
            generation_config["responseSchema"] = schema

        payload["generationConfig"] = generation_config

        raw_response = self._http_request(url=url, payload=payload, headers={})

        candidates = raw_response.get("candidates", [])
        if not candidates:
            raise ConstrainedDecodingError(f"Gemini returned empty candidates in response: {raw_response}")

        candidate = candidates[0]
        content_obj = candidate.get("content", {})
        parts = content_obj.get("parts", [])
        if not parts:
            raise ConstrainedDecodingError(f"Gemini candidate contains no content parts: {candidate}")

        content_text = parts[0].get("text", "")
        parsed_json: Any | None = None

        if schema and content_text:
            try:
                parsed_json = json.loads(content_text)
            except json.JSONDecodeError as exc:
                raise ConstrainedDecodingError(
                    f"Gemini failed to emit valid JSON under responseSchema: {exc}. Content: {content_text[:200]}"
                ) from exc

        usage = raw_response.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount", 0)
        completion_tokens = usage.get("candidatesTokenCount", 0)
        total_tokens = usage.get("totalTokenCount", prompt_tokens + completion_tokens)

        return ProviderResponse(
            content=content_text,
            parsed_json=parsed_json,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=model,
            provider="gemini",
            raw=raw_response,
        )
