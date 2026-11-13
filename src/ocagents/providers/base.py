"""
Open Cloud Agents: Model Provider Base Architecture (Milestone v2.0 - TASK-4.1).

Defines the universal ModelProvider interface, ProviderConfig, ProviderResponse,
and structured decoding exceptions for LLM backends.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("ocagents.providers")


class ProviderError(Exception):
    """Base exception for model provider errors."""


class AuthenticationError(ProviderError):
    """Raised when provider authentication fails (e.g., HTTP 401/403)."""


class RateLimitError(ProviderError):
    """Raised when rate limits or quotas are exceeded (e.g., HTTP 429)."""


class ConstrainedDecodingError(ProviderError):
    """Raised when a model fails to emit payload satisfying the required schema."""


class TokenBudgetExceededError(ProviderError):
    """Raised when an agent session exceeds its declared maximum token budget."""


@dataclass
class ProviderConfig:
    """Configuration parameters for a model provider client."""

    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None
    temperature: float = 0.0
    max_tokens: int = 4096
    timeout: float = 60.0
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ProviderResponse:
    """Standardized response from a foundation model provider."""

    content: str
    parsed_json: Any | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = ""
    provider: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.total_tokens == 0:
            self.total_tokens = self.prompt_tokens + self.completion_tokens


class ModelProvider(ABC):
    """Abstract Base Class for foundation model providers with constrained decoding."""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        schema: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ProviderResponse:
        """
        Executes a generation request with optional JSON Schema constrained decoding.

        Args:
            prompt: User or task prompt.
            system_prompt: Optional system prompt or role directive.
            schema: JSON schema dict to constrain output decoding.
            max_tokens: Override max output tokens.
            temperature: Override decoding temperature.

        Returns:
            ProviderResponse containing content, parsed_json, and token metrics.
        """
        raise NotImplementedError

    def _http_request(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout: float | None = None,
        max_retries: int = 2,
    ) -> dict[str, Any]:
        """
        Executes an HTTP POST request using standard library urllib with error mapping.
        """
        data = json.dumps(payload).encode("utf-8")
        req_headers = {
            "Content-Type": "application/json",
            "User-Agent": "OpenCloudAgents/1.6.0 (universal-orchestrator)",
            **self.config.extra_headers,
            **headers,
        }

        timeout_sec = timeout or self.config.timeout
        attempt = 0
        backoff = 1.0

        while True:
            attempt += 1
            req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                    resp_body = resp.read().decode("utf-8")
                    try:
                        return json.loads(resp_body)
                    except json.JSONDecodeError as exc:
                        raise ProviderError(f"Provider returned invalid JSON response: {exc}") from exc
            except urllib.error.HTTPError as exc:
                status = exc.code
                error_body = ""
                try:
                    error_body = exc.read().decode("utf-8", errors="replace")
                except (OSError, UnicodeDecodeError) as read_exc:
                    logger.debug("Failed to read HTTP error response body: %s", read_exc)

                if status in (401, 403):
                    raise AuthenticationError(
                        f"Authentication failed for {self.config.provider} ({status}): {error_body}"
                    ) from exc
                elif status == 429:
                    if attempt <= max_retries:
                        logger.warning(
                            "Rate limited by %s (429). Retrying in %.1fs (attempt %d/%d)...",
                            self.config.provider,
                            backoff,
                            attempt,
                            max_retries,
                        )
                        time.sleep(backoff)
                        backoff *= 2.0
                        continue
                    raise RateLimitError(
                        f"Rate limit exceeded for {self.config.provider} after {max_retries} retries: {error_body}"
                    ) from exc
                elif status in (500, 502, 503, 504) and attempt <= max_retries:
                    logger.warning(
                        "Transient server error %d from %s. Retrying in %.1fs...",
                        status,
                        self.config.provider,
                        backoff,
                    )
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue
                else:
                    raise ProviderError(
                        f"HTTP error {status} from {self.config.provider}: {error_body}"
                    ) from exc
            except urllib.error.URLError as exc:
                if attempt <= max_retries:
                    logger.warning(
                        "Connection error to %s: %s. Retrying in %.1fs...",
                        url,
                        exc.reason,
                        backoff,
                    )
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue
                raise ProviderError(f"Failed to connect to {self.config.provider} at {url}: {exc.reason}") from exc
