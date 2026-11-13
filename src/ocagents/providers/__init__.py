"""
Open Cloud Agents: Model Providers & Constrained Decoding Engine.

Provides unified adapters for Anthropic, Google Gemini, OpenAI, and Ollama/vLLM,
with JSON Schema constrained decoding, bounded retries, and token budgeting.
"""

from ocagents.providers.anthropic import AnthropicProvider
from ocagents.providers.base import (
    AuthenticationError,
    ConstrainedDecodingError,
    ModelProvider,
    ProviderConfig,
    ProviderError,
    ProviderResponse,
    RateLimitError,
    TokenBudgetExceededError,
)
from ocagents.providers.factory import detect_default_provider, get_provider
from ocagents.providers.gemini import GeminiProvider
from ocagents.providers.ollama import OllamaProvider
from ocagents.providers.openai import OpenAIProvider
from ocagents.providers.retry import (
    BoundedRetryEngine,
    RetryExecutionResult,
    get_findings_batch_schema,
    load_finding_schema,
)

__all__ = [
    "AnthropicProvider",
    "AuthenticationError",
    "BoundedRetryEngine",
    "ConstrainedDecodingError",
    "GeminiProvider",
    "ModelProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "ProviderConfig",
    "ProviderError",
    "ProviderResponse",
    "RateLimitError",
    "RetryExecutionResult",
    "TokenBudgetExceededError",
    "detect_default_provider",
    "get_findings_batch_schema",
    "get_provider",
    "load_finding_schema",
]
