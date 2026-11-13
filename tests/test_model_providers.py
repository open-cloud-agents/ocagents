"""
Unit tests for Open Cloud Agents Model Providers & Bounded Retry Engine (TASK-4.1).
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from ocagents.providers import (
    AnthropicProvider,
    AuthenticationError,
    BoundedRetryEngine,
    ConstrainedDecodingError,
    GeminiProvider,
    OllamaProvider,
    OpenAIProvider,
    ProviderConfig,
    ProviderResponse,
    TokenBudgetExceededError,
    detect_default_provider,
    get_provider,
)


class TestModelProviders(unittest.TestCase):
    """Test suite for foundation model provider adapters."""

    def test_openai_provider_generation(self):
        """Verifies OpenAI adapter formats json_schema response_format and extracts tokens."""
        provider = OpenAIProvider(
            ProviderConfig(
                provider="openai",
                model="gpt-4o",
                api_key="test-key",
                base_url="https://api.openai.com/v1",
            )
        )

        sample_finding = {
            "findings": [
                {
                    "rule_id": "rules/01-destructive-actions.md",
                    "resource": "aws_s3_bucket.prod",
                    "evidence": "diff:terraform/s3.tf#L10-L12",
                    "fact": "Bucket has force_destroy enabled.",
                    "recommendation": "Disable force_destroy.",
                    "category": "security",
                    "severity": "critical",
                    "confidence": 0.95,
                }
            ]
        }

        mock_response = {
            "id": "chatcmpl-123",
            "model": "gpt-4o",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(sample_finding),
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 80,
                "total_tokens": 230,
            },
        }

        with patch.object(provider, "_http_request", return_value=mock_response) as mock_http:
            resp = provider.generate(
                prompt="Review diff",
                system_prompt="You are a reviewer",
                schema={"type": "object"},
            )

            mock_http.assert_called_once()
            _, kwargs = mock_http.call_args
            payload = kwargs["payload"]
            self.assertEqual(payload["response_format"]["type"], "json_schema")
            self.assertEqual(payload["response_format"]["json_schema"]["strict"], True)
            self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-key")

            self.assertEqual(resp.prompt_tokens, 150)
            self.assertEqual(resp.completion_tokens, 80)
            self.assertEqual(resp.total_tokens, 230)
            self.assertIn("findings", resp.parsed_json)

    def test_openai_missing_api_key(self):
        """OpenAIProvider must raise AuthenticationError when api_key is missing on api.openai.com."""
        provider = OpenAIProvider(
            ProviderConfig(
                provider="openai",
                model="gpt-4o",
                api_key=None,
                base_url="https://api.openai.com/v1",
            )
        )
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(AuthenticationError):
                provider.generate(prompt="Hello")

    def test_anthropic_provider_tool_constrained_decoding(self):
        """Verifies Anthropic adapter sets tool_choice and extracts tool_use input."""
        provider = AnthropicProvider(
            ProviderConfig(
                provider="anthropic",
                model="claude-3-5-sonnet-20241022",
                api_key="sk-ant-test",
            )
        )

        sample_findings = {
            "findings": [
                {
                    "rule_id": "rules/02-secrets-and-identity.md",
                    "resource": "aws_iam_policy.admin",
                    "evidence": "diff:iam.tf#L5",
                    "fact": "Wildcard IAM policy attached.",
                    "recommendation": "Restrict IAM permissions.",
                    "category": "security",
                    "severity": "high",
                    "confidence": 0.9,
                }
            ]
        }

        mock_response = {
            "id": "msg-123",
            "model": "claude-3-5-sonnet-20241022",
            "content": [
                {
                    "type": "tool_use",
                    "name": "emit_findings",
                    "input": sample_findings,
                }
            ],
            "usage": {
                "input_tokens": 200,
                "output_tokens": 100,
            },
        }

        with patch.object(provider, "_http_request", return_value=mock_response) as mock_http:
            resp = provider.generate(
                prompt="Audit IAM diff",
                schema={"type": "object"},
            )

            mock_http.assert_called_once()
            _, kwargs = mock_http.call_args
            payload = kwargs["payload"]
            self.assertEqual(payload["tool_choice"], {"type": "tool", "name": "emit_findings"})
            self.assertEqual(kwargs["headers"]["x-api-key"], "sk-ant-test")

            self.assertEqual(resp.prompt_tokens, 200)
            self.assertEqual(resp.completion_tokens, 100)
            self.assertEqual(resp.total_tokens, 300)
            self.assertEqual(resp.parsed_json, sample_findings)

    def test_gemini_provider_response_schema(self):
        """Verifies Gemini adapter populates generationConfig.responseSchema and extracts candidates."""
        provider = GeminiProvider(
            ProviderConfig(
                provider="gemini",
                model="gemini-1.5-pro",
                api_key="gemini-key",
            )
        )

        sample_findings = {"findings": []}
        mock_response = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": json.dumps(sample_findings)}]
                    }
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 80,
                "candidatesTokenCount": 40,
                "totalTokenCount": 120,
            },
        }

        with patch.object(provider, "_http_request", return_value=mock_response) as mock_http:
            resp = provider.generate(
                prompt="Analyze code",
                system_prompt="Architect agent",
                schema={"type": "object"},
            )

            mock_http.assert_called_once()
            _, kwargs = mock_http.call_args
            payload = kwargs["payload"]
            self.assertEqual(payload["generationConfig"]["responseMimeType"], "application/json")
            self.assertIn("systemInstruction", payload)

            self.assertEqual(resp.prompt_tokens, 80)
            self.assertEqual(resp.completion_tokens, 40)
            self.assertEqual(resp.total_tokens, 120)
            self.assertEqual(resp.parsed_json, sample_findings)

    def test_ollama_provider_native_format_schema(self):
        """Verifies Ollama adapter injects schema under payload['format']."""
        provider = OllamaProvider(
            ProviderConfig(
                provider="ollama",
                model="llama3.2",
                base_url="http://localhost:11434",
            )
        )

        mock_response = {
            "message": {
                "role": "assistant",
                "content": json.dumps({"findings": []}),
            },
            "prompt_eval_count": 65,
            "eval_count": 35,
        }

        with patch.object(provider, "_http_request", return_value=mock_response) as mock_http:
            schema = {"type": "object"}
            resp = provider.generate(prompt="Inspect diff", schema=schema)

            mock_http.assert_called_once()
            _, kwargs = mock_http.call_args
            self.assertEqual(kwargs["payload"]["format"], schema)
            self.assertEqual(resp.total_tokens, 100)


class TestBoundedRetryEngine(unittest.TestCase):
    """Test suite for BoundedRetryEngine schema feedback and token budgeting."""

    def setUp(self):
        self.mock_provider = MagicMock()

    def test_first_attempt_success(self):
        """Clean valid finding on attempt 1 returns immediately with retry_count=0."""
        valid_payload = {
            "findings": [
                {
                    "rule_id": "rules/01-destructive-actions.md",
                    "category": "security",
                    "resource": "aws_s3_bucket.prod",
                    "fact": "force_destroy is enabled",
                    "evidence": "diff:terraform/s3.tf#L12",
                    "recommendation": "Remove force_destroy = true",
                    "severity": "critical",
                    "confidence": 0.95,
                }
            ]
        }

        self.mock_provider.generate.return_value = ProviderResponse(
            content=json.dumps(valid_payload),
            parsed_json=valid_payload,
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

        engine = BoundedRetryEngine(self.mock_provider, max_retries=2, max_total_tokens=5000)
        result = engine.execute(prompt="Audit", agent_name="security-commander")

        self.assertEqual(result.attempts, 1)
        self.assertEqual(result.total_tokens, 150)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding["retry_count"], 0)
        self.assertEqual(finding["agent"], "security-commander")
        self.assertEqual(finding["origin"], "model_assertion")
        self.assertTrue(finding["id"].startswith("FND-"))

    def test_retry_on_schema_error_then_success(self):
        """Engine feeds back schema violations on attempt 1, succeeding on attempt 2."""
        invalid_payload = {
            "findings": [
                {
                    "rule_id": "rules/01-destructive-actions.md",
                    "category": "security",
                    "resource": "aws_s3_bucket.prod",
                    "fact": "force_destroy is enabled",
                    "evidence": "diff:terraform/s3.tf#L12",
                    "recommendation": "Remove force_destroy",
                    "severity": "extreme_danger",  # Disallowed
                }
            ]
        }

        valid_payload = {
            "findings": [
                {
                    "rule_id": "rules/01-destructive-actions.md",
                    "category": "security",
                    "resource": "aws_s3_bucket.prod",
                    "fact": "force_destroy is enabled",
                    "evidence": "diff:terraform/s3.tf#L12",
                    "recommendation": "Remove force_destroy = true",
                    "severity": "critical",
                    "confidence": 0.95,
                }
            ]
        }

        self.mock_provider.generate.side_effect = [
            ProviderResponse(
                content=json.dumps(invalid_payload),
                parsed_json=invalid_payload,
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
            ),
            ProviderResponse(
                content=json.dumps(valid_payload),
                parsed_json=valid_payload,
                prompt_tokens=160,
                completion_tokens=60,
                total_tokens=220,
            ),
        ]

        engine = BoundedRetryEngine(self.mock_provider, max_retries=2, max_total_tokens=5000)
        result = engine.execute(prompt="Audit", agent_name="security-commander")

        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.total_tokens, 370)  # 150 + 220
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding["retry_count"], 1)

        # Verify second call included feedback prompt
        second_call_prompt = self.mock_provider.generate.call_args_list[1][1]["prompt"]
        self.assertIn("[SYSTEM FEEDBACK - RETRY ATTEMPT #2]", second_call_prompt)
        self.assertIn("extreme_danger", second_call_prompt)

    def test_token_budget_exceeded(self):
        """Engine raises TokenBudgetExceededError when cumulative tokens cross threshold."""
        payload = {"findings": []}
        self.mock_provider.generate.return_value = ProviderResponse(
            content=json.dumps(payload),
            parsed_json=payload,
            prompt_tokens=800,
            completion_tokens=300,
            total_tokens=1100,
        )

        engine = BoundedRetryEngine(self.mock_provider, max_total_tokens=1000)
        with self.assertRaises(TokenBudgetExceededError):
            engine.execute(prompt="Audit", agent_name="architect")

    def test_max_retries_exceeded_raises_error(self):
        """Engine raises ConstrainedDecodingError when max_retries is exhausted."""
        invalid_payload = {"findings": [{"severity": "invalid_val"}]}
        self.mock_provider.generate.return_value = ProviderResponse(
            content=json.dumps(invalid_payload),
            parsed_json=invalid_payload,
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

        engine = BoundedRetryEngine(self.mock_provider, max_retries=1)
        with self.assertRaises(ConstrainedDecodingError):
            engine.execute(prompt="Audit")


class TestProviderFactory(unittest.TestCase):
    """Test provider discovery and factory initialization."""

    def test_factory_openai(self):
        provider = get_provider("openai", api_key="test", model="gpt-4o")
        self.assertIsInstance(provider, OpenAIProvider)
        self.assertEqual(provider.config.model, "gpt-4o")

    def test_factory_anthropic(self):
        provider = get_provider("anthropic", api_key="test", model="claude-3-5-sonnet-20241022")
        self.assertIsInstance(provider, AnthropicProvider)

    def test_factory_gemini(self):
        provider = get_provider("gemini", api_key="test")
        self.assertIsInstance(provider, GeminiProvider)

    def test_factory_ollama(self):
        provider = get_provider("ollama")
        self.assertIsInstance(provider, OllamaProvider)

    def test_factory_vllm(self):
        provider = get_provider("vllm")
        self.assertIsInstance(provider, OpenAIProvider)
        self.assertEqual(provider.config.provider, "vllm")

    def test_factory_invalid(self):
        with self.assertRaises(ValueError):
            get_provider("unsupported-vendor")

    def test_detect_default_provider_precedence(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-123"}, clear=True):
            self.assertEqual(detect_default_provider(), "anthropic")

        with patch.dict("os.environ", {"GEMINI_API_KEY": "gemini-123"}, clear=True):
            self.assertEqual(detect_default_provider(), "gemini")

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-123"}, clear=True):
            self.assertEqual(detect_default_provider(), "openai")

        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(detect_default_provider(), "ollama")


if __name__ == "__main__":
    unittest.main()
