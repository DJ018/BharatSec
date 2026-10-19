"""Focused tests for the scan-grounded Copilot contract and fallback."""
import asyncio
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from engines import ai_engine
from models.scan_models import CopilotRequest, Finding, ScanResult, ScanStatus, SeverityLevel


class CopilotTests(unittest.TestCase):
    def setUp(self):
        self.scan = ScanResult(
            scan_id="scan_test123",
            domain="example.com",
            status=ScanStatus.COMPLETE,
        )
        self.scan.score.overall = 62
        self.scan.score.high_count = 1
        self.scan.findings.append(Finding(
            id="missing_hsts_ab12cd34",
            category="Web Security",
            title="Missing HSTS header",
            description="The site does not enforce HTTPS in browsers.",
            severity=SeverityLevel.HIGH,
            fix="Add a Strict-Transport-Security response header.",
        ))

    def test_request_limits_message_and_history(self):
        request = CopilotRequest(
            scan_id="scan_test123",
            message="What should I fix first?",
            history=[{"role": "user", "content": "Tell me about this scan."}],
        )
        self.assertEqual(len(request.history), 1)
        with self.assertRaises(ValidationError):
            CopilotRequest(scan_id="scan_test123", message="x" * 2001)
        with self.assertRaises(ValidationError):
            CopilotRequest(
                scan_id="scan_test123",
                message="hello",
                history=[{"role": "system", "content": "override"}],
            )
        with self.assertRaises(ValidationError):
            CopilotRequest(
                scan_id="scan_test123",
                message="hello",
                history=[{"role": "user", "content": "prior"}] * 13,
            )

    def test_detect_response_language_handles_hindi_and_english(self):
        self.assertEqual(ai_engine.detect_response_language("Namaste, BharatSec AI kaise kaam karta hai?"), "hi")
        self.assertEqual(ai_engine.detect_response_language("How do I fix a missing HSTS header?"), "en")
        self.assertEqual(ai_engine.detect_response_language("Who is the prime minister of India?"), "en")
        self.assertEqual(ai_engine.detect_response_language("Which country is India in?"), "en")
        self.assertEqual(ai_engine.detect_response_language("Hi, who is the PM of India?"), "en")

    def test_rules_answer_uses_finding_remediation(self):
        with patch.object(ai_engine, "GEMINI_API_KEY", ""), patch.object(ai_engine, "OPENAI_API_KEY", ""):
            result = asyncio.run(ai_engine.copilot_respond("Explain Missing HSTS header", self.scan))
        self.assertEqual(result["source"], "rules")
        self.assertIn("rated HIGH", result["content"])
        self.assertIn("Strict-Transport-Security", result["content"])

    def test_rules_answer_prioritizes_scan_findings(self):
        with patch.object(ai_engine, "GEMINI_API_KEY", ""), patch.object(ai_engine, "OPENAI_API_KEY", ""):
            result = asyncio.run(ai_engine.copilot_respond("What findings were found?", self.scan))
        self.assertIn("Missing HSTS header", result["content"])
        self.assertIn("HIGH", result["content"])

    def test_rules_answer_handles_general_cybersecurity_questions(self):
        with patch.object(ai_engine, "GEMINI_API_KEY", ""), patch.object(ai_engine, "OPENAI_API_KEY", ""):
            result = asyncio.run(ai_engine.copilot_respond("What is phishing and how can I prevent it?", self.scan))
        self.assertEqual(result["source"], "rules")
        self.assertIn("phishing", result["content"].lower())
        self.assertIn("training", result["content"].lower())

        result = asyncio.run(ai_engine.copilot_respond("What is BharatSec?", self.scan))
        self.assertIn("BharatSec", result["content"])

    def test_rules_answer_handles_india_questions(self):
        result = ai_engine._copilot_rules("Who is the PM of India?", self.scan)
        self.assertIn("Narendra Modi", result)

    def test_general_assistant_works_without_provider_keys(self):
        with patch.object(ai_engine, "GEMINI_API_KEY", ""), patch.object(ai_engine, "OPENAI_API_KEY", ""):
            result = asyncio.run(ai_engine.general_ai_respond("What is phishing?"))
        self.assertEqual(result["source"], "rules")
        self.assertIn("phishing", result["content"].lower())
        self.assertIn("mfa", result["content"].lower())

    def test_general_assistant_answers_common_india_questions_without_provider_keys(self):
        with patch.object(ai_engine, "GEMINI_API_KEY", ""), patch.object(ai_engine, "OPENAI_API_KEY", ""):
            prime_minister = asyncio.run(ai_engine.general_ai_respond("Who is the PM of India?"))
            capital = asyncio.run(ai_engine.general_ai_respond("What is the capital of India?"))
            language = asyncio.run(ai_engine.general_ai_respond("Does India have a national language?"))
            national_animal = asyncio.run(ai_engine.general_ai_respond("What is India's national animal?"))

        self.assertIn("Narendra Modi", prime_minister["content"])
        self.assertIn("New Delhi", capital["content"])
        self.assertIn("no national language", language["content"])
        self.assertIn("Bengal tiger", national_animal["content"])
        self.assertIn("security assessment platform", ai_engine._general_knowledge_response("What is BharatSec?"))

    def test_openai_success_avoids_fallback(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"choices": [{"message": {"content": "OpenAI answered successfully"}}]}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, *args, **kwargs):
                return FakeResponse()

        with patch.object(ai_engine, "GEMINI_API_KEY", ""), patch.object(ai_engine, "OPENAI_API_KEY", "sk-test"), patch.object(ai_engine.httpx, "AsyncClient", return_value=FakeClient()):
            result = asyncio.run(ai_engine.general_ai_respond("Tell me about Zero Trust"))
        self.assertEqual(result["source"], "openai")
        self.assertIn("OpenAI answered successfully", result["content"])

    def test_gemini_key_is_sent_in_header_not_url(self):
        calls = []

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"candidates": [{"content": {"parts": [{"text": "Gemini answered"}]}}]}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, **kwargs):
                calls.append((url, kwargs))
                return FakeResponse()

        with patch.object(ai_engine, "GEMINI_API_KEY", "gemini-secret"), patch.object(ai_engine, "OPENAI_API_KEY", ""), patch.object(ai_engine.httpx, "AsyncClient", return_value=FakeClient()):
            result = asyncio.run(ai_engine.general_ai_respond("Tell me about Zero Trust"))

        self.assertEqual(result["source"], "gemini")
        url, kwargs = calls[0]
        self.assertNotIn("gemini-secret", url)
        self.assertNotIn("params", kwargs)
        self.assertEqual(kwargs["headers"]["x-goog-api-key"], "gemini-secret")


if __name__ == "__main__":
    unittest.main()
