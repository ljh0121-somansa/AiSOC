"""Tests for agent LLM response parsing and error handling across agents.

Verifies that empty responses, non-JSON strings, reasoning model tags (<think>...</think>),
markdown fences, and malformed JSON are handled cleanly without raising unhandled JSONDecodeError.
"""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch
from typing import Any

from app.agents.auto_triage_agent import _parse_llm_response
from app.agents.cloud_agent import _parse_response as _parse_cloud_response
from app.agents.identity_agent import _parse_response as _parse_identity_response
from app.agents.insider_threat_agent import _parse_response as _parse_insider_response
from app.agents.phishing_agent import _parse_response as _parse_phishing_response
from app.investigator.utils import normalize_string_list


class TestAgentLLMResponseParsing(unittest.TestCase):
    def test_auto_triage_valid_json(self) -> None:
        raw = '{"verdict": "false_positive", "confidence": 0.95, "rationale": "Authorized scan."}'
        res = _parse_llm_response(raw)
        self.assertEqual(res["verdict"], "false_positive")
        self.assertAlmostEqual(res["confidence"], 0.95)
        self.assertEqual(res["rationale"], "Authorized scan.")

    def test_auto_triage_markdown_fences(self) -> None:
        raw = '```json\n{"verdict": "benign", "confidence": 0.8, "rationale": "Expected activity."}\n```'
        res = _parse_llm_response(raw)
        self.assertEqual(res["verdict"], "benign")
        self.assertAlmostEqual(res["confidence"], 0.8)

    def test_auto_triage_reasoning_tags(self) -> None:
        raw = '<think>Analyzing alert severity...</think> {"verdict": "true_positive", "confidence": 0.9, "rationale": "Malicious payload."}'
        res = _parse_llm_response(raw)
        self.assertEqual(res["verdict"], "true_positive")
        self.assertAlmostEqual(res["confidence"], 0.9)

    def test_auto_triage_empty_response_fallback(self) -> None:
        res = _parse_llm_response("")
        self.assertEqual(res["verdict"], "true_positive")
        self.assertEqual(res["confidence"], 0.5)

    def test_auto_triage_invalid_json_fallback(self) -> None:
        res = _parse_llm_response("I am an AI assistant and cannot perform this classification.")
        self.assertEqual(res["verdict"], "true_positive")
        self.assertEqual(res["confidence"], 0.5)

    def test_auto_triage_type_coercion(self) -> None:
        raw = '{"verdict": "unknown_verdict", "confidence": "0.75", "rationale": "Test"}'
        res = _parse_llm_response(raw)
        self.assertEqual(res["verdict"], "true_positive")  # fallback for invalid verdict
        self.assertAlmostEqual(res["confidence"], 0.75)

    def test_cloud_agent_parsing(self) -> None:
        raw = '{"verdict": "false_positive", "confidence": 0.9, "cloud_indicators": ["public_bucket"], "risk_category": "storage_exposure", "cloud_provider": "aws", "rationale": "Public by design."}'
        res = _parse_cloud_response(raw)
        self.assertEqual(res["verdict"], "false_positive")
        self.assertEqual(res["cloud_indicators"], ["public_bucket"])
        self.assertEqual(res["risk_category"], "storage_exposure")
        self.assertEqual(res["cloud_provider"], "aws")

    def test_cloud_agent_invalid_json_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            _parse_cloud_response("No JSON provided")

    def test_identity_agent_parsing(self) -> None:
        raw = '{"verdict": "true_positive", "confidence": 0.85, "identity_indicators": ["impossible_travel"], "attack_type": "credential_stuffing", "rationale": "Suspicious login."}'
        res = _parse_identity_response(raw)
        self.assertEqual(res["verdict"], "true_positive")
        self.assertEqual(res["identity_indicators"], ["impossible_travel"])
        self.assertEqual(res["attack_type"], "credential_stuffing")

    def test_insider_threat_agent_parsing(self) -> None:
        raw = '{"verdict": "true_positive", "confidence": 0.88, "threat_indicators": ["bulk_download"], "threat_category": "data_exfiltration", "user_risk_level": "high", "rationale": "Mass download."}'
        res = _parse_insider_response(raw)
        self.assertEqual(res["verdict"], "true_positive")
        self.assertEqual(res["user_risk_level"], "high")

    def test_phishing_agent_parsing(self) -> None:
        raw = '{"verdict": "benign", "confidence": 0.92, "phishing_indicators": [], "rationale": "Internal newsletter."}'
        res = _parse_phishing_response(raw)
        self.assertEqual(res["verdict"], "benign")
        self.assertEqual(res["phishing_indicators"], [])

    def test_normalize_string_list_dict_items(self) -> None:
        dict_items = [{'name': 'Unknown / Opportunistic Attacker', 'evidence': '일치'}]
        res = normalize_string_list(dict_items)
        self.assertEqual(res, ['Unknown / Opportunistic Attacker'])

    def test_normalize_string_list_various_inputs(self) -> None:
        self.assertEqual(normalize_string_list(['APT28', 'LockBit']), ['APT28', 'LockBit'])
        self.assertEqual(normalize_string_list('SingleString'), ['SingleString'])
        self.assertEqual(normalize_string_list([{'id': 'T1566.001'}]), ['T1566.001'])
        self.assertEqual(normalize_string_list(None), [])

    @patch("httpx.AsyncClient.post")
    def test_enrich_ioc_payload_key(self, mock_post: Any) -> None:
        import asyncio
        from unittest.mock import MagicMock
        from app.investigator.tools import enrich_ioc
        
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": "8.8.8.8", "risk_score": 0}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        res = asyncio.run(enrich_ioc("8.8.8.8", "ip"))
        self.assertEqual(res["risk_score"], 0)
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"], {"value": "8.8.8.8", "ioc_type": "ip"})

    def test_forensic_agent_key_mapping_fallback(self) -> None:
        llm_result = {
            "forensic_summary": "포렌식 요약 테스트",
            "root_cause_analysis": "근본 원인 분석 테스트",
            "attack_timeline": [{"timestamp": "2026-08-19", "description": "이벤트"}],
            "compromised_assets": {"hosts": ["srv-01"], "identities": ["admin"]},
            "confidence": 0.9,
        }
        summary_str = str(llm_result.get("summary") or llm_result.get("forensic_summary") or "")
        root_cause_str = str(llm_result.get("root_cause_hypothesis") or llm_result.get("root_cause_analysis") or "")
        timeline_data = llm_result.get("timeline") or llm_result.get("attack_timeline") or []
        blast_val = llm_result.get("blast_radius") or llm_result.get("compromised_assets") or ""

        self.assertEqual(summary_str, "포렌식 요약 테스트")
        self.assertEqual(root_cause_str, "근본 원인 분석 테스트")
        self.assertEqual(len(timeline_data), 1)
        self.assertIn("srv-01", str(blast_val))


if __name__ == "__main__":
    unittest.main()
