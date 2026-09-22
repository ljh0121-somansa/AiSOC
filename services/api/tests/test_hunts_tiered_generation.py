"""Tests for Hunt Query Tiered Generation (Tier 1 -> Tier 2 -> Tier 3).

Verifies the 3-tiered execution strategy under standard and air-gapped modes.
"""

from __future__ import annotations

import pytest
import uuid
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.llm_resolver import LlmConfig
from app.services.hunt_query_generator import generate_queries_tiered


@pytest.fixture
def mock_db():
    return MagicMock()


@pytest.fixture
def mock_tenant_id():
    return uuid.uuid4()


@pytest.mark.asyncio
async def test_tier1_standard_openai_success(mock_db, mock_tenant_id):
    """Tier 1 Test: Standard environment, airgap disabled.

    Mocks a successful OpenAI API response.
    """
    mock_config = LlmConfig(
        allowed=True,
        base_url="https://api.openai.com/v1",
        model="gpt-4o-mini",
        api_key="sk-test-key",
        source="environment",
        reason=""
    )

    mock_response = httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": '{"esql": "FROM logs | KEEP a", "spl": "index=a", "kql": "SecurityEvent | limit 10"}'
                    }
                }
            ]
        }
    )

    with patch("app.services.hunt_query_generator.resolve_llm_config", new_callable=AsyncMock) as mock_resolve, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        
        mock_resolve.return_value = mock_config
        mock_post.return_value = mock_response

        res = await generate_queries_tiered(mock_db, mock_tenant_id, "Find anomalous network activity", "T1041")

        mock_resolve.assert_called_once_with(mock_db, mock_tenant_id)
        assert res["query_generation_mode"] == "ai"
        assert res["warnings"] is None
        assert res["esql"] == "FROM logs | KEEP a"
        assert res["spl"] == "index=a"
        assert res["kql"] == "SecurityEvent | limit 10"


@pytest.mark.asyncio
async def test_tier2_airgapped_private_llm_success(mock_db, mock_tenant_id):
    """Tier 2 Test: Airgap is enabled, but private LLM is on allowlist.

    The outbound private LLM call should be allowed and return AI queries.
    """
    mock_config = LlmConfig(
        allowed=True,
        base_url="https://qwen.proxy.ainexus.ktcloud.com/v1",
        model="Qwen2.5-72B-Instruct-AWQ",
        api_key="vllm-no-key-needed",
        source="tenant",
        reason=""
    )

    mock_response = httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": '{"esql": "FROM logs-private", "spl": "index=private", "kql": "PrivateEvent"}'
                    }
                }
            ]
        }
    )

    with patch("app.services.hunt_query_generator.resolve_llm_config", new_callable=AsyncMock) as mock_resolve, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        
        mock_resolve.return_value = mock_config
        mock_post.return_value = mock_response

        res = await generate_queries_tiered(mock_db, mock_tenant_id, "Find lateral movement", "T1021")

        assert res["query_generation_mode"] == "ai"
        assert res["warnings"] is None
        assert "private" in res["esql"]


@pytest.mark.asyncio
async def test_tier3_airgapped_private_llm_failure(mock_db, mock_tenant_id):
    """Tier 3 Test: Airgap is enabled, private LLM is allowed but unreachable (times out).

    Should gracefully catch exception and fallback to deterministic templates.
    """
    mock_config = LlmConfig(
        allowed=True,
        base_url="https://qwen.proxy.ainexus.ktcloud.com/v1",
        model="Qwen2.5-72B-Instruct-AWQ",
        api_key="vllm-no-key-needed",
        source="tenant",
        reason=""
    )

    with patch("app.services.hunt_query_generator.resolve_llm_config", new_callable=AsyncMock) as mock_resolve, \
         patch("httpx.AsyncClient.post", side_effect=httpx.ConnectTimeout("Connection timed out")):
        
        mock_resolve.return_value = mock_config

        res = await generate_queries_tiered(mock_db, mock_tenant_id, "Find phishing attempts", "T1566")

        assert res["query_generation_mode"] == "fallback"
        assert res["warnings"] == "Local/private LLM was unreachable or returned an invalid response."
        assert "FROM logs-*" in res["esql"]
        assert "phishing" in res["esql"]


@pytest.mark.asyncio
async def test_tier3_airgapped_no_allowlist_direct_fallback(mock_db, mock_tenant_id):
    """Tier 3 Test: Airgap is enabled, public LLM is blocked, no local LLM allowed.

    Should directly fallback without calling HTTP.
    """
    mock_config = LlmConfig(
        allowed=False,
        base_url="https://api.openai.com",
        model="gpt-4o-mini",
        api_key=None,
        source="environment",
        reason="AISOC_AIRGAPPED is on and base_url points at api.openai.com."
    )

    with patch("app.services.hunt_query_generator.resolve_llm_config", new_callable=AsyncMock) as mock_resolve, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        
        mock_resolve.return_value = mock_config

        res = await generate_queries_tiered(mock_db, mock_tenant_id, "Find ransomware footprint", "T1486")

        # Must NOT call HTTP at all
        mock_post.assert_not_called()

        assert res["query_generation_mode"] == "fallback"
        assert res["warnings"] == "AISOC_AIRGAPPED is on and base_url points at api.openai.com."
        assert "FROM logs-*" in res["esql"]
        assert "ransomware" in res["esql"]
