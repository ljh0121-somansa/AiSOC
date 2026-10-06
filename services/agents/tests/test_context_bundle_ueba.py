"""UEBA baselines are reachable and authenticated.

Gap-closure: ``_fetch_baselines`` used to point at ``http://ueba:8086`` — the
host-port that belongs to the realtime service, not the UEBA container, whose
internal listener is ``8004`` — and it sent no bearer credential, although
UEBA's router requires one (``require_service_auth`` fails closed with 503
when none is configured). A caller on the wrong port and without a token
would never have baselines, and the failure would read as an unreachable
service rather than a misconfiguration.

These tests pin the two facts that must be true for that gap not to reopen:
the URL carries ``8004``, and a service token (when present in the
environment) is forwarded as ``Authorization: Bearer``.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.context import bundle as module
from app.context.bundle import ContextBundleBuilder, EntityRef


class FakeResponse:
    def __init__(self, payload: Any, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    @property
    def headers(self) -> dict[str, str]:
        return {"content-type": "application/json"}


class FakeClient:
    """Stands in for httpx.AsyncClient; records the request it was given."""

    calls: list[tuple[str, dict[str, Any]]] = []

    def __init__(self, payload: Any = None, *, boom: Exception | None = None) -> None:
        self._payload = payload
        self._boom = boom

    def __call__(self, *args: Any, **kwargs: Any) -> FakeClient:
        return self

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        FakeClient.calls.append((url, kwargs))
        if self._boom is not None:
            raise self._boom
        return FakeResponse(self._payload)


@pytest.fixture(autouse=True)
def _reset_calls() -> None:
    FakeClient.calls = []


def _patch_client(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> None:
    monkeypatch.setattr(module.httpx, "AsyncClient", client)


_ENTITY = EntityRef(type="user", value="svc_backup")


class TestFetchBaselines:
    async def test_ueba_url_is_the_internal_8004_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The default must point at the UEBA container's listener (8004), not
        an unrelated host port, or every lookup is a connection refusal."""
        _patch_client(monkeypatch, FakeClient([]))
        await ContextBundleBuilder()._fetch_baselines("t-1", [_ENTITY])

        url, _ = FakeClient.calls[0]
        assert url.startswith("http://ueba:8004/api/v1/ueba/baselines")

    async def test_a_service_token_is_forwarded_as_bearer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SERVICE_TOKEN", "shared-secret")
        _patch_client(monkeypatch, FakeClient([]))
        await ContextBundleBuilder()._fetch_baselines("t-1", [_ENTITY])

        _url, kwargs = FakeClient.calls[0]
        assert kwargs["headers"]["Authorization"] == "Bearer shared-secret"

    async def test_the_tenant_is_declared_on_the_service_token_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """UEBA refuses a service token with 403 unless it declares its tenant
        on X-AiSOC-Tenant-ID, so the header is required here (the query param
        the route ignores for the token path)."""
        monkeypatch.setenv("AISOC_SERVICE_TOKEN", "shared-secret")
        _patch_client(monkeypatch, FakeClient([]))
        await ContextBundleBuilder()._fetch_baselines("tenant-a", [_ENTITY])

        _url, kwargs = FakeClient.calls[0]
        assert kwargs["headers"]["X-AiSOC-Tenant-ID"] == "tenant-a"
        # The tenant rides the header, not the query, in the token path.
        assert "tenant_id" not in kwargs.get("params", {})

    async def test_precedence_prefers_the_agents_service_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SERVICE_TOKEN", "shared-secret")
        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "agents-secret")
        _patch_client(monkeypatch, FakeClient([]))
        await ContextBundleBuilder()._fetch_baselines("t-1", [_ENTITY])

        _url, kwargs = FakeClient.calls[0]
        assert kwargs["headers"]["Authorization"] == "Bearer agents-secret"

    async def test_no_token_means_no_bearer_header_is_sent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without a token there is nothing to send; a missing credential is
        not invented. UEBA then answers per its own auth policy."""
        monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
        monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
        _patch_client(monkeypatch, FakeClient([]))
        await ContextBundleBuilder()._fetch_baselines("t-1", [_ENTITY])

        _url, kwargs = FakeClient.calls[0]
        assert "Authorization" not in kwargs.get("headers", {})

    async def test_a_matching_baseline_row_is_mapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, FakeClient([
            {"entity_id": "svc_backup", "peer_group_id": "g1", "deviation_score": 0.42},
            {"entity_id": "someone_else"},
        ]))
        out = await ContextBundleBuilder()._fetch_baselines("t-1", [_ENTITY])

        assert set(out) == {"user:svc_backup"}
        assert out["user:svc_backup"].peer_group_id == "g1"
        assert out["user:svc_backup"].deviation_score == 0.42

    async def test_unreachable_ueba_degrades_cleanly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A refusal to connect must not raise: the agent still gets built,
        only without UEBA-blessed baselines."""
        _patch_client(monkeypatch, FakeClient(payload=None, boom=RuntimeError("connection refused")))
        out = await ContextBundleBuilder()._fetch_baselines("t-1", [_ENTITY])

        assert out == {}
