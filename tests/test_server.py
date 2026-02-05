"""Tests for the FastAPI server."""

import pytest
from httpx import ASGITransport, AsyncClient

from sundew.config import SundewConfig
from sundew.server import SundewServer, _path_matches


def test_path_matches_exact() -> None:
    """Exact paths should match."""
    assert _path_matches("/api/v1/users", "/api/v1/users") is True


def test_path_matches_variable() -> None:
    """Paths with {{variable}} segments should match any value."""
    assert _path_matches("/api/v1/users/abc123", "/api/v1/users/{{random_id}}") is True


def test_path_matches_mismatch() -> None:
    """Non-matching paths should return False."""
    assert _path_matches("/api/v1/users", "/api/v1/payments") is False


def test_path_matches_length_mismatch() -> None:
    """Paths with different segment counts should not match."""
    assert _path_matches("/api/v1/users/abc/extra", "/api/v1/users/{{id}}") is False


@pytest.mark.asyncio
async def test_health_endpoint() -> None:
    """The /health endpoint should return 200 OK."""
    config = SundewConfig()
    config.llm.provider = "none"
    server = SundewServer(config)

    transport = ASGITransport(app=server.app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_catch_all_returns_response() -> None:
    """Unknown paths should still return a response (not crash)."""
    config = SundewConfig()
    config.llm.provider = "none"
    server = SundewServer(config)

    transport = ASGITransport(app=server.app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/anything")
        assert response.status_code in (200, 404, 503)
