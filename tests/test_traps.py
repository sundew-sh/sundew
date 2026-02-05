"""Tests for trap endpoints: MCP server, REST API, and AI discovery."""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from sundew.models import Persona  # noqa: TCH001
from sundew.persona.generator import generate_persona
from sundew.traps.api import create_api_router
from sundew.traps.discovery import create_discovery_router
from sundew.traps.mcp import create_mcp_router

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_app(persona: Persona) -> FastAPI:
    """Create a test FastAPI app with all trap routers mounted."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.include_router(create_mcp_router(persona))
    app.include_router(create_api_router(persona))
    app.include_router(create_discovery_router(persona))
    return app


@pytest.fixture(params=["fintech", "saas", "healthcare"])
def persona_by_industry(request: pytest.FixtureRequest) -> Persona:
    """Generate a persona for each of the 3 primary industries."""
    industry_seeds = {"fintech": 100, "saas": 200, "healthcare": 300}
    seed = industry_seeds[request.param]
    p = generate_persona(seed)
    # Force the desired industry for deterministic testing
    return p.model_copy(update={"industry": request.param})


@pytest.fixture
def fintech_persona() -> Persona:
    """A deterministic fintech persona for targeted tests."""
    p = generate_persona(42)
    return p.model_copy(update={"industry": "fintech"})


@pytest.fixture
def saas_persona() -> Persona:
    """A deterministic SaaS persona for targeted tests."""
    p = generate_persona(99)
    return p.model_copy(update={"industry": "saas"})


@pytest.fixture
def healthcare_persona() -> Persona:
    """A deterministic healthcare persona for targeted tests."""
    p = generate_persona(77)
    return p.model_copy(update={"industry": "healthcare"})


# ---------------------------------------------------------------------------
# MCP Server Trap Tests
# ---------------------------------------------------------------------------


class TestMCPTrap:
    """Tests for the MCP JSON-RPC server trap."""

    async def test_initialize(self, fintech_persona: Persona) -> None:
        """MCP initialize should return protocol version and capabilities."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {},
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] == 1
        assert "protocolVersion" in data["result"]
        assert "capabilities" in data["result"]
        assert "serverInfo" in data["result"]

    async def test_tools_list(self, fintech_persona: Persona) -> None:
        """tools/list should return persona-appropriate tool definitions."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
            )
        data = resp.json()
        tools = data["result"]["tools"]
        assert len(tools) == 4
        # Fintech tools should include transaction-related names
        tool_names = [t["name"] for t in tools]
        assert any("transaction" in n for n in tool_names)

    async def test_tools_call(self, fintech_persona: Persona) -> None:
        """tools/call should return interpolated response with canary tokens."""
        prefix = fintech_persona.mcp_tool_prefix
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": f"{prefix}query_transactions",
                        "arguments": {"account_id": "acc_123"},
                    },
                },
            )
        data = resp.json()
        assert "result" in data
        content = data["result"]["content"]
        assert len(content) > 0
        assert content[0]["type"] == "text"
        # Verify canary tokens are present (not template placeholders)
        text = content[0]["text"]
        assert "{{canary" not in text

    async def test_unknown_tool(self, fintech_persona: Persona) -> None:
        """Calling an unknown tool should return a JSON-RPC error."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "nonexistent_tool", "arguments": {}},
                },
            )
        data = resp.json()
        assert "error" in data
        assert data["error"]["code"] == -32602

    async def test_unknown_method(self, fintech_persona: Persona) -> None:
        """Calling an unknown JSON-RPC method should return method-not-found."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "unknown/method",
                    "params": {},
                },
            )
        data = resp.json()
        assert "error" in data
        assert data["error"]["code"] == -32601

    async def test_invalid_json(self, fintech_persona: Persona) -> None:
        """Sending invalid JSON should return a parse error."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                content="not json",
                headers={"content-type": "application/json"},
            )
        data = resp.json()
        assert "error" in data
        assert data["error"]["code"] == -32700

    async def test_persona_headers(self, fintech_persona: Persona) -> None:
        """MCP responses should include persona-appropriate headers."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {},
                },
            )
        assert resp.headers.get("server") == fintech_persona.server_header

    async def test_saas_tools(self, saas_persona: Persona) -> None:
        """SaaS persona should have user/workspace related tools."""
        app = _make_app(saas_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                },
            )
        tools = resp.json()["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert any("user" in n for n in tool_names)
        assert any("api_key" in n for n in tool_names)

    async def test_healthcare_tools(self, healthcare_persona: Persona) -> None:
        """Healthcare persona should have patient/prescription related tools."""
        app = _make_app(healthcare_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                },
            )
        tools = resp.json()["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert any("patient" in n for n in tool_names)

    async def test_notifications_initialized(self, fintech_persona: Persona) -> None:
        """notifications/initialized should return empty 200."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# REST API Trap Tests
# ---------------------------------------------------------------------------


class TestAPITrap:
    """Tests for the adaptive REST API trap."""

    async def test_auth_token(self, fintech_persona: Persona) -> None:
        """Auth endpoint should accept any credentials and return a token."""
        app = _make_app(fintech_persona)
        prefix = fintech_persona.endpoint_prefix.rstrip("/")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"{prefix}/auth/token",
                json={"username": "test", "password": "test"},
            )
        assert resp.status_code == 200
        data = resp.json()
        # Should have some token-like field
        assert any(k in data for k in ["token", "access_token", "api_key", "session_id"])

    async def test_list_resources(self, fintech_persona: Persona) -> None:
        """GET on a resource path should return paginated data with canary tokens."""
        app = _make_app(fintech_persona)
        prefix = fintech_persona.endpoint_prefix.rstrip("/")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"{prefix}/transactions")
        assert resp.status_code == 200
        data = resp.json()
        assert "data" in data
        assert "meta" in data
        assert data["meta"]["page"] == 1
        # Verify no unresolved placeholders
        raw = json.dumps(data)
        assert "{{" not in raw

    async def test_detail_resource(self, fintech_persona: Persona) -> None:
        """GET on a resource/id path should return a detail response."""
        app = _make_app(fintech_persona)
        prefix = fintech_persona.endpoint_prefix.rstrip("/")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"{prefix}/transactions/txn_123")
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        raw = json.dumps(data)
        assert "{{" not in raw

    async def test_create_resource(self, saas_persona: Persona) -> None:
        """POST on a resource path should return 201 with a new resource."""
        app = _make_app(saas_persona)
        prefix = saas_persona.endpoint_prefix.rstrip("/")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"{prefix}/users",
                json={"name": "Test User", "email": "test@test.com"},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"

    async def test_rate_limit_headers(self, fintech_persona: Persona) -> None:
        """API responses should include rate limit headers."""
        app = _make_app(fintech_persona)
        prefix = fintech_persona.endpoint_prefix.rstrip("/")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"{prefix}/transactions")
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-remaining" in resp.headers
        assert "x-ratelimit-reset" in resp.headers

    async def test_server_header(self, fintech_persona: Persona) -> None:
        """API responses should include the persona's Server header."""
        app = _make_app(fintech_persona)
        prefix = fintech_persona.endpoint_prefix.rstrip("/")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"{prefix}/transactions")
        assert resp.headers.get("server") == fintech_persona.server_header

    async def test_pagination_params(self, saas_persona: Persona) -> None:
        """Pagination parameters should be reflected in the response."""
        app = _make_app(saas_persona)
        prefix = saas_persona.endpoint_prefix.rstrip("/")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"{prefix}/users?page=3&per_page=10")
        data = resp.json()
        assert data["meta"]["page"] == 3
        assert data["meta"]["per_page"] == 10

    async def test_swagger_docs(self, fintech_persona: Persona) -> None:
        """The Swagger/OpenAPI docs endpoint should return a valid spec."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        # Find the docs path for this persona
        from sundew.traps.api import _docs_path

        docs_url = _docs_path(fintech_persona)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(docs_url)
        assert resp.status_code == 200
        data = resp.json()
        assert "openapi" in data
        assert "paths" in data
        assert "info" in data


# ---------------------------------------------------------------------------
# Discovery Endpoint Tests
# ---------------------------------------------------------------------------


class TestDiscoveryTrap:
    """Tests for the AI discovery endpoints."""

    async def test_ai_plugin_json(self, fintech_persona: Persona) -> None:
        """/.well-known/ai-plugin.json should return a valid plugin manifest."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/ai-plugin.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["schema_version"] == "v1"
        assert "name_for_human" in data
        assert "name_for_model" in data
        assert fintech_persona.company_name in data["name_for_human"]

    async def test_mcp_json(self, saas_persona: Persona) -> None:
        """/.well-known/mcp.json should return MCP discovery info."""
        app = _make_app(saas_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/mcp.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "mcp_version" in data
        assert "server" in data
        assert data["server"]["name"] == saas_persona.mcp_server_name
        assert "endpoints" in data

    async def test_robots_txt(self, healthcare_persona: Persona) -> None:
        """/robots.txt should contain Disallow entries for trap paths."""
        app = _make_app(healthcare_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/robots.txt")
        assert resp.status_code == 200
        text = resp.text
        assert "User-agent: *" in text
        assert "Disallow:" in text
        assert "Sitemap:" in text
        # Healthcare persona should disallow patient paths
        assert "patients" in text

    async def test_sitemap_xml(self, fintech_persona: Persona) -> None:
        """/sitemap.xml should be valid XML with trap URLs."""
        app = _make_app(fintech_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/sitemap.xml")
        assert resp.status_code == 200
        assert "application/xml" in resp.headers["content-type"]
        text = resp.text
        assert '<?xml version="1.0"' in text
        assert "<urlset" in text
        assert "<loc>" in text

    async def test_openapi_json(self, saas_persona: Persona) -> None:
        """/openapi.json should return a valid OpenAPI spec."""
        app = _make_app(saas_persona)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["openapi"] == "3.0.3"
        assert saas_persona.company_name in data["info"]["title"]
        assert len(data["paths"]) > 0

    async def test_discovery_uses_persona_company(self, persona_by_industry: Persona) -> None:
        """All discovery endpoints should reference the persona's company name."""
        app = _make_app(persona_by_industry)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            plugin = await client.get("/.well-known/ai-plugin.json")
            openapi = await client.get("/openapi.json")
        company = persona_by_industry.company_name
        assert company in plugin.json()["name_for_human"]
        assert company in openapi.json()["info"]["title"]
