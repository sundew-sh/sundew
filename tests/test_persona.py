"""Tests for persona variation — verifies that different personas produce unique outputs.

Generates 10 personas and verifies that no two share identical response bodies,
endpoint paths, response headers, or timing configurations.
"""

from __future__ import annotations

import json

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from sundew.models import Persona  # noqa: TCH001
from sundew.persona.generator import generate_persona
from sundew.traps.api import create_api_router
from sundew.traps.discovery import create_discovery_router
from sundew.traps.mcp import create_mcp_router

SEEDS = list(range(10, 20))  # 10 different seeds


def _generate_personas() -> list[Persona]:
    """Generate 10 unique personas."""
    return [generate_persona(seed) for seed in SEEDS]


def _make_app(persona: Persona) -> FastAPI:
    """Create a test app for a given persona."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.include_router(create_mcp_router(persona))
    app.include_router(create_api_router(persona))
    app.include_router(create_discovery_router(persona))
    return app


# ---------------------------------------------------------------------------
# Persona Identity Variation
# ---------------------------------------------------------------------------


class TestPersonaVariation:
    """Verify that 10 personas produce sufficiently unique outputs."""

    def test_unique_company_names(self) -> None:
        """All 10 personas should have unique company names."""
        personas = _generate_personas()
        names = [p.company_name for p in personas]
        assert len(set(names)) == len(names), f"Duplicate company names: {names}"

    def test_unique_seeds(self) -> None:
        """All 10 personas should have unique seeds."""
        personas = _generate_personas()
        seeds = [p.seed for p in personas]
        assert len(set(seeds)) == len(seeds)

    def test_varied_industries(self) -> None:
        """10 personas should cover at least 3 different industries."""
        personas = _generate_personas()
        industries = {p.industry for p in personas}
        assert len(industries) >= 3, f"Only {len(industries)} industries: {industries}"

    def test_varied_frameworks(self) -> None:
        """10 personas should have at least 3 different framework fingerprints."""
        personas = _generate_personas()
        frameworks = {p.framework_fingerprint for p in personas}
        assert len(frameworks) >= 3, f"Only {len(frameworks)} frameworks: {frameworks}"

    def test_varied_server_headers(self) -> None:
        """10 personas should have at least 3 different server headers."""
        personas = _generate_personas()
        headers = {p.server_header for p in personas}
        assert len(headers) >= 3

    def test_varied_endpoint_prefixes(self) -> None:
        """10 personas should have at least 2 different endpoint prefixes."""
        personas = _generate_personas()
        prefixes = {p.endpoint_prefix for p in personas}
        assert len(prefixes) >= 2

    def test_varied_latencies(self) -> None:
        """10 personas should have at least 3 different latency values."""
        personas = _generate_personas()
        latencies = {p.response_latency_ms for p in personas}
        assert len(latencies) >= 3

    def test_varied_auth_schemes(self) -> None:
        """10 personas should have at least 2 different auth schemes."""
        personas = _generate_personas()
        schemes = {p.auth_scheme for p in personas}
        assert len(schemes) >= 2

    def test_varied_mcp_tool_prefixes(self) -> None:
        """10 personas should have at least 3 different MCP tool prefixes."""
        personas = _generate_personas()
        prefixes = {p.mcp_tool_prefix for p in personas}
        assert len(prefixes) >= 3


# ---------------------------------------------------------------------------
# Endpoint Output Variation
# ---------------------------------------------------------------------------


class TestEndpointVariation:
    """Verify that different personas produce different API outputs."""

    async def test_unique_mcp_tool_lists(self) -> None:
        """Different personas should expose different MCP tool names."""
        personas = _generate_personas()
        tool_sets: list[frozenset[str]] = []

        for persona in personas:
            app = _make_app(persona)
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
            names = frozenset(t["name"] for t in tools)
            tool_sets.append(names)

        # At least 3 unique tool sets among 10 personas
        unique_sets = set(tool_sets)
        assert len(unique_sets) >= 3, f"Only {len(unique_sets)} unique tool sets among 10 personas"

    async def test_unique_ai_plugin_manifests(self) -> None:
        """Different personas should produce different ai-plugin.json content."""
        personas = _generate_personas()
        manifests: list[str] = []

        for persona in personas:
            app = _make_app(persona)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/.well-known/ai-plugin.json")
            manifests.append(json.dumps(resp.json(), sort_keys=True))

        unique = set(manifests)
        assert len(unique) == len(manifests), (
            f"Only {len(unique)} unique ai-plugin.json manifests out of {len(manifests)}"
        )

    async def test_unique_robots_txt(self) -> None:
        """Different personas should produce different robots.txt content."""
        personas = _generate_personas()
        robots: list[str] = []

        for persona in personas:
            app = _make_app(persona)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/robots.txt")
            robots.append(resp.text)

        unique = set(robots)
        # At least 3 unique robots.txt variants
        assert len(unique) >= 3, (
            f"Only {len(unique)} unique robots.txt among {len(robots)} personas"
        )

    async def test_unique_openapi_specs(self) -> None:
        """Different personas should produce different OpenAPI specs."""
        personas = _generate_personas()
        specs: list[str] = []

        for persona in personas:
            app = _make_app(persona)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/openapi.json")
            specs.append(json.dumps(resp.json(), sort_keys=True))

        unique = set(specs)
        assert len(unique) == len(specs), (
            f"Only {len(unique)} unique OpenAPI specs out of {len(specs)}"
        )

    async def test_unique_auth_tokens(self) -> None:
        """Different personas should produce different auth token structures."""
        personas = _generate_personas()
        token_keys: list[frozenset[str]] = []

        for persona in personas:
            app = _make_app(persona)
            prefix = persona.endpoint_prefix.rstrip("/")
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"{prefix}/auth/token",
                    json={"username": "test", "password": "test"},
                )
            keys = frozenset(resp.json().keys())
            token_keys.append(keys)

        # At least 2 different token response structures
        unique_structures = set(token_keys)
        assert len(unique_structures) >= 2, (
            f"Only {len(unique_structures)} unique auth response structures"
        )

    async def test_no_shared_response_bodies(self) -> None:
        """Two different personas should not return identical list responses."""
        p1 = generate_persona(42)
        p2 = generate_persona(99)

        async def get_list_body(persona: Persona) -> str:
            app = _make_app(persona)
            prefix = persona.endpoint_prefix.rstrip("/")
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get(f"{prefix}/test-resource")
            return json.dumps(resp.json(), sort_keys=True)

        body1 = await get_list_body(p1)
        body2 = await get_list_body(p2)
        assert body1 != body2, "Two personas returned identical response bodies"
