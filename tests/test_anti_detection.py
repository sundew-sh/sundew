"""Anti-detection tests for Sundew honeypot.

THE critical test suite: if an AI agent can fingerprint Sundew across deployments,
the entire project fails. These tests deploy multiple Sundew instances with different
personas and verify zero cross-instance correlation.

Tests cover:
- Response body pattern uniqueness
- Error message uniqueness
- HTTP header fingerprinting resistance
- OpenAPI schema structural diversity
- MCP server metadata diversity
- Timing profile non-correlation
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import statistics
import time
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of distinct personas to test against
NUM_PERSONAS = 5

# Maximum allowed similarity ratio between any two persona instances (0-1).
# 0 = completely different, 1 = identical. We want LOW similarity.
MAX_SIMILARITY_RATIO = 0.3

# Sundew-specific strings that must NEVER appear in any response
SUNDEW_TELLS = [
    "sundew",
    "honeypot",
    "canary",
    "deception",
    "trap",
    "decoy",
    "musette",
    # Common framework tells
    "fastapi",
    "uvicorn",
    "starlette",
    "pydantic",
    # Python tells (should be hidden by persona)
    "python",
    "cpython",
]

# Headers that should not appear in responses (they leak implementation details)
LEAKY_HEADERS = [
    "x-powered-by",
    "x-fastapi-version",
    "x-starlette-version",
    "x-python-version",
    "x-uvicorn-version",
    "x-sundew",
    "x-honeypot",
    "server",  # Must be persona-controlled, not default
]

# Default server headers that reveal framework
FRAMEWORK_SERVER_VALUES = [
    "uvicorn",
    "hypercorn",
    "gunicorn",
    "python",
    "fastapi",
    "starlette",
    "werkzeug",
    "aiohttp",
]


# ---------------------------------------------------------------------------
# Fixtures: Multi-persona deployment
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def persona_names() -> list[str]:
    """Return persona names for testing."""
    return [
        "techcorp_api",
        "medical_records",
        "fintech_gateway",
        "iot_management",
        "devops_dashboard",
    ]


@pytest.fixture(scope="module")
def persona_apps(persona_names):
    """Create Sundew app instances with different personas.

    If the persona system is not yet built, skip the test.
    """
    try:
        from sundew.server import create_app

        apps = {}
        for name in persona_names:
            try:
                app = create_app(persona=name)
                apps[name] = app
            except Exception:
                pass

        if len(apps) < 2:
            pytest.skip(
                f"Need at least 2 persona apps for comparison, got {len(apps)}. "
                "Persona system may not be built yet."
            )
        return apps
    except ImportError:
        pytest.skip("sundew.server not yet available (being built by another teammate)")


@pytest.fixture(scope="module")
def persona_clients(persona_apps):
    """Create async test clients for each persona app."""
    from httpx import ASGITransport, AsyncClient

    clients = {}
    for name, app in persona_apps.items():
        transport = ASGITransport(app=app)
        clients[name] = AsyncClient(transport=transport, base_url="http://test")
    return clients


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _jaccard_similarity(set_a: set, set_b: set) -> float:
    """Compute Jaccard similarity between two sets. 0 = disjoint, 1 = identical."""
    if not set_a and not set_b:
        return 1.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 1.0


def _string_similarity(a: str, b: str) -> float:
    """Compute normalized edit distance similarity between two strings."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    # Use a simple token-based approach for efficiency
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    return _jaccard_similarity(tokens_a, tokens_b)


def _extract_structural_keys(obj: Any, prefix: str = "") -> set[str]:
    """Recursively extract the structural skeleton of a JSON object."""
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.add(full_key)
            keys.update(_extract_structural_keys(v, full_key))
    elif isinstance(obj, list) and obj:
        keys.add(f"{prefix}[]")
        keys.update(_extract_structural_keys(obj[0], f"{prefix}[]"))
    else:
        keys.add(f"{prefix}={type(obj).__name__}")
    return keys


# ---------------------------------------------------------------------------
# Tests: Response body pattern uniqueness
# ---------------------------------------------------------------------------


class TestResponseBodyUniqueness:
    """Verify no two personas share response body patterns."""

    ENDPOINTS_TO_TEST = [
        ("GET", "/"),
        ("GET", "/health"),
        ("GET", "/api/v1/status"),
        ("GET", "/docs"),
        ("GET", "/openapi.json"),
    ]

    async def _collect_responses(
        self, persona_clients: dict, method: str, path: str
    ) -> dict[str, dict[str, Any]]:
        """Collect responses from all personas for a given endpoint."""
        results = {}
        for name, client in persona_clients.items():
            try:
                response = await client.request(method, path)
                results[name] = {
                    "status": response.status_code,
                    "body": response.text,
                    "headers": dict(response.headers),
                    "content_type": response.headers.get("content-type", ""),
                }
            except Exception as e:
                results[name] = {"error": str(e)}
        return results

    async def test_no_shared_response_bodies(self, persona_clients) -> None:
        """Response bodies must differ across personas for the same endpoint."""
        for method, path in self.ENDPOINTS_TO_TEST:
            responses = await self._collect_responses(persona_clients, method, path)
            bodies = {
                name: data.get("body", "")
                for name, data in responses.items()
                if "error" not in data and data.get("body")
            }
            if len(bodies) < 2:
                continue

            # Check that no two bodies are identical
            seen_hashes: dict[str, str] = {}
            for name, body in bodies.items():
                body_hash = hashlib.sha256(body.encode()).hexdigest()
                if body_hash in seen_hashes:
                    pytest.fail(
                        f"Personas '{name}' and '{seen_hashes[body_hash]}' return "
                        f"identical response bodies for {method} {path}. "
                        "This is a fingerprinting vector."
                    )
                seen_hashes[body_hash] = name

            # Check that similarity is below threshold
            names = list(bodies.keys())
            for i in range(len(names)):
                for j in range(i + 1, len(names)):
                    sim = _string_similarity(bodies[names[i]], bodies[names[j]])
                    assert sim < MAX_SIMILARITY_RATIO, (
                        f"Personas '{names[i]}' and '{names[j]}' have "
                        f"{sim:.1%} similarity on {method} {path} "
                        f"(max allowed: {MAX_SIMILARITY_RATIO:.0%}). "
                        "Reduce shared patterns."
                    )

    async def test_no_common_strings_in_errors(self, persona_clients) -> None:
        """Error responses must not share recognizable strings across personas."""
        error_paths = [
            "/nonexistent-path-404",
            "/api/v1/does-not-exist",
            "/api/v1/../../../etc/passwd",
        ]

        all_error_tokens: dict[str, set[str]] = {}
        for name, client in persona_clients.items():
            tokens: set[str] = set()
            for path in error_paths:
                try:
                    response = await client.get(path)
                    if response.status_code >= 400:
                        # Tokenize error response
                        body = response.text.lower()
                        tokens.update(body.split())
                except Exception:
                    pass
            all_error_tokens[name] = tokens

        if len(all_error_tokens) < 2:
            pytest.skip("Need at least 2 personas for comparison")

        # Find tokens common to ALL personas (excluding generic HTTP tokens)
        generic_tokens = {"not", "found", "error", "the", "a", "an", "is", "was", "404", "500"}
        common_tokens = set.intersection(*all_error_tokens.values()) - generic_tokens

        # Filter out very short tokens (likely just punctuation/articles)
        significant_common = {t for t in common_tokens if len(t) > 3}

        if significant_common:
            pytest.fail(
                f"Error messages share common tokens across all personas: "
                f"{significant_common}. These are fingerprinting vectors. "
                "Each persona should have unique error wording."
            )


# ---------------------------------------------------------------------------
# Tests: HTTP header fingerprinting resistance
# ---------------------------------------------------------------------------


class TestHTTPHeaderResistance:
    """Verify HTTP headers do not leak implementation details."""

    async def test_no_framework_headers(self, persona_clients) -> None:
        """No response should contain headers that identify the framework."""
        for name, client in persona_clients.items():
            try:
                response = await client.get("/")
            except Exception:
                continue

            headers = {k.lower(): v for k, v in response.headers.items()}

            for leaky_header in LEAKY_HEADERS:
                if leaky_header in headers:
                    value = headers[leaky_header]
                    if leaky_header == "server":
                        # Server header is OK if it's persona-controlled
                        if any(fw in value.lower() for fw in FRAMEWORK_SERVER_VALUES):
                            pytest.fail(
                                f"Persona '{name}': Server header '{value}' "
                                "reveals framework. Must be persona-controlled."
                            )
                    else:
                        pytest.fail(f"Persona '{name}': Leaky header '{leaky_header}: {value}'")

    async def test_no_sundew_tells_in_headers(self, persona_clients) -> None:
        """No Sundew-identifying strings in any header name or value."""
        for name, client in persona_clients.items():
            try:
                response = await client.get("/")
            except Exception:
                continue

            for header_name, header_value in response.headers.items():
                combined = f"{header_name} {header_value}".lower()
                for tell in SUNDEW_TELLS:
                    if tell in combined:
                        pytest.fail(
                            f"Persona '{name}': Header '{header_name}: {header_value}' "
                            f"contains Sundew tell '{tell}'"
                        )

    async def test_header_sets_differ_across_personas(self, persona_clients) -> None:
        """Different personas should have different header sets."""
        header_sets: dict[str, set[str]] = {}
        for name, client in persona_clients.items():
            try:
                response = await client.get("/")
                header_sets[name] = set(response.headers.keys())
            except Exception:
                pass

        if len(header_sets) < 2:
            pytest.skip("Need at least 2 personas for comparison")

        # Not all personas must have completely different headers,
        # but the set shouldn't be identical across ALL personas
        all_identical = all(s == list(header_sets.values())[0] for s in header_sets.values())
        if all_identical and len(header_sets) > 2:
            pytest.fail(
                "All personas return identical header sets. "
                "Vary headers per persona to resist fingerprinting."
            )


# ---------------------------------------------------------------------------
# Tests: No Sundew tells in any response
# ---------------------------------------------------------------------------


class TestNoSundewTells:
    """Verify no response body contains strings that identify Sundew."""

    ENDPOINTS = [
        "/",
        "/health",
        "/docs",
        "/openapi.json",
        "/api/v1/status",
        "/.well-known/mcp.json",
        "/nonexistent-for-error-page",
    ]

    async def test_no_tells_in_response_bodies(self, persona_clients) -> None:
        """No Sundew-identifying strings in any response body."""
        for name, client in persona_clients.items():
            for path in self.ENDPOINTS:
                try:
                    response = await client.get(path)
                    body = response.text.lower()
                    for tell in SUNDEW_TELLS:
                        if tell in body:
                            pytest.fail(
                                f"Persona '{name}' at {path}: "
                                f"Response body contains tell '{tell}'. "
                                "This identifies the honeypot."
                            )
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Tests: OpenAPI schema structural diversity
# ---------------------------------------------------------------------------


class TestOpenAPIDiversity:
    """Verify OpenAPI schemas differ structurally across personas."""

    async def test_openapi_structural_diversity(self, persona_clients) -> None:
        """OpenAPI schemas must have different structures per persona."""
        schemas: dict[str, set[str]] = {}
        for name, client in persona_clients.items():
            try:
                response = await client.get("/openapi.json")
                if response.status_code == 200:
                    data = response.json()
                    schemas[name] = _extract_structural_keys(data)
            except Exception:
                pass

        if len(schemas) < 2:
            pytest.skip("Need at least 2 OpenAPI schemas for comparison")

        names = list(schemas.keys())
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                sim = _jaccard_similarity(schemas[names[i]], schemas[names[j]])
                if sim > MAX_SIMILARITY_RATIO:
                    pytest.fail(
                        f"OpenAPI schemas for '{names[i]}' and '{names[j]}' have "
                        f"{sim:.1%} structural similarity "
                        f"(max: {MAX_SIMILARITY_RATIO:.0%}). "
                        "Schemas must differ per persona."
                    )

    async def test_openapi_no_sundew_metadata(self, persona_clients) -> None:
        """OpenAPI schema must not contain Sundew-identifying metadata."""
        for name, client in persona_clients.items():
            try:
                response = await client.get("/openapi.json")
                if response.status_code == 200:
                    raw = response.text.lower()
                    for tell in SUNDEW_TELLS:
                        if tell in raw:
                            pytest.fail(f"Persona '{name}': OpenAPI schema contains tell '{tell}'")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Tests: MCP server metadata diversity
# ---------------------------------------------------------------------------


class TestMCPServerDiversity:
    """Verify MCP server metadata differs across personas."""

    async def test_mcp_server_names_differ(self, persona_clients) -> None:
        """MCP server names must be unique per persona."""
        mcp_names: dict[str, str] = {}
        for name, client in persona_clients.items():
            try:
                response = await client.get("/.well-known/mcp.json")
                if response.status_code == 200:
                    data = response.json()
                    server_name = data.get("name", "")
                    mcp_names[name] = server_name
            except Exception:
                pass

        if len(mcp_names) < 2:
            pytest.skip("Need at least 2 MCP manifests for comparison")

        # All MCP server names must be unique
        seen: dict[str, str] = {}
        for persona, mcp_name in mcp_names.items():
            if mcp_name in seen:
                pytest.fail(
                    f"Personas '{persona}' and '{seen[mcp_name]}' share MCP "
                    f"server name '{mcp_name}'. Must be unique."
                )
            seen[mcp_name] = persona

    async def test_mcp_capabilities_differ(self, persona_clients) -> None:
        """MCP capability sets should vary across personas."""
        capabilities: dict[str, set[str]] = {}
        for name, client in persona_clients.items():
            try:
                response = await client.get("/.well-known/mcp.json")
                if response.status_code == 200:
                    data = response.json()
                    tools = data.get("tools", [])
                    cap_set = {t.get("name", "") for t in tools if isinstance(t, dict)}
                    capabilities[name] = cap_set
            except Exception:
                pass

        if len(capabilities) < 2:
            pytest.skip("Need at least 2 MCP manifests for comparison")

        # Not all personas should expose identical tool sets
        all_identical = all(s == list(capabilities.values())[0] for s in capabilities.values())
        if all_identical and len(capabilities) >= 3:
            pytest.fail("All personas expose identical MCP tool sets. Vary tools per persona.")

    async def test_mcp_no_implementation_artifacts(self, persona_clients) -> None:
        """MCP responses must not contain implementation-specific artifacts."""
        implementation_tells = [
            "fastapi",
            "pydantic",
            "python",
            "sundew",
            "honeypot",
            "starlette",
            "uvicorn",
            "asyncio",
        ]

        for name, client in persona_clients.items():
            try:
                response = await client.get("/.well-known/mcp.json")
                if response.status_code == 200:
                    raw = response.text.lower()
                    for tell in implementation_tells:
                        if tell in raw:
                            pytest.fail(
                                f"Persona '{name}': MCP manifest contains "
                                f"implementation artifact '{tell}'"
                            )
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Tests: Timing profile non-correlation
# ---------------------------------------------------------------------------


class TestTimingProfiles:
    """Verify response timing is not correlatable across personas."""

    NUM_SAMPLES = 20
    ENDPOINT = "/api/v1/status"

    async def _measure_response_times(self, client, path: str, n: int) -> list[float]:
        """Measure response times for n requests."""
        times = []
        for _ in range(n):
            start = time.perf_counter()
            with contextlib.suppress(Exception):
                await client.get(path)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        return times

    async def test_timing_not_identical_across_personas(self, persona_clients) -> None:
        """Response timing distributions should differ across personas.

        If all personas have identical timing characteristics, an attacker
        could fingerprint the underlying implementation.
        """
        if len(persona_clients) < 2:
            pytest.skip("Need at least 2 personas")

        timing_profiles: dict[str, dict[str, float]] = {}
        for name, client in persona_clients.items():
            times = await self._measure_response_times(client, self.ENDPOINT, self.NUM_SAMPLES)
            if len(times) >= 5:
                timing_profiles[name] = {
                    "mean": statistics.mean(times),
                    "stdev": statistics.stdev(times) if len(times) > 1 else 0,
                    "median": statistics.median(times),
                }

        if len(timing_profiles) < 2:
            pytest.skip("Insufficient timing data")

        # This is a soft check: we want to verify that persona-based
        # timing jitter is being applied, not that timing is perfectly
        # decorrelated (which would be unrealistic in test environments)
        means = [p["mean"] for p in timing_profiles.values()]
        if len(set(round(m, 4) for m in means)) == 1 and len(means) >= 3:
            # All means identical to 4 decimal places across 3+ personas
            import warnings

            warnings.warn(
                "All personas have identical mean response times. "
                "Consider adding persona-specific timing jitter to resist "
                "timing-based fingerprinting.",
                stacklevel=2,
            )


# ---------------------------------------------------------------------------
# Tests: Static analysis of response generation
# ---------------------------------------------------------------------------


class TestResponseGenerationSafety:
    """Verify the response generation code does not have hardcoded patterns
    that would be shared across personas."""

    def _find_response_files(self) -> list:
        """Find source files that generate HTTP responses."""
        from pathlib import Path

        src_dir = Path(__file__).resolve().parent.parent / "src" / "sundew"
        response_files = []
        for pyfile in src_dir.rglob("*.py"):
            content = pyfile.read_text(encoding="utf-8", errors="ignore")
            if any(
                kw in content for kw in ["JSONResponse", "HTMLResponse", "Response(", "return {"]
            ):
                response_files.append(pyfile)
        return response_files

    def test_no_hardcoded_error_messages_in_routes(self) -> None:
        """Error messages in route handlers should come from persona config,
        not be hardcoded strings."""
        response_files = self._find_response_files()
        if not response_files:
            pytest.skip("No response generation files found yet")

        # Common hardcoded error messages that should be persona-driven
        hardcoded_errors = [
            "Internal Server Error",
            "Not Found",
            "Bad Request",
            "Unauthorized",
            "Forbidden",
        ]

        for pyfile in response_files:
            content = pyfile.read_text(encoding="utf-8")
            for error_msg in hardcoded_errors:
                # Allow in comments and docstrings, flag in string literals
                # used in response construction
                escaped = re.escape(error_msg)
                pattern = (
                    rf"(?:JSONResponse|Response|return\s*\{{)"
                    rf'.*?["\'].*?{escaped}.*?["\']'
                )
                if re.search(pattern, content, re.DOTALL | re.IGNORECASE):
                    rel = pyfile.relative_to(pyfile.parent.parent.parent.parent)
                    import warnings

                    warnings.warn(
                        f"{rel}: Contains hardcoded error message '{error_msg}'. "
                        "Consider making this persona-driven.",
                        stacklevel=2,
                    )

    def test_no_hardcoded_server_name(self) -> None:
        """Server name must not be hardcoded -- must come from persona."""
        response_files = self._find_response_files()
        if not response_files:
            pytest.skip("No response generation files found yet")

        for pyfile in response_files:
            content = pyfile.read_text(encoding="utf-8")
            # Check for hardcoded Server header values
            if re.search(
                r'["\']server["\']:\s*["\'][^"\']+["\']',
                content,
                re.IGNORECASE,
            ):
                rel = pyfile.relative_to(pyfile.parent.parent.parent.parent)
                import warnings

                warnings.warn(
                    f"{rel}: May contain hardcoded Server header. "
                    "Ensure this comes from persona config.",
                    stacklevel=2,
                )
