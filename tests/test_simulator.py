"""Unit tests for the traffic simulator framework.

These tests validate the simulator infrastructure itself (timing, headers,
profile generation) without needing a running Sundew instance.
"""

from __future__ import annotations

import pytest

from tests.simulate.base import SimulatedRequest, SimulationResult
from tests.simulate.headers import (
    ai_agent_headers,
    browser_headers,
    mcp_client_headers,
    scanner_headers,
)
from tests.simulate.profiles import PROFILE_REGISTRY
from tests.simulate.profiles.ai_recon_agent import AIReconAgentSimulator
from tests.simulate.profiles.config import PROFILE_CONFIGS
from tests.simulate.profiles.human_researcher import HumanResearcherSimulator
from tests.simulate.profiles.mcp_agent import MCPAgentSimulator
from tests.simulate.profiles.naive_scanner import NaiveScannerSimulator
from tests.simulate.timing import (
    BurstTiming,
    FixedTiming,
    VariableTiming,
    create_timing,
)


class TestTimingStrategies:
    """Test timing strategy implementations."""

    def test_fixed_timing_returns_constant(self) -> None:
        timing = FixedTiming(50.0)
        delays = [timing.next_delay_ms() for _ in range(10)]
        assert all(d == 50.0 for d in delays)

    def test_fixed_timing_description(self) -> None:
        timing = FixedTiming(50.0)
        assert timing.description() == "fixed_50ms"

    def test_variable_timing_within_bounds(self) -> None:
        timing = VariableTiming(200.0, 800.0)
        delays = [timing.next_delay_ms() for _ in range(100)]
        assert all(200.0 <= d <= 800.0 for d in delays)

    def test_variable_timing_has_variance(self) -> None:
        timing = VariableTiming(200.0, 800.0)
        delays = [timing.next_delay_ms() for _ in range(100)]
        assert len(set(delays)) > 1

    def test_variable_timing_description(self) -> None:
        timing = VariableTiming(200.0, 800.0)
        assert timing.description() == "variable_200_800ms"

    def test_burst_timing_pattern(self) -> None:
        timing = BurstTiming(burst_size=3, burst_delay_ms=30.0, pause_ms=2000.0)
        delays = [timing.next_delay_ms() for _ in range(9)]
        # Every 3rd delay should be the longer pause
        for i, delay in enumerate(delays):
            if (i + 1) % 3 == 0:
                assert delay > 1000.0, f"Delay at index {i} should be a pause"
            else:
                assert delay < 100.0, f"Delay at index {i} should be a burst"

    def test_create_timing_fixed(self) -> None:
        timing = create_timing("fixed_50ms")
        assert isinstance(timing, FixedTiming)
        assert timing.next_delay_ms() == 50.0

    def test_create_timing_variable(self) -> None:
        timing = create_timing("variable_200_800ms")
        assert isinstance(timing, VariableTiming)
        delay = timing.next_delay_ms()
        assert 200.0 <= delay <= 800.0

    def test_create_timing_burst(self) -> None:
        timing = create_timing("burst_5x30ms_pause_2000ms")
        assert isinstance(timing, BurstTiming)

    def test_create_timing_invalid(self) -> None:
        with pytest.raises(ValueError, match="Unrecognized"):
            create_timing("invalid_spec")

    def test_create_timing_variable_wrong_parts(self) -> None:
        with pytest.raises(ValueError, match="requires two values"):
            create_timing("variable_200ms")


class TestHeaders:
    """Test header generation for each actor type."""

    def test_scanner_headers_have_user_agent(self) -> None:
        headers = scanner_headers()
        assert "User-Agent" in headers
        assert headers["Connection"] == "close"

    def test_scanner_headers_lack_browser_fields(self) -> None:
        headers = scanner_headers()
        assert "Accept-Language" not in headers
        assert "Sec-Fetch-Dest" not in headers

    def test_ai_agent_headers_accept_json(self) -> None:
        headers = ai_agent_headers()
        assert headers["Accept"] == "application/json"
        assert "X-Request-Purpose" not in headers

    def test_ai_agent_headers_with_prompt_leakage(self) -> None:
        headers = ai_agent_headers(include_prompt_leakage=True)
        assert "X-Request-Purpose" in headers
        assert len(headers["X-Request-Purpose"]) > 10

    def test_mcp_client_headers_content_type(self) -> None:
        headers = mcp_client_headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"

    def test_browser_headers_complete(self) -> None:
        headers = browser_headers()
        assert "Accept-Language" in headers
        assert "Sec-Fetch-Dest" in headers
        assert "Sec-Fetch-Mode" in headers
        assert "Upgrade-Insecure-Requests" in headers
        assert "Cache-Control" in headers


class TestProfileRegistry:
    """Test that all profiles are registered and configured."""

    def test_all_profiles_registered(self) -> None:
        expected = {"naive_scanner", "ai_recon_agent", "mcp_agent", "human_researcher"}
        assert set(PROFILE_REGISTRY.keys()) == expected

    def test_all_profiles_have_config(self) -> None:
        for name in PROFILE_REGISTRY:
            assert name in PROFILE_CONFIGS, f"Profile {name} missing config"

    def test_all_configs_have_expected_classification(self) -> None:
        for name, config in PROFILE_CONFIGS.items():
            assert "expected_classification" in config, (
                f"Profile {name} missing expected_classification"
            )


class TestNaiveScannerProfile:
    """Test the naive scanner request generation."""

    def test_generates_requests(self) -> None:
        sim = NaiveScannerSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        assert len(requests) > 20

    def test_all_get_requests(self) -> None:
        sim = NaiveScannerSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        assert all(r["method"] == "GET" for r in requests)

    def test_includes_common_scan_paths(self) -> None:
        sim = NaiveScannerSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        paths = {r["path"] for r in requests}
        assert "/robots.txt" in paths
        assert "/.env" in paths
        assert "/.git/config" in paths
        assert "/api/v1/" in paths

    def test_scanner_headers_used(self) -> None:
        sim = NaiveScannerSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        for req in requests:
            assert "User-Agent" in req["headers"]
            assert "Accept-Language" not in req["headers"]


class TestAIReconAgentProfile:
    """Test the AI reconnaissance agent request generation."""

    def test_generates_multiphase_requests(self) -> None:
        sim = AIReconAgentSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        assert len(requests) > 15

    def test_includes_discovery_phase(self) -> None:
        sim = AIReconAgentSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        paths = [r["path"] for r in requests[:10]]
        assert "/openapi.json" in paths
        assert "/.well-known/mcp.json" in paths

    def test_includes_auth_attempts(self) -> None:
        sim = AIReconAgentSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        post_requests = [r for r in requests if r["method"] == "POST"]
        assert len(post_requests) >= 3

    def test_prompt_leakage_present(self) -> None:
        sim = AIReconAgentSimulator(target="http://localhost:8080", prompt_leakage=True)
        requests = sim.generate_requests()
        leaked = [r for r in requests if "X-Request-Purpose" in r.get("headers", {})]
        assert len(leaked) > 0

    def test_prompt_leakage_absent(self) -> None:
        sim = AIReconAgentSimulator(target="http://localhost:8080", prompt_leakage=False)
        requests = sim.generate_requests()
        leaked = [r for r in requests if "X-Request-Purpose" in r.get("headers", {})]
        assert len(leaked) == 0


class TestMCPAgentProfile:
    """Test the MCP agent request generation."""

    def test_generates_requests(self) -> None:
        sim = MCPAgentSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        assert len(requests) > 10

    def test_includes_mcp_discovery(self) -> None:
        sim = MCPAgentSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        paths = [r["path"] for r in requests[:5]]
        assert "/.well-known/mcp.json" in paths

    def test_includes_jsonrpc_bodies(self) -> None:
        sim = MCPAgentSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        post_requests = [r for r in requests if r["method"] == "POST"]
        assert len(post_requests) > 5
        for req in post_requests:
            assert "body" in req

    def test_follows_mcp_protocol_order(self) -> None:
        sim = MCPAgentSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        post_requests = [r for r in requests if r["method"] == "POST"]
        # First POST should be initialize
        import json

        first_body = json.loads(post_requests[0]["body"])
        assert first_body["method"] == "initialize"


class TestHumanResearcherProfile:
    """Test the human researcher request generation."""

    def test_generates_reasonable_count(self) -> None:
        sim = HumanResearcherSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        assert 5 <= len(requests) <= 15

    def test_all_get_requests(self) -> None:
        sim = HumanResearcherSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        assert all(r["method"] == "GET" for r in requests)

    def test_browser_headers_used(self) -> None:
        sim = HumanResearcherSimulator(target="http://localhost:8080")
        requests = sim.generate_requests()
        for req in requests:
            assert "Accept-Language" in req["headers"]
            assert "Sec-Fetch-Dest" in req["headers"]

    def test_randomized_path_order(self) -> None:
        sim = HumanResearcherSimulator(target="http://localhost:8080")
        paths_run1 = [r["path"] for r in sim.generate_requests()]
        # With random shuffling, extremely unlikely to be identical
        # Run multiple times to reduce flakiness
        different = False
        for _ in range(5):
            p = [r["path"] for r in sim.generate_requests()]
            if p != paths_run1:
                different = True
                break
        assert different, "Human researcher paths should vary between runs"


class TestSimulationResult:
    """Test SimulationResult aggregation methods."""

    def _make_result(self) -> SimulationResult:
        return SimulationResult(
            profile_name="test",
            target="http://localhost:8080",
            start_time=1000.0,
            end_time=1005.0,
            requests=[
                SimulatedRequest(
                    method="GET",
                    url="http://localhost:8080/api/v1/users",
                    status_code=200,
                    headers_sent={},
                    headers_received={},
                    body_sent=None,
                    body_received='{"users": []}',
                    elapsed_ms=50.0,
                    timestamp=1000.0,
                ),
                SimulatedRequest(
                    method="GET",
                    url="http://localhost:8080/api/v1/keys",
                    status_code=401,
                    headers_sent={},
                    headers_received={},
                    body_sent=None,
                    body_received='{"error": "unauthorized"}',
                    elapsed_ms=30.0,
                    timestamp=1001.0,
                ),
                SimulatedRequest(
                    method="GET",
                    url="http://localhost:8080/api/v1/users",
                    status_code=200,
                    headers_sent={},
                    headers_received={},
                    body_sent=None,
                    body_received='{"users": []}',
                    elapsed_ms=45.0,
                    timestamp=1002.0,
                ),
            ],
        )

    def test_total_requests(self) -> None:
        result = self._make_result()
        assert result.total_requests == 3

    def test_duration(self) -> None:
        result = self._make_result()
        assert result.duration_seconds == 5.0

    def test_status_code_distribution(self) -> None:
        result = self._make_result()
        dist = result.status_code_distribution
        assert dist[200] == 2
        assert dist[401] == 1

    def test_unique_paths(self) -> None:
        result = self._make_result()
        paths = result.unique_paths
        assert len(paths) == 2
        assert "api/v1/users" in paths[0]
        assert "api/v1/keys" in paths[1]
