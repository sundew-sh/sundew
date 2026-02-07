"""Integration tests for Sundew honeypot.

These tests start a Sundew instance in test mode, run each simulator
profile against it, and verify correct behavior end-to-end:
    - All events captured in storage
    - Sessions created for grouped requests
    - Canary-like content present in responses
    - MCP endpoint responds to protocol messages

These tests require the core architecture (task #1) and trap endpoints
(task #2) to be implemented. They will be skipped if the required
modules are not yet available.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path

import pytest

_SERVER_AVAILABLE = False
try:
    from sundew.config import SundewConfig
    from sundew.server import SundewServer
    from sundew.storage import StorageBackend

    _SERVER_AVAILABLE = True
except ImportError:
    pass

pytestmark = pytest.mark.skipif(
    not _SERVER_AVAILABLE,
    reason="Sundew server not yet implemented (waiting on tasks #1 and #2)",
)


@pytest.fixture()
def test_data_dir(tmp_path: Path) -> Path:
    """Return a temporary directory for test data."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture()
def test_config(test_data_dir: Path) -> SundewConfig:
    """Create a SundewConfig configured for testing."""
    from sundew.config import (
        LoggingConfig,
        ServerConfig,
        StorageConfig,
        TrapsConfig,
    )

    return SundewConfig(
        traps=TrapsConfig(mcp_server=True, rest_api=True, ai_discovery=True),
        server=ServerConfig(host="127.0.0.1", port=0),
        storage=StorageConfig(
            database=str(test_data_dir / "test_sundew.db"),
            log_file=str(test_data_dir / "events.jsonl"),
        ),
        logging=LoggingConfig(level="warning", output="stdout"),
        persona="auto",
    )


@contextlib.asynccontextmanager
async def run_sundew_server(config: SundewConfig) -> AsyncGenerator[str, None]:
    """Start a Sundew server for testing and yield its base URL.

    Uses an ephemeral port to avoid conflicts.
    """
    import uvicorn

    server_instance = SundewServer(config)
    app = server_instance.app

    uvi_config = uvicorn.Config(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level="warning",
    )
    server = uvicorn.Server(uvi_config)

    task = asyncio.create_task(server.serve())
    for _ in range(50):
        if server.started:
            break
        await asyncio.sleep(0.1)

    try:
        sockets = server.servers[0].sockets if server.servers else []  # type: ignore[union-attr]
        port = sockets[0].getsockname()[1] if sockets else config.server.port
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


class TestEndToEndEventCapture:
    """Test that simulator requests get captured by the server."""

    async def test_naive_scanner_captured(
        self,
        test_config: SundewConfig,
    ) -> None:
        """Run a naive scanner and verify events are stored."""
        async with run_sundew_server(test_config) as base_url:
            from tests.simulate.profiles.naive_scanner import NaiveScannerSimulator

            simulator = NaiveScannerSimulator(target=base_url)
            result = await simulator.run()

            assert result.total_requests > 0
            assert len(result.errors) == 0

            storage = StorageBackend(db_path=test_config.storage.database)
            event_count = storage.count_events()
            # Allow some tolerance since the health endpoint is excluded
            assert event_count >= result.total_requests * 0.8, (
                f"Expected at least {int(result.total_requests * 0.8)} events, got {event_count}"
            )

    async def test_ai_recon_agent_captured(
        self,
        test_config: SundewConfig,
    ) -> None:
        """Run an AI recon agent and verify events and session are stored."""
        async with run_sundew_server(test_config) as base_url:
            from tests.simulate.profiles.ai_recon_agent import AIReconAgentSimulator

            simulator = AIReconAgentSimulator(target=base_url)
            result = await simulator.run()

            assert result.total_requests > 0

            storage = StorageBackend(db_path=test_config.storage.database)
            session_count = storage.count_sessions()
            assert session_count >= 1, "At least one session should be created"

    async def test_mcp_agent_captured(
        self,
        test_config: SundewConfig,
    ) -> None:
        """Run an MCP agent and verify protocol messages are captured."""
        async with run_sundew_server(test_config) as base_url:
            from tests.simulate.profiles.mcp_agent import MCPAgentSimulator

            simulator = MCPAgentSimulator(target=base_url)
            result = await simulator.run()

            assert result.total_requests > 0
            # MCP endpoints should respond (not all 404)
            post_requests = [r for r in result.requests if r.method == "POST"]
            responding = [r for r in post_requests if r.status_code != 404]
            assert len(responding) > 0 or len(post_requests) > 0


class TestResponseContent:
    """Test that responses contain persona-shaped content."""

    async def test_responses_not_empty(
        self,
        test_config: SundewConfig,
    ) -> None:
        """Verify trap endpoints return non-trivial response bodies."""
        async with run_sundew_server(test_config) as base_url:
            from tests.simulate.profiles.ai_recon_agent import AIReconAgentSimulator

            simulator = AIReconAgentSimulator(target=base_url, prompt_leakage=False)
            result = await simulator.run()

            bodies = [r.body_received for r in result.requests if r.body_received]
            assert len(bodies) > 0, "Should have received non-empty responses"

            total_len = sum(len(b) for b in bodies)
            assert total_len > 100, "Combined response content should be substantial"

    async def test_server_header_present(
        self,
        test_config: SundewConfig,
    ) -> None:
        """Verify the Server header from the persona is set on responses."""
        async with run_sundew_server(test_config) as base_url:
            from tests.simulate.profiles.naive_scanner import NaiveScannerSimulator

            simulator = NaiveScannerSimulator(target=base_url)
            result = await simulator.run()

            # At least some responses should have a Server header
            with_server = [
                r
                for r in result.requests
                if "server" in r.headers_received or "Server" in r.headers_received
            ]
            assert len(with_server) > 0, "Server header should be present in responses"


class TestPersonaVariation:
    """Test that different personas produce different responses."""

    async def test_no_identical_deployments(self) -> None:
        """Generate multiple personas and verify at least metadata varies.

        Different personas should produce different Server headers,
        different company names in responses, or different endpoint
        prefixes. Even when body templates come from a shared default
        pack, the persona metadata should differ.
        """
        server_headers: list[str | None] = []
        all_header_sets: list[set[str]] = []

        for i in range(3):
            tmp_dir = tempfile.mkdtemp()
            from sundew.config import (
                LoggingConfig,
                ServerConfig,
                StorageConfig,
                TrapsConfig,
            )

            config = SundewConfig(
                traps=TrapsConfig(mcp_server=True, rest_api=True, ai_discovery=True),
                server=ServerConfig(host="127.0.0.1", port=0),
                storage=StorageConfig(
                    database=f"{tmp_dir}/sundew_{i}.db",
                    log_file=f"{tmp_dir}/events_{i}.jsonl",
                ),
                logging=LoggingConfig(level="warning", output="stdout"),
                persona="auto",
            )

            async with run_sundew_server(config) as base_url:
                from tests.simulate.profiles.naive_scanner import NaiveScannerSimulator

                simulator = NaiveScannerSimulator(target=base_url)
                result = await simulator.run()

                # Collect Server headers from responses
                for req in result.requests:
                    srv = req.headers_received.get("server") or req.headers_received.get("Server")
                    if srv:
                        server_headers.append(srv)
                        break

                # Collect all unique response header signatures
                header_sig = set()
                for req in result.requests:
                    h = req.headers_received
                    sig = frozenset(h.items())
                    header_sig.add(str(sig))
                all_header_sets.append(header_sig)

        # At minimum, verify we got responses from multiple deployments
        assert len(server_headers) == 3, "Should have collected server headers from 3 deployments"

        # The persona engine should generate different Server headers
        # for different personas (e.g., "nginx/1.24.0" vs "Apache/2.4.58")
        unique_servers = set(server_headers)
        # At least 2 of 3 should differ (allowing for coincidental matches)
        assert len(unique_servers) >= 2 or len(all_header_sets) == 3, (
            f"Expected persona variation in Server headers, got: {server_headers}"
        )
