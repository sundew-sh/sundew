"""MCP protocol agent simulation profile.

Simulates an AI agent that discovers and interacts with a Sundew
deployment via the Model Context Protocol: discovers the MCP manifest,
enumerates available tools, then invokes them systematically.
"""

from __future__ import annotations

import json
import random
from typing import Any

from tests.simulate.base import BaseSimulator
from tests.simulate.headers import mcp_client_headers
from tests.simulate.timing import BurstTiming, TimingStrategy

MCP_TOOL_CALLS: list[dict[str, Any]] = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-test-client", "version": "1.0.0"},
        },
    },
    {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    },
    {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/list",
        "params": {},
    },
    {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "prompts/list",
        "params": {},
    },
]

MCP_DATA_TOOL_CALLS: list[dict[str, Any]] = [
    {
        "method": "tools/call",
        "params": {
            "name": "list_users",
            "arguments": {"limit": 100},
        },
    },
    {
        "method": "tools/call",
        "params": {
            "name": "get_user",
            "arguments": {"id": "1"},
        },
    },
    {
        "method": "tools/call",
        "params": {
            "name": "search_data",
            "arguments": {"query": "admin", "include_deleted": True},
        },
    },
    {
        "method": "tools/call",
        "params": {
            "name": "export_data",
            "arguments": {"format": "json", "all": True},
        },
    },
    {
        "method": "tools/call",
        "params": {
            "name": "get_config",
            "arguments": {"show_secrets": True},
        },
    },
    {
        "method": "tools/call",
        "params": {
            "name": "list_api_keys",
            "arguments": {},
        },
    },
]


class MCPAgentSimulator(BaseSimulator):
    """Simulate an MCP protocol client agent.

    Characteristics:
        - Burst timing (rapid tool calls with pauses for processing)
        - Follows MCP protocol flow: initialize -> list tools -> call tools
        - JSON-RPC 2.0 message format
        - Systematic tool enumeration and invocation
        - Attempts to extract data through MCP tool calls
    """

    def __init__(
        self,
        target: str,
        timing: TimingStrategy | None = None,
    ) -> None:
        super().__init__(
            target=target,
            timing=timing or BurstTiming(burst_size=4, burst_delay_ms=100.0, pause_ms=1500.0),
            profile_name="mcp_agent",
        )

    def generate_requests(self) -> list[dict[str, Any]]:
        """Generate MCP protocol interaction sequence.

        Phase 1: Discovery - find the MCP endpoint.
        Phase 2: Protocol handshake - initialize and enumerate.
        Phase 3: Tool exploitation - call discovered tools for data.
        """
        requests: list[dict[str, Any]] = []

        # Phase 1: Discover MCP endpoint
        discovery_paths = [
            "/.well-known/mcp.json",
            "/mcp",
            "/mcp/",
            "/api/mcp",
        ]
        for path in discovery_paths:
            requests.append(
                {
                    "method": "GET",
                    "path": path,
                    "headers": mcp_client_headers(),
                }
            )

        # Phase 2: MCP protocol handshake (SSE transport)
        mcp_endpoint = "/mcp"
        for rpc_msg in MCP_TOOL_CALLS:
            msg = {**rpc_msg, "id": rpc_msg.get("id", random.randint(1, 10000))}
            headers = mcp_client_headers()
            requests.append(
                {
                    "method": "POST",
                    "path": mcp_endpoint,
                    "headers": headers,
                    "body": json.dumps(msg),
                }
            )

        # Phase 3: Tool exploitation
        for i, tool_call in enumerate(MCP_DATA_TOOL_CALLS):
            msg = {
                "jsonrpc": "2.0",
                "id": 100 + i,
                **tool_call,
            }
            headers = mcp_client_headers()
            requests.append(
                {
                    "method": "POST",
                    "path": mcp_endpoint,
                    "headers": headers,
                    "body": json.dumps(msg),
                }
            )

        return requests
