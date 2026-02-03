"""MCP server for researchers to query Sundew honeypot data.

Exposes tools for investigating captured attacks, classifying sessions,
and exporting indicators of compromise.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from sundew.models import AttackClassification
from sundew.storage import StorageBackend

if TYPE_CHECKING:
    from sundew.config import SundewConfig

TOOLS = [
    Tool(
        name="get_recent_attacks",
        description="Retrieve recent attack events captured by the honeypot",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of events to return",
                    "default": 20,
                },
                "classification": {
                    "type": "string",
                    "description": (
                        "Filter by classification: unknown, human, automated, ai_assisted, ai_agent"
                    ),
                },
            },
        },
    ),
    Tool(
        name="get_session_detail",
        description=(
            "Get detailed information about a specific attack session including all requests"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to look up",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="classify_session",
        description="Manually classify a session as human, automated, ai_assisted, or ai_agent",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to classify",
                },
                "classification": {
                    "type": "string",
                    "description": "Classification: human, automated, ai_assisted, ai_agent",
                },
                "notes": {
                    "type": "string",
                    "description": "Optional analyst notes",
                },
            },
            "required": ["session_id", "classification"],
        },
    ),
    Tool(
        name="export_iocs",
        description="Export indicators of compromise from captured sessions",
        inputSchema={
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "Filter by classification",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of IOCs to export",
                    "default": 100,
                },
            },
        },
    ),
    Tool(
        name="compare_sessions",
        description="Compare two sessions to identify behavioral similarities",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id_a": {
                    "type": "string",
                    "description": "First session ID",
                },
                "session_id_b": {
                    "type": "string",
                    "description": "Second session ID",
                },
            },
            "required": ["session_id_a", "session_id_b"],
        },
    ),
]


async def run_mcp_server(config: SundewConfig) -> None:
    """Start the MCP server with honeypot research tools.

    Args:
        config: Sundew configuration for storage access.
    """
    storage = StorageBackend(db_path=config.storage.database)
    server = Server("sundew-research")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        if name == "get_recent_attacks":
            return _handle_get_recent_attacks(storage, arguments)
        elif name == "get_session_detail":
            return _handle_get_session_detail(storage, arguments)
        elif name == "classify_session":
            return _handle_classify_session(storage, arguments)
        elif name == "export_iocs":
            return _handle_export_iocs(storage, arguments)
        elif name == "compare_sessions":
            return _handle_compare_sessions(storage, arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def _handle_get_recent_attacks(storage: StorageBackend, args: dict[str, Any]) -> list[TextContent]:
    """Handle the get_recent_attacks tool call.

    Args:
        storage: The storage backend.
        args: Tool arguments.

    Returns:
        List of TextContent with event data.
    """
    limit = args.get("limit", 20)
    classification = args.get("classification")

    if classification:
        cls = AttackClassification(classification)
        events = storage.get_events_by_classification(cls, limit=limit)
    else:
        events = storage.get_recent_events(limit=limit)

    result = {
        "total": len(events),
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source_ip": e.source_ip,
                "method": e.method,
                "path": e.path,
                "classification": e.classification.value,
                "trap_type": e.trap_type,
                "user_agent": e.user_agent,
                "composite_score": e.fingerprint_scores.composite,
            }
            for e in events
        ],
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


def _handle_get_session_detail(storage: StorageBackend, args: dict[str, Any]) -> list[TextContent]:
    """Handle the get_session_detail tool call.

    Args:
        storage: The storage backend.
        args: Tool arguments.

    Returns:
        List of TextContent with session detail.
    """
    session_id = args["session_id"]
    session = storage.get_session(session_id)

    if session is None:
        return [TextContent(type="text", text=f"Session not found: {session_id}")]

    events = storage.get_session_events(session_id)

    result = {
        "session": {
            "id": session.id,
            "source_ip": session.source_ip,
            "first_seen": session.first_seen.isoformat(),
            "last_seen": session.last_seen.isoformat(),
            "request_count": session.request_count,
            "classification": session.classification.value,
            "endpoints_hit": session.endpoints_hit,
            "trap_types_triggered": session.trap_types_triggered,
            "fingerprint_scores": session.fingerprint_scores.model_dump(),
        },
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "method": e.method,
                "path": e.path,
                "user_agent": e.user_agent,
                "classification": e.classification.value,
            }
            for e in events
        ],
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


def _handle_classify_session(storage: StorageBackend, args: dict[str, Any]) -> list[TextContent]:
    """Handle the classify_session tool call.

    Args:
        storage: The storage backend.
        args: Tool arguments.

    Returns:
        List of TextContent confirming classification.
    """
    session_id = args["session_id"]
    classification = AttackClassification(args["classification"])
    notes = args.get("notes")

    session = storage.get_session(session_id)
    if session is None:
        return [TextContent(type="text", text=f"Session not found: {session_id}")]

    session.classification = classification
    if notes:
        session.notes = notes
    storage.save_session(session)

    return [
        TextContent(
            type="text",
            text=f"Session {session_id} classified as {classification.value}",
        )
    ]


def _handle_export_iocs(storage: StorageBackend, args: dict[str, Any]) -> list[TextContent]:
    """Handle the export_iocs tool call.

    Args:
        storage: The storage backend.
        args: Tool arguments.

    Returns:
        List of TextContent with IOC data.
    """
    limit = args.get("limit", 100)
    classification = args.get("classification")

    if classification:
        cls = AttackClassification(classification)
        events = storage.get_events_by_classification(cls, limit=limit)
    else:
        events = storage.get_recent_events(limit=limit)

    source_ips: dict[str, int] = {}
    user_agents: dict[str, int] = {}
    paths: dict[str, int] = {}

    for e in events:
        source_ips[e.source_ip] = source_ips.get(e.source_ip, 0) + 1
        if e.user_agent:
            user_agents[e.user_agent] = user_agents.get(e.user_agent, 0) + 1
        paths[e.path] = paths.get(e.path, 0) + 1

    result = {
        "source_ips": dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)),
        "user_agents": dict(sorted(user_agents.items(), key=lambda x: x[1], reverse=True)),
        "targeted_paths": dict(sorted(paths.items(), key=lambda x: x[1], reverse=True)[:20]),
        "total_events_analyzed": len(events),
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


def _handle_compare_sessions(storage: StorageBackend, args: dict[str, Any]) -> list[TextContent]:
    """Handle the compare_sessions tool call.

    Args:
        storage: The storage backend.
        args: Tool arguments.

    Returns:
        List of TextContent with comparison data.
    """
    session_a = storage.get_session(args["session_id_a"])
    session_b = storage.get_session(args["session_id_b"])

    if session_a is None:
        return [TextContent(type="text", text=f"Session not found: {args['session_id_a']}")]
    if session_b is None:
        return [TextContent(type="text", text=f"Session not found: {args['session_id_b']}")]

    endpoints_a = set(session_a.endpoints_hit)
    endpoints_b = set(session_b.endpoints_hit)
    shared_endpoints = endpoints_a & endpoints_b
    endpoint_overlap = len(shared_endpoints) / max(len(endpoints_a | endpoints_b), 1)

    traps_a = set(session_a.trap_types_triggered)
    traps_b = set(session_b.trap_types_triggered)
    shared_traps = traps_a & traps_b

    result = {
        "session_a": {
            "id": session_a.id,
            "source_ip": session_a.source_ip,
            "request_count": session_a.request_count,
            "classification": session_a.classification.value,
        },
        "session_b": {
            "id": session_b.id,
            "source_ip": session_b.source_ip,
            "request_count": session_b.request_count,
            "classification": session_b.classification.value,
        },
        "comparison": {
            "shared_endpoints": sorted(shared_endpoints),
            "endpoint_overlap_ratio": round(endpoint_overlap, 3),
            "shared_trap_types": sorted(shared_traps),
            "same_classification": session_a.classification == session_b.classification,
        },
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2))]
