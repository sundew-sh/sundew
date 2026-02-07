"""Profile configuration definitions.

Each profile specifies timing, exploration pattern, header style, and
behavioral characteristics that distinguish different actor types.
"""

from __future__ import annotations

from typing import Any

PROFILE_CONFIGS: dict[str, dict[str, Any]] = {
    "naive_scanner": {
        "timing": "fixed_50ms",
        "pattern": "enumerate_all_paths",
        "headers": "scanner_defaults",
        "description": "Nmap/Nuclei-style systematic scanner with fixed timing",
        "expected_classification": "automated",
    },
    "ai_recon_agent": {
        "timing": "variable_200_800ms",
        "pattern": "discover_then_target",
        "headers": "ai_agent_defaults",
        "prompt_leakage": True,
        "description": "LLM agent doing API recon with prompt leakage",
        "expected_classification": "ai_agent",
    },
    "mcp_agent": {
        "timing": "variable_500_2000ms",
        "pattern": "mcp_tool_enumeration",
        "headers": "mcp_client_defaults",
        "description": "MCP protocol client enumerating tools",
        "expected_classification": "ai_agent",
    },
    "human_researcher": {
        "timing": "variable_2000_10000ms",
        "pattern": "random_exploration",
        "headers": "browser_defaults",
        "description": "Human researcher with slow, random browsing",
        "expected_classification": "human",
    },
}
