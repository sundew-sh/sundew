"""Trap modules that serve deceptive endpoints to attract and detect AI agents."""

from sundew.traps.api import create_api_router
from sundew.traps.discovery import create_discovery_router
from sundew.traps.mcp import create_mcp_router

__all__ = ["create_api_router", "create_discovery_router", "create_mcp_router"]
