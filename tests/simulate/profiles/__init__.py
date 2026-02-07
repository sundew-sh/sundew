"""Simulator profiles for different actor types."""

from __future__ import annotations

from tests.simulate.profiles.ai_recon_agent import AIReconAgentSimulator
from tests.simulate.profiles.human_researcher import HumanResearcherSimulator
from tests.simulate.profiles.mcp_agent import MCPAgentSimulator
from tests.simulate.profiles.naive_scanner import NaiveScannerSimulator

__all__ = [
    "AIReconAgentSimulator",
    "HumanResearcherSimulator",
    "MCPAgentSimulator",
    "NaiveScannerSimulator",
]

PROFILE_REGISTRY: dict[str, type] = {
    "naive_scanner": NaiveScannerSimulator,
    "ai_recon_agent": AIReconAgentSimulator,
    "mcp_agent": MCPAgentSimulator,
    "human_researcher": HumanResearcherSimulator,
}
