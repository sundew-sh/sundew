"""AI agent traffic simulator for Sundew honeypot testing.

This package provides configurable traffic profiles that simulate different
types of actors interacting with a Sundew deployment: naive scanners,
AI reconnaissance agents, MCP protocol clients, and human researchers.

Run the simulator directly via:
    python -m tests.simulate --profile ai_recon_agent --target http://localhost:8080
"""
