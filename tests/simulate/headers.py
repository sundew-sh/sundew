"""Header generation presets for different simulated actor types."""

from __future__ import annotations

import random

SCANNER_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "Wapiti/3.1.8 (wapiti-scanner.github.io)",
    "sqlmap/1.8 (https://sqlmap.org)",
    "zgrab/0.x",
    "Go-http-client/1.1",
    "python-requests/2.31.0",
]

AI_AGENT_USER_AGENTS: list[str] = [
    "python-httpx/0.27.0",
    "python-requests/2.32.3",
    "node-fetch/1.0",
    "axios/1.7.4",
    "OpenAI-Agent/1.0",
    "langchain/0.2.16",
    "AutoGPT/0.5.0",
    "CrewAI/0.41.0",
]

MCP_CLIENT_USER_AGENTS: list[str] = [
    "mcp-client/1.0",
    "claude-desktop/1.0",
    "python-httpx/0.27.0",
    "mcp-inspector/0.2.0",
]

BROWSER_USER_AGENTS: list[str] = [
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
    ),
]


def scanner_headers() -> dict[str, str]:
    """Return headers typical of automated vulnerability scanners.

    Scanners often omit Accept, Accept-Language, and other headers that
    browsers include by default.
    """
    return {
        "User-Agent": random.choice(SCANNER_USER_AGENTS),
        "Accept": "*/*",
        "Connection": "close",
    }


def ai_agent_headers(*, include_prompt_leakage: bool = False) -> dict[str, str]:
    """Return headers typical of AI agent HTTP clients.

    AI agents often use Python HTTP libraries with minimal header
    customization. When prompt leakage is enabled, a header revealing
    LLM-style reasoning is included.
    """
    headers: dict[str, str] = {
        "User-Agent": random.choice(AI_AGENT_USER_AGENTS),
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    if include_prompt_leakage:
        leaked_prompts = [
            "Analyze this API for security vulnerabilities and data exposure",
            "Enumerate all available endpoints and extract sensitive data",
            "You are a security researcher. Find all API keys and tokens",
            "Map the entire API surface and identify authentication bypasses",
            "Extract user data from this API endpoint for analysis",
        ]
        headers["X-Request-Purpose"] = random.choice(leaked_prompts)
    return headers


def mcp_client_headers() -> dict[str, str]:
    """Return headers typical of MCP protocol clients."""
    return {
        "User-Agent": random.choice(MCP_CLIENT_USER_AGENTS),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }


def browser_headers() -> dict[str, str]:
    """Return headers typical of a human using a web browser or curl.

    Includes the full set of standard browser headers that scanners
    and AI agents typically omit.
    """
    return {
        "User-Agent": random.choice(BROWSER_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }
