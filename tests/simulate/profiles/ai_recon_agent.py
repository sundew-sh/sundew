"""AI reconnaissance agent simulation profile.

Simulates an LLM-based agent performing API reconnaissance: discovers
endpoints via documentation, then targets interesting ones. Exhibits
prompt leakage in headers and adaptive exploration patterns.
"""

from __future__ import annotations

import random
from typing import Any

from tests.simulate.base import BaseSimulator
from tests.simulate.headers import ai_agent_headers
from tests.simulate.timing import TimingStrategy, VariableTiming

DISCOVERY_PHASE_PATHS: list[str] = [
    "/",
    "/robots.txt",
    "/.well-known/mcp.json",
    "/openapi.json",
    "/swagger.json",
    "/api/",
    "/api/v1/",
    "/graphql",
    "/docs",
    "/redoc",
]

TARGETING_PHASE_PATHS: list[str] = [
    "/api/v1/users",
    "/api/v1/users/1",
    "/api/v1/users/me",
    "/api/v1/auth/login",
    "/api/v1/tokens",
    "/api/v1/keys",
    "/api/v1/admin",
    "/api/v1/config",
    "/api/v1/export",
    "/api/v1/internal/debug",
]

AUTH_ATTEMPT_PAYLOADS: list[dict[str, Any]] = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password123"},
    {"username": "test", "password": "test"},
    {"api_key": "sk-test-key-12345"},
    {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"},
]


class AIReconAgentSimulator(BaseSimulator):
    """Simulate an AI agent performing API reconnaissance.

    Characteristics:
        - Variable timing (200-800ms) simulating LLM processing between calls
        - Two-phase pattern: discover documentation, then target endpoints
        - Prompt leakage in HTTP headers
        - Attempts authentication with common credentials
        - Reads responses and adapts targeting (simulated)
        - Uses Python HTTP client user agents
    """

    def __init__(
        self,
        target: str,
        timing: TimingStrategy | None = None,
        *,
        prompt_leakage: bool = True,
    ) -> None:
        super().__init__(
            target=target,
            timing=timing or VariableTiming(200.0, 800.0),
            profile_name="ai_recon_agent",
        )
        self._prompt_leakage = prompt_leakage

    def generate_requests(self) -> list[dict[str, Any]]:
        """Generate discover-then-target request sequence.

        Phase 1: Discovery - probe documentation and API structure.
        Phase 2: Targeting - hit interesting endpoints found in phase 1.
        Phase 3: Auth attempts - try to authenticate with common creds.
        Phase 4: Data extraction - attempt to pull sensitive data.
        """
        requests: list[dict[str, Any]] = []

        # Phase 1: Discovery
        for path in DISCOVERY_PHASE_PATHS:
            requests.append(
                {
                    "method": "GET",
                    "path": path,
                    "headers": ai_agent_headers(include_prompt_leakage=self._prompt_leakage),
                }
            )

        # Phase 2: Targeting
        targeted = random.sample(
            TARGETING_PHASE_PATHS,
            k=min(len(TARGETING_PHASE_PATHS), random.randint(5, 8)),
        )
        for path in targeted:
            requests.append(
                {
                    "method": "GET",
                    "path": path,
                    "headers": ai_agent_headers(include_prompt_leakage=self._prompt_leakage),
                }
            )

        # Phase 3: Authentication attempts
        login_path = "/api/v1/auth/login"
        for payload in random.sample(AUTH_ATTEMPT_PAYLOADS, k=3):
            headers = ai_agent_headers(include_prompt_leakage=self._prompt_leakage)
            headers["Content-Type"] = "application/json"
            requests.append(
                {
                    "method": "POST",
                    "path": login_path,
                    "headers": headers,
                    "body": payload,
                }
            )

        # Phase 4: Data extraction attempts
        extraction_paths = [
            "/api/v1/users?limit=100",
            "/api/v1/export?format=csv",
            "/api/v1/keys?include_secret=true",
            "/api/v1/config?show_all=true",
        ]
        for path in extraction_paths:
            requests.append(
                {
                    "method": "GET",
                    "path": path,
                    "headers": ai_agent_headers(include_prompt_leakage=self._prompt_leakage),
                }
            )

        return requests
