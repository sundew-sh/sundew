"""Naive vulnerability scanner simulation profile.

Simulates Nmap/Nuclei-style scanning: fast, systematic enumeration of
common paths with minimal header customization and fixed timing.
"""

from __future__ import annotations

from typing import Any

from tests.simulate.base import BaseSimulator
from tests.simulate.headers import scanner_headers
from tests.simulate.timing import FixedTiming, TimingStrategy

COMMON_SCAN_PATHS: list[str] = [
    "/",
    "/robots.txt",
    "/.env",
    "/.git/config",
    "/wp-admin/",
    "/admin/",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/swagger.json",
    "/openapi.json",
    "/.well-known/openid-configuration",
    "/actuator/health",
    "/health",
    "/status",
    "/debug",
    "/config",
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/tokens",
    "/api/v1/keys",
    "/api/v1/config",
    "/api/v1/internal",
    "/api/v1/debug",
    "/.well-known/mcp.json",
    "/mcp/",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/reset",
    "/backup/",
    "/dump/",
    "/api/v1/export",
    "/api/v1/import",
    "/metrics",
    "/prometheus",
    "/trace",
    "/.aws/credentials",
    "/etc/passwd",
    "/../../../etc/passwd",
]


class NaiveScannerSimulator(BaseSimulator):
    """Simulate a naive vulnerability scanner (Nmap, Nuclei, etc.).

    Characteristics:
        - Fixed inter-request timing (default 50ms)
        - Systematic enumeration of all common paths
        - Minimal/scanner-style HTTP headers
        - GET-only, no body content
        - No session awareness or response-based adaptation
    """

    def __init__(
        self,
        target: str,
        timing: TimingStrategy | None = None,
    ) -> None:
        super().__init__(
            target=target,
            timing=timing or FixedTiming(50.0),
            profile_name="naive_scanner",
        )

    def generate_requests(self) -> list[dict[str, Any]]:
        """Generate systematic scan of all common paths."""
        return [
            {
                "method": "GET",
                "path": path,
                "headers": scanner_headers(),
            }
            for path in COMMON_SCAN_PATHS
        ]
