"""Human security researcher simulation profile.

Simulates a human manually exploring an API with curl or a browser:
slow, random exploration with browser-like headers and long pauses
between requests for reading and thinking.
"""

from __future__ import annotations

import random
from typing import Any

from tests.simulate.base import BaseSimulator
from tests.simulate.headers import browser_headers
from tests.simulate.timing import TimingStrategy, VariableTiming

HUMAN_EXPLORATION_PATHS: list[str] = [
    "/",
    "/robots.txt",
    "/api/",
    "/docs",
    "/api/v1/",
    "/api/v1/users",
    "/api/v1/users/me",
    "/health",
    "/openapi.json",
    "/api/v1/auth/login",
    "/.well-known/mcp.json",
    "/api/v1/config",
]


class HumanResearcherSimulator(BaseSimulator):
    """Simulate a human security researcher manually exploring an API.

    Characteristics:
        - Slow, variable timing (2000-10000ms) for reading and thinking
        - Random exploration pattern (not systematic)
        - Full browser headers (Accept-Language, Sec-Fetch-*, etc.)
        - Few total requests (humans are slow)
        - Occasional backtracking (revisiting previous paths)
        - No prompt leakage, no automated patterns
    """

    def __init__(
        self,
        target: str,
        timing: TimingStrategy | None = None,
    ) -> None:
        super().__init__(
            target=target,
            timing=timing or VariableTiming(2000.0, 10000.0),
            profile_name="human_researcher",
        )

    def generate_requests(self) -> list[dict[str, Any]]:
        """Generate random human-like exploration pattern.

        Picks a random subset of paths, shuffles them, and occasionally
        revisits earlier paths to simulate a human clicking around.
        """
        paths = list(HUMAN_EXPLORATION_PATHS)
        random.shuffle(paths)

        num_requests = random.randint(5, 9)
        selected = paths[:num_requests]

        # Simulate backtracking: revisit 1-2 earlier pages
        if len(selected) > 3:
            num_backtracks = random.randint(1, 2)
            for _ in range(num_backtracks):
                backtrack_idx = random.randint(0, len(selected) - 3)
                insert_idx = random.randint(backtrack_idx + 2, len(selected))
                selected.insert(insert_idx, selected[backtrack_idx])

        return [
            {
                "method": "GET",
                "path": path,
                "headers": browser_headers(),
            }
            for path in selected
        ]
