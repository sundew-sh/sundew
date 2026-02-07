"""Base simulator class and result types."""

from __future__ import annotations

import abc
import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from tests.simulate.timing import TimingStrategy  # noqa: TC001


@dataclass
class SimulatedRequest:
    """Record of a single request sent by the simulator."""

    method: str
    url: str
    status_code: int
    headers_sent: dict[str, str]
    headers_received: dict[str, str]
    body_sent: str | None
    body_received: str
    elapsed_ms: float
    timestamp: float


@dataclass
class SimulationResult:
    """Aggregate results from a complete simulation run."""

    profile_name: str
    target: str
    requests: list[SimulatedRequest] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def total_requests(self) -> int:
        """Return the total number of requests made."""
        return len(self.requests)

    @property
    def duration_seconds(self) -> float:
        """Return the total simulation duration in seconds."""
        return self.end_time - self.start_time

    @property
    def status_code_distribution(self) -> dict[int, int]:
        """Return a count of each HTTP status code received."""
        dist: dict[int, int] = {}
        for req in self.requests:
            dist[req.status_code] = dist.get(req.status_code, 0) + 1
        return dist

    @property
    def unique_paths(self) -> list[str]:
        """Return deduplicated list of URL paths accessed in order."""
        seen: set[str] = set()
        paths: list[str] = []
        for req in self.requests:
            path = req.url.split("//", 1)[-1].split("/", 1)[-1] if "//" in req.url else req.url
            if path not in seen:
                seen.add(path)
                paths.append(path)
        return paths


class BaseSimulator(abc.ABC):
    """Abstract base for all traffic simulation profiles.

    Subclasses implement generate_requests() to produce the sequence of
    HTTP requests characteristic of their actor type. The base class
    handles timing, execution, and result collection.
    """

    def __init__(
        self,
        target: str,
        timing: TimingStrategy,
        profile_name: str,
    ) -> None:
        self._target = target.rstrip("/")
        self._timing = timing
        self._profile_name = profile_name

    @abc.abstractmethod
    def generate_requests(self) -> list[dict[str, Any]]:
        """Generate the ordered list of HTTP requests to execute.

        Each dict must contain:
            - method: str (GET, POST, etc.)
            - path: str (relative path, e.g., '/api/v1/users')
            - headers: dict[str, str]

        Optional keys:
            - body: str | dict (request body)
            - params: dict[str, str] (query parameters)

        Returns:
            Ordered list of request specifications.
        """

    async def run(self, *, timeout: float = 30.0) -> SimulationResult:
        """Execute the full simulation against the target.

        Args:
            timeout: Maximum time in seconds for the entire simulation.

        Returns:
            A SimulationResult with all captured requests and metadata.
        """
        result = SimulationResult(
            profile_name=self._profile_name,
            target=self._target,
            start_time=time.monotonic(),
        )

        request_specs = self.generate_requests()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            for i, spec in enumerate(request_specs):
                if i > 0:
                    delay_ms = self._timing.next_delay_ms()
                    await asyncio.sleep(delay_ms / 1000.0)

                method = spec["method"]
                url = f"{self._target}{spec['path']}"
                headers = spec.get("headers", {})
                body = spec.get("body")
                params = spec.get("params")

                body_str: str | None = None
                if isinstance(body, dict):
                    import json

                    body_str = json.dumps(body)
                elif isinstance(body, str):
                    body_str = body

                req_start = time.monotonic()
                try:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        content=body_str,
                        params=params,
                    )
                    elapsed_ms = (time.monotonic() - req_start) * 1000.0

                    result.requests.append(
                        SimulatedRequest(
                            method=method,
                            url=url,
                            status_code=response.status_code,
                            headers_sent=headers,
                            headers_received=dict(response.headers),
                            body_sent=body_str,
                            body_received=response.text,
                            elapsed_ms=elapsed_ms,
                            timestamp=time.time(),
                        )
                    )
                except httpx.HTTPError as exc:
                    result.errors.append(f"Request {i} ({method} {url}): {exc}")

        result.end_time = time.monotonic()
        return result
