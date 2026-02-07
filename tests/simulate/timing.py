"""Timing strategies that control inter-request delays for each simulator profile."""

from __future__ import annotations

import abc
import random


class TimingStrategy(abc.ABC):
    """Base class for request timing strategies."""

    @abc.abstractmethod
    def next_delay_ms(self) -> float:
        """Return the next delay in milliseconds before the next request."""

    @abc.abstractmethod
    def description(self) -> str:
        """Return a human-readable description of this timing strategy."""


class FixedTiming(TimingStrategy):
    """Emit requests at a fixed interval."""

    def __init__(self, interval_ms: float) -> None:
        self._interval_ms = interval_ms

    def next_delay_ms(self) -> float:
        """Return the fixed interval in milliseconds."""
        return self._interval_ms

    def description(self) -> str:
        """Return description of this fixed timing."""
        return f"fixed_{int(self._interval_ms)}ms"


class VariableTiming(TimingStrategy):
    """Emit requests with uniformly random delays between min and max."""

    def __init__(self, min_ms: float, max_ms: float) -> None:
        self._min_ms = min_ms
        self._max_ms = max_ms

    def next_delay_ms(self) -> float:
        """Return a uniformly random delay between min and max milliseconds."""
        return random.uniform(self._min_ms, self._max_ms)

    def description(self) -> str:
        """Return description of this variable timing."""
        return f"variable_{int(self._min_ms)}_{int(self._max_ms)}ms"


class BurstTiming(TimingStrategy):
    """Emit bursts of fast requests separated by longer pauses.

    Simulates batch-style tool calling where an AI agent makes several
    rapid API calls, then pauses to process results.
    """

    def __init__(
        self,
        burst_size: int = 5,
        burst_delay_ms: float = 30.0,
        pause_ms: float = 2000.0,
    ) -> None:
        self._burst_size = burst_size
        self._burst_delay_ms = burst_delay_ms
        self._pause_ms = pause_ms
        self._counter = 0

    def next_delay_ms(self) -> float:
        """Return the next delay: short within burst, long between bursts."""
        self._counter += 1
        if self._counter % self._burst_size == 0:
            return self._pause_ms + random.uniform(-200, 200)
        return self._burst_delay_ms + random.uniform(-10, 10)

    def description(self) -> str:
        """Return description of this burst timing."""
        burst = f"burst_{self._burst_size}x{int(self._burst_delay_ms)}ms"
        return f"{burst}_pause_{int(self._pause_ms)}ms"


def create_timing(spec: str) -> TimingStrategy:
    """Create a TimingStrategy from a string specification.

    Supported formats:
        - "fixed_50ms"        -> FixedTiming(50)
        - "variable_200_800ms" -> VariableTiming(200, 800)
        - "burst_5x30ms_2000ms" -> BurstTiming(5, 30, 2000)

    Args:
        spec: The timing specification string.

    Returns:
        A TimingStrategy instance matching the specification.

    Raises:
        ValueError: If the specification format is unrecognized.
    """
    if spec.startswith("fixed_"):
        ms = float(spec.removeprefix("fixed_").removesuffix("ms"))
        return FixedTiming(ms)

    if spec.startswith("variable_"):
        parts = spec.removeprefix("variable_").removesuffix("ms").split("_")
        if len(parts) != 2:
            msg = f"Variable timing requires two values, got: {spec}"
            raise ValueError(msg)
        return VariableTiming(float(parts[0]), float(parts[1]))

    if spec.startswith("burst_"):
        remainder = spec.removeprefix("burst_")
        burst_part, pause_part = remainder.split("_pause_")
        count_str, delay_str = burst_part.split("x")
        return BurstTiming(
            burst_size=int(count_str),
            burst_delay_ms=float(delay_str.removesuffix("ms")),
            pause_ms=float(pause_part.removesuffix("ms")),
        )

    msg = f"Unrecognized timing specification: {spec}"
    raise ValueError(msg)
