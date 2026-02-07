"""CLI entry point for the AI agent traffic simulator.

Usage:
    python -m tests.simulate --profile ai_recon_agent --target http://localhost:8080
    python -m tests.simulate --profile naive_scanner --target http://localhost:8080 --runs 5
    python -m tests.simulate --list-profiles
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any

from tests.simulate.base import SimulationResult  # noqa: TC001
from tests.simulate.profiles import PROFILE_REGISTRY
from tests.simulate.profiles.config import PROFILE_CONFIGS


def format_result(result: SimulationResult) -> dict[str, Any]:
    """Convert a SimulationResult to a JSON-serializable summary."""
    return {
        "profile": result.profile_name,
        "target": result.target,
        "total_requests": result.total_requests,
        "duration_seconds": round(result.duration_seconds, 3),
        "status_codes": result.status_code_distribution,
        "unique_paths_count": len(result.unique_paths),
        "errors": result.errors,
    }


def print_result(result: SimulationResult) -> None:
    """Print a human-readable summary of a simulation run."""
    print(f"\n{'=' * 60}")
    print(f"Profile: {result.profile_name}")
    print(f"Target:  {result.target}")
    print(f"{'=' * 60}")
    print(f"Total requests:  {result.total_requests}")
    print(f"Duration:        {result.duration_seconds:.3f}s")
    print(f"Unique paths:    {len(result.unique_paths)}")
    print(f"Status codes:    {result.status_code_distribution}")
    if result.errors:
        print(f"Errors:          {len(result.errors)}")
        for err in result.errors[:5]:
            print(f"  - {err}")
    print()


async def run_simulation(
    profile_name: str,
    target: str,
    runs: int = 1,
    *,
    json_output: bool = False,
) -> list[SimulationResult]:
    """Run a simulation profile against the target.

    Args:
        profile_name: Name of the simulator profile to run.
        target: Target URL (e.g., http://localhost:8080).
        runs: Number of times to repeat the simulation.
        json_output: If True, output results as JSON.

    Returns:
        List of SimulationResult objects.
    """
    simulator_cls = PROFILE_REGISTRY.get(profile_name)
    if simulator_cls is None:
        print(f"Unknown profile: {profile_name}", file=sys.stderr)
        print(f"Available profiles: {', '.join(PROFILE_REGISTRY.keys())}", file=sys.stderr)
        sys.exit(1)

    results: list[SimulationResult] = []
    for i in range(runs):
        if not json_output:
            print(f"Run {i + 1}/{runs}...")

        simulator = simulator_cls(target=target)
        result = await simulator.run()
        results.append(result)

        if json_output:
            print(json.dumps(format_result(result)))
        else:
            print_result(result)

    return results


def list_profiles() -> None:
    """Print all available simulator profiles."""
    print("\nAvailable simulator profiles:\n")
    for name, config in PROFILE_CONFIGS.items():
        desc = config.get("description", "No description")
        timing = config.get("timing", "unknown")
        expected = config.get("expected_classification", "unknown")
        print(f"  {name}")
        print(f"    Description:    {desc}")
        print(f"    Timing:         {timing}")
        print(f"    Expected class: {expected}")
        print()


def main() -> None:
    """Parse arguments and run the simulator."""
    parser = argparse.ArgumentParser(
        prog="tests.simulate",
        description="AI Agent Traffic Simulator for Sundew honeypot testing",
    )
    parser.add_argument(
        "--profile",
        type=str,
        help="Simulator profile to run",
    )
    parser.add_argument(
        "--target",
        type=str,
        default="http://localhost:8080",
        help="Target Sundew instance URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of simulation runs (default: 1)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        default=False,
        help="List all available simulator profiles",
    )

    args = parser.parse_args()

    if args.list_profiles:
        list_profiles()
        return

    if not args.profile:
        parser.error("--profile is required (or use --list-profiles)")

    start = time.monotonic()
    asyncio.run(run_simulation(args.profile, args.target, args.runs, json_output=args.json))
    elapsed = time.monotonic() - start

    if not args.json:
        print(f"Total elapsed: {elapsed:.3f}s")


if __name__ == "__main__":
    main()
