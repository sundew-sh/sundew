"""Generate demo data by running all simulator profiles against a local Sundew instance.

This script produces a realistic SQLite database that ships with the project,
allowing new users to explore `sundew query` immediately without deploying.

Usage:
    python scripts/generate_demo_data.py
    python scripts/generate_demo_data.py --target http://localhost:8080
    python scripts/generate_demo_data.py --output data/demo_sundew.db --runs 3
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Any

# Add the project root to path for imports
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

from tests.simulate.profiles import PROFILE_REGISTRY  # noqa: E402
from tests.simulate.profiles.config import PROFILE_CONFIGS  # noqa: E402


def create_demo_schema(conn: sqlite3.Connection) -> None:
    """Create the Sundew database schema for demo data."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            session_id TEXT,
            source_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            headers TEXT,
            body TEXT,
            user_agent TEXT,
            classification TEXT NOT NULL DEFAULT 'unknown',
            trap_type TEXT,
            response_status INTEGER,
            fingerprint_scores TEXT,
            notes TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            source_ip TEXT NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0,
            classification TEXT NOT NULL DEFAULT 'unknown',
            fingerprint_scores TEXT,
            endpoints_hit TEXT,
            trap_types_triggered TEXT,
            tags TEXT,
            notes TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_classification ON events(classification)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sessions_classification ON sessions(classification)"
    )
    conn.commit()


def generate_synthetic_events(
    profile_name: str,
    run_index: int,
    num_requests: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Generate synthetic event data for a simulator profile without a live server.

    This produces realistic-looking database records based on what each
    simulator profile would generate, without requiring a running Sundew instance.

    Args:
        profile_name: Name of the simulator profile.
        run_index: Index of this run (for IP variation).
        num_requests: Number of requests to generate.

    Returns:
        Tuple of (list of event dicts, session dict).
    """
    config = PROFILE_CONFIGS[profile_name]
    classification = config["expected_classification"]

    session_id = uuid.uuid4().hex
    source_ip = f"10.{run_index}.{hash(profile_name) % 256}.{run_index + 1}"
    base_time = time.time() - 3600 + (run_index * 600)

    simulator_cls = PROFILE_REGISTRY[profile_name]
    simulator = simulator_cls(target="http://honeypot.local:8080")
    request_specs = simulator.generate_requests()

    events: list[dict[str, Any]] = []
    endpoints_hit: list[str] = []
    trap_types: set[str] = set()

    for i, spec in enumerate(request_specs[:num_requests]):
        path = spec["path"]
        method = spec["method"]
        headers = spec.get("headers", {})
        user_agent = headers.get("User-Agent", "unknown")

        # Determine trap type from path
        trap_type = "rest_api"
        if "/mcp" in path or "mcp.json" in path:
            trap_type = "mcp"
        elif path in ("/robots.txt", "/openapi.json", "/swagger.json", "/.well-known/mcp.json"):
            trap_type = "discovery"

        # Generate fingerprint scores based on profile
        scores = _generate_scores(profile_name, i, num_requests)

        event = {
            "id": uuid.uuid4().hex,
            "timestamp": base_time + i * _timing_offset(profile_name),
            "session_id": session_id,
            "source_ip": source_ip,
            "method": method,
            "path": path,
            "headers": json.dumps(headers),
            "body": json.dumps(spec.get("body")) if spec.get("body") else None,
            "user_agent": user_agent,
            "classification": classification,
            "trap_type": trap_type,
            "response_status": 200 if i % 5 != 4 else 401,
            "fingerprint_scores": json.dumps(scores),
            "notes": None,
        }
        events.append(event)

        if path not in endpoints_hit:
            endpoints_hit.append(path)
        trap_types.add(trap_type)

    session = {
        "id": session_id,
        "source_ip": source_ip,
        "first_seen": events[0]["timestamp"] if events else base_time,
        "last_seen": events[-1]["timestamp"] if events else base_time,
        "request_count": len(events),
        "classification": classification,
        "fingerprint_scores": json.dumps(
            _generate_scores(profile_name, 0, 1)
        ),
        "endpoints_hit": json.dumps(endpoints_hit),
        "trap_types_triggered": json.dumps(sorted(trap_types)),
        "tags": json.dumps([profile_name]),
        "notes": f"Demo data generated from {profile_name} profile",
    }

    return events, session


def _generate_scores(profile_name: str, request_index: int, total: int) -> dict[str, float]:
    """Generate fingerprint scores appropriate for each profile type."""
    import random

    rng = random.Random(hash(f"{profile_name}_{request_index}_{total}"))

    base_scores: dict[str, dict[str, tuple[float, float]]] = {
        "naive_scanner": {
            "timing_regularity": (0.9, 1.0),
            "header_anomaly": (0.7, 0.9),
            "path_traversal": (0.8, 1.0),
            "tool_calling_pattern": (0.1, 0.3),
            "credential_stuffing": (0.0, 0.2),
            "user_agent_score": (0.6, 0.9),
        },
        "ai_recon_agent": {
            "timing_regularity": (0.4, 0.7),
            "header_anomaly": (0.6, 0.9),
            "path_traversal": (0.7, 1.0),
            "tool_calling_pattern": (0.8, 1.0),
            "credential_stuffing": (0.5, 0.8),
            "user_agent_score": (0.6, 0.9),
        },
        "mcp_agent": {
            "timing_regularity": (0.6, 0.9),
            "header_anomaly": (0.5, 0.8),
            "path_traversal": (0.4, 0.7),
            "tool_calling_pattern": (0.9, 1.0),
            "credential_stuffing": (0.3, 0.5),
            "user_agent_score": (0.6, 0.9),
        },
        "human_researcher": {
            "timing_regularity": (0.0, 0.2),
            "header_anomaly": (0.0, 0.2),
            "path_traversal": (0.1, 0.3),
            "tool_calling_pattern": (0.0, 0.1),
            "credential_stuffing": (0.0, 0.1),
            "user_agent_score": (0.0, 0.2),
        },
    }

    ranges = base_scores.get(profile_name, base_scores["human_researcher"])
    scores: dict[str, float] = {}
    for key, (low, high) in ranges.items():
        scores[key] = round(rng.uniform(low, high), 3)

    # Compute composite as weighted average
    weights = {
        "timing_regularity": 0.15,
        "header_anomaly": 0.15,
        "path_traversal": 0.2,
        "tool_calling_pattern": 0.25,
        "credential_stuffing": 0.1,
        "user_agent_score": 0.15,
    }
    composite = sum(scores[k] * weights[k] for k in weights)
    scores["composite"] = round(composite, 3)

    return scores


def _timing_offset(profile_name: str) -> float:
    """Return the average time offset between requests for a profile."""
    offsets: dict[str, float] = {
        "naive_scanner": 0.05,
        "ai_recon_agent": 0.5,
        "mcp_agent": 0.8,
        "human_researcher": 5.0,
    }
    return offsets.get(profile_name, 1.0)


def populate_demo_db(
    db_path: str | Path,
    runs_per_profile: int = 3,
) -> dict[str, Any]:
    """Generate and insert demo data for all profiles.

    Args:
        db_path: Path to the output SQLite database.
        runs_per_profile: Number of simulation runs per profile.

    Returns:
        Summary statistics of the generated data.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    create_demo_schema(conn)

    total_events = 0
    total_sessions = 0
    profile_stats: dict[str, dict[str, int]] = {}

    for profile_name in PROFILE_REGISTRY:
        simulator_cls = PROFILE_REGISTRY[profile_name]
        # Create a temporary simulator to know how many requests it generates
        sim = simulator_cls(target="http://honeypot.local:8080")
        num_requests = len(sim.generate_requests())

        profile_events = 0
        for run_idx in range(runs_per_profile):
            events, session = generate_synthetic_events(
                profile_name, run_idx, num_requests
            )

            for event in events:
                conn.execute(
                    "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    tuple(event.values()),
                )

            conn.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(session.values()),
            )

            profile_events += len(events)
            total_sessions += 1

        total_events += profile_events
        profile_stats[profile_name] = {
            "events": profile_events,
            "sessions": runs_per_profile,
        }

    conn.commit()
    conn.close()

    return {
        "db_path": str(db_path),
        "total_events": total_events,
        "total_sessions": total_sessions,
        "profiles": profile_stats,
    }


def main() -> None:
    """Parse arguments and generate demo data."""
    parser = argparse.ArgumentParser(
        description="Generate demo data for Sundew honeypot",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(_project_root / "data" / "demo_sundew.db"),
        help="Output SQLite database path",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of simulation runs per profile (default: 3)",
    )

    args = parser.parse_args()

    print(f"Generating demo data with {args.runs} runs per profile...")
    stats = populate_demo_db(args.output, args.runs)

    print(f"\nDemo database created: {stats['db_path']}")
    print(f"Total events:   {stats['total_events']}")
    print(f"Total sessions: {stats['total_sessions']}")
    print("\nPer-profile breakdown:")
    for name, pstats in stats["profiles"].items():
        print(f"  {name}: {pstats['events']} events, {pstats['sessions']} sessions")


if __name__ == "__main__":
    main()
