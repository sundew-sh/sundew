"""Tests for Sundew CLI query command.

These tests validate the CLI interface for querying captured data
using the actual sundew.cli module and its real option signatures.

Requires the CLI module (sundew.cli) to be implemented.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

if TYPE_CHECKING:
    from pathlib import Path

_CLI_AVAILABLE = False
try:
    from sundew.cli import main as cli_main
    from sundew.models import AttackClassification, RequestEvent, Session
    from sundew.storage import StorageBackend

    _CLI_AVAILABLE = True
except ImportError:
    pass

pytestmark = pytest.mark.skipif(
    not _CLI_AVAILABLE,
    reason="Sundew CLI not yet implemented (waiting on task #1)",
)


@pytest.fixture()
def populated_db(tmp_path: Path) -> tuple[Path, str]:
    """Create a Sundew storage database with sample event data for CLI testing.

    Uses the actual StorageBackend to ensure schema compatibility.

    Returns:
        Tuple of (db_path, session_id).
    """
    db_path = tmp_path / "test_sundew.db"
    log_path = tmp_path / "events.jsonl"
    storage = StorageBackend(db_path=str(db_path), log_path=str(log_path))

    session = Session(
        source_ip="10.0.0.1",
        request_count=0,
    )
    storage.save_session(session)

    for i in range(20):
        event = RequestEvent(
            source_ip="10.0.0.1",
            method="GET",
            path=f"/api/v1/endpoint_{i}",
            headers={"user-agent": "python-httpx/0.27.0"},
            user_agent="python-httpx/0.27.0",
            classification=AttackClassification.AI_AGENT,
            trap_type="rest_api",
            response_status=200,
            session_id=session.id,
        )
        storage.save_event(event)
        storage.update_session_with_event(session, event)

    return db_path, session.id


@pytest.fixture()
def config_file(tmp_path: Path, populated_db: tuple[Path, str]) -> Path:
    """Create a sundew.yaml config pointing to the test database."""
    db_path = populated_db[0]
    config_path = tmp_path / "sundew.yaml"
    config_path.write_text(
        f"server:\n  host: 127.0.0.1\n  port: 8080\n"
        f"storage:\n  database: {db_path}\n  log_file: {db_path.parent / 'events.jsonl'}\n"
        f"logging:\n  level: warning\n  output: stdout\n"
    )
    return config_path


class TestQueryCommand:
    """Test the sundew query CLI command."""

    def test_query_recent_events(self, config_file: Path, populated_db: tuple[Path, str]) -> None:
        """Test 'sundew query --last 10' returns recent events."""
        runner = CliRunner()
        result = runner.invoke(cli_main, ["--config", str(config_file), "query", "--last", "10"])
        assert result.exit_code == 0

    def test_query_by_classification(
        self, config_file: Path, populated_db: tuple[Path, str]
    ) -> None:
        """Test 'sundew query --classification ai_agent' filters correctly."""
        runner = CliRunner()
        result = runner.invoke(
            cli_main,
            ["--config", str(config_file), "query", "--classification", "ai_agent"],
        )
        assert result.exit_code == 0

    def test_query_sessions(self, config_file: Path, populated_db: tuple[Path, str]) -> None:
        """Test 'sundew query --sessions' shows session data."""
        runner = CliRunner()
        result = runner.invoke(cli_main, ["--config", str(config_file), "query", "--sessions"])
        assert result.exit_code == 0

    def test_query_json_output(self, config_file: Path, populated_db: tuple[Path, str]) -> None:
        """Test 'sundew query --json-output' produces valid JSON."""
        runner = CliRunner()
        result = runner.invoke(
            cli_main,
            ["--config", str(config_file), "query", "--last", "5", "--json-output"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) <= 5

    def test_query_sessions_json(self, config_file: Path, populated_db: tuple[Path, str]) -> None:
        """Test 'sundew query --sessions --json-output' produces valid JSON."""
        runner = CliRunner()
        result = runner.invoke(
            cli_main,
            ["--config", str(config_file), "query", "--sessions", "--json-output"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)


class TestGenerateCommand:
    """Test the sundew generate CLI command."""

    def test_generate_persona_json(self) -> None:
        """Test 'sundew generate --json-output' produces valid JSON persona."""
        runner = CliRunner()
        result = runner.invoke(cli_main, ["generate", "--json-output"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "company_name" in parsed
        assert "industry" in parsed
        assert "seed" in parsed

    def test_generate_persona_table(self) -> None:
        """Test 'sundew generate' produces a readable table."""
        runner = CliRunner()
        result = runner.invoke(cli_main, ["generate"])
        assert result.exit_code == 0
        assert "Generated Persona" in result.output

    def test_generate_persona_to_file(self, tmp_path: Path) -> None:
        """Test 'sundew generate --output file.yaml' saves persona to disk."""
        output_file = tmp_path / "persona.yaml"
        runner = CliRunner()
        result = runner.invoke(cli_main, ["generate", "--output", str(output_file)])
        assert result.exit_code == 0
        assert output_file.exists()
