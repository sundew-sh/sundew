"""Storage layer for Sundew events and sessions.

Provides SQLite backend for structured storage and JSON Lines logging
for streaming event output.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sundew.models import (
    AttackClassification,
    FingerprintScores,
    RequestEvent,
    Session,
)

logger = logging.getLogger(__name__)


class StorageBackend:
    """SQLite-based storage for honeypot events and sessions.

    Handles persistence of RequestEvent and Session objects, with
    structured JSON Lines logging as a secondary output.
    """

    def __init__(self, db_path: str | Path, log_path: str | Path | None = None) -> None:
        """Initialize the storage backend.

        Args:
            db_path: Path to the SQLite database file.
            log_path: Optional path for JSON Lines event log.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path = Path(log_path) if log_path else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create database tables if they do not exist."""
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                session_id TEXT,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                query_params TEXT NOT NULL DEFAULT '{}',
                headers TEXT NOT NULL DEFAULT '{}',
                body TEXT,
                body_json TEXT,
                content_type TEXT,
                user_agent TEXT,
                fingerprint_scores TEXT NOT NULL DEFAULT '{}',
                classification TEXT NOT NULL DEFAULT 'unknown',
                trap_type TEXT,
                matched_endpoint TEXT,
                response_status INTEGER,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                request_ids TEXT NOT NULL DEFAULT '[]',
                classification TEXT NOT NULL DEFAULT 'unknown',
                fingerprint_scores TEXT NOT NULL DEFAULT '{}',
                endpoints_hit TEXT NOT NULL DEFAULT '[]',
                trap_types_triggered TEXT NOT NULL DEFAULT '[]',
                tags TEXT NOT NULL DEFAULT '[]',
                notes TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_classification ON events(classification);
            CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
            CREATE INDEX IF NOT EXISTS idx_sessions_classification ON sessions(classification);
        """)
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the SQLite database.

        Returns:
            A sqlite3.Connection instance.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def save_event(self, event: RequestEvent) -> None:
        """Persist a RequestEvent to the database and event log.

        Args:
            event: The RequestEvent to store.
        """
        conn = self._connect()
        conn.execute(
            """INSERT OR REPLACE INTO events
               (id, timestamp, session_id, source_ip, source_port, method, path,
                query_params, headers, body, body_json, content_type, user_agent,
                fingerprint_scores, classification, trap_type, matched_endpoint,
                response_status, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id,
                event.timestamp.isoformat(),
                event.session_id,
                event.source_ip,
                event.source_port,
                event.method,
                event.path,
                json.dumps(event.query_params),
                json.dumps(event.headers),
                event.body,
                json.dumps(event.body_json) if event.body_json else None,
                event.content_type,
                event.user_agent,
                event.fingerprint_scores.model_dump_json(),
                event.classification.value,
                event.trap_type,
                event.matched_endpoint,
                event.response_status,
                event.notes,
            ),
        )
        conn.commit()
        conn.close()

        self._log_event(event)

    def save_session(self, session: Session) -> None:
        """Persist a Session to the database.

        Args:
            session: The Session to store.
        """
        conn = self._connect()
        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (id, source_ip, first_seen, last_seen, request_count, request_ids,
                classification, fingerprint_scores, endpoints_hit, trap_types_triggered,
                tags, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session.id,
                session.source_ip,
                session.first_seen.isoformat(),
                session.last_seen.isoformat(),
                session.request_count,
                json.dumps(session.request_ids),
                session.classification.value,
                session.fingerprint_scores.model_dump_json(),
                json.dumps(session.endpoints_hit),
                json.dumps(session.trap_types_triggered),
                json.dumps(session.tags),
                session.notes,
            ),
        )
        conn.commit()
        conn.close()

    def get_event(self, event_id: str) -> RequestEvent | None:
        """Retrieve a single event by ID.

        Args:
            event_id: The event ID to look up.

        Returns:
            The matching RequestEvent, or None if not found.
        """
        conn = self._connect()
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        conn.close()

        if row is None:
            return None
        return _row_to_event(row)

    def get_session(self, session_id: str) -> Session | None:
        """Retrieve a single session by ID.

        Args:
            session_id: The session ID to look up.

        Returns:
            The matching Session, or None if not found.
        """
        conn = self._connect()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        conn.close()

        if row is None:
            return None
        return _row_to_session(row)

    def get_recent_events(self, limit: int = 50) -> list[RequestEvent]:
        """Retrieve the most recent events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of RequestEvent instances, most recent first.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [_row_to_event(row) for row in rows]

    def get_recent_sessions(self, limit: int = 20) -> list[Session]:
        """Retrieve the most recent sessions.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            List of Session instances, most recent first.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [_row_to_session(row) for row in rows]

    def get_events_by_classification(
        self, classification: AttackClassification, limit: int = 50
    ) -> list[RequestEvent]:
        """Retrieve events filtered by classification.

        Args:
            classification: The classification to filter by.
            limit: Maximum number of events to return.

        Returns:
            List of matching RequestEvent instances.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM events WHERE classification = ? ORDER BY timestamp DESC LIMIT ?",
            (classification.value, limit),
        ).fetchall()
        conn.close()
        return [_row_to_event(row) for row in rows]

    def get_session_events(self, session_id: str) -> list[RequestEvent]:
        """Retrieve all events belonging to a session.

        Args:
            session_id: The session ID to look up events for.

        Returns:
            List of RequestEvent instances in chronological order.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        ).fetchall()
        conn.close()
        return [_row_to_event(row) for row in rows]

    def count_events(self) -> int:
        """Return the total number of stored events.

        Returns:
            Event count as an integer.
        """
        conn = self._connect()
        result = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        conn.close()
        return result[0] if result else 0

    def count_sessions(self) -> int:
        """Return the total number of stored sessions.

        Returns:
            Session count as an integer.
        """
        conn = self._connect()
        result = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
        conn.close()
        return result[0] if result else 0

    def get_or_create_session(self, source_ip: str) -> Session:
        """Get the active session for an IP or create a new one.

        Args:
            source_ip: The source IP address.

        Returns:
            An existing or new Session instance.
        """
        conn = self._connect()
        row = conn.execute(
            """SELECT * FROM sessions WHERE source_ip = ?
               ORDER BY last_seen DESC LIMIT 1""",
            (source_ip,),
        ).fetchone()
        conn.close()

        if row is not None:
            session = _row_to_session(row)
            now = datetime.now(UTC)
            last = session.last_seen
            if last.tzinfo is None:
                last = last.replace(tzinfo=UTC)
            age = (now - last).total_seconds()
            if age < 3600:
                return session

        session = Session(source_ip=source_ip)
        self.save_session(session)
        return session

    def update_session_with_event(self, session: Session, event: RequestEvent) -> Session:
        """Update a session with a new event.

        Args:
            session: The session to update.
            event: The new event to add.

        Returns:
            The updated Session instance.
        """
        session.last_seen = event.timestamp
        session.request_count += 1
        session.request_ids.append(event.id)

        if event.path not in session.endpoints_hit:
            session.endpoints_hit.append(event.path)
        if event.trap_type and event.trap_type not in session.trap_types_triggered:
            session.trap_types_triggered.append(event.trap_type)

        self.save_session(session)
        return session

    def _log_event(self, event: RequestEvent) -> None:
        """Append an event to the JSON Lines log file.

        Args:
            event: The event to log.
        """
        if self.log_path is None:
            return
        try:
            with open(self.log_path, "a") as f:
                f.write(event.model_dump_json() + "\n")
        except OSError as exc:
            logger.warning("Failed to write event log: %s", exc)


def _row_to_event(row: sqlite3.Row) -> RequestEvent:
    """Convert a database row to a RequestEvent.

    Args:
        row: A sqlite3.Row from the events table.

    Returns:
        A populated RequestEvent instance.
    """
    return RequestEvent(
        id=row["id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        session_id=row["session_id"],
        source_ip=row["source_ip"],
        source_port=row["source_port"],
        method=row["method"],
        path=row["path"],
        query_params=json.loads(row["query_params"]),
        headers=json.loads(row["headers"]),
        body=row["body"],
        body_json=json.loads(row["body_json"]) if row["body_json"] else None,
        content_type=row["content_type"],
        user_agent=row["user_agent"],
        fingerprint_scores=FingerprintScores.model_validate_json(row["fingerprint_scores"]),
        classification=AttackClassification(row["classification"]),
        trap_type=row["trap_type"],
        matched_endpoint=row["matched_endpoint"],
        response_status=row["response_status"],
        notes=row["notes"],
    )


def _row_to_session(row: sqlite3.Row) -> Session:
    """Convert a database row to a Session.

    Args:
        row: A sqlite3.Row from the sessions table.

    Returns:
        A populated Session instance.
    """
    return Session(
        id=row["id"],
        source_ip=row["source_ip"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        request_count=row["request_count"],
        request_ids=json.loads(row["request_ids"]),
        classification=AttackClassification(row["classification"]),
        fingerprint_scores=FingerprintScores.model_validate_json(row["fingerprint_scores"]),
        endpoints_hit=json.loads(row["endpoints_hit"]),
        trap_types_triggered=json.loads(row["trap_types_triggered"]),
        tags=json.loads(row["tags"]),
        notes=row["notes"],
    )
