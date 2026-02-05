"""Tests for the storage backend."""

import tempfile
from pathlib import Path

from sundew.models import AttackClassification, RequestEvent, Session
from sundew.storage import StorageBackend


def _make_storage() -> StorageBackend:
    """Create a storage backend with a temporary database."""
    tmpdir = tempfile.mkdtemp()
    return StorageBackend(
        db_path=Path(tmpdir) / "test.db",
        log_path=Path(tmpdir) / "events.jsonl",
    )


def test_save_and_get_event() -> None:
    """Events should round-trip through save and get."""
    storage = _make_storage()
    event = RequestEvent(
        source_ip="10.0.0.1",
        method="GET",
        path="/api/v1/test",
    )
    storage.save_event(event)
    loaded = storage.get_event(event.id)
    assert loaded is not None
    assert loaded.source_ip == "10.0.0.1"
    assert loaded.method == "GET"
    assert loaded.path == "/api/v1/test"


def test_save_and_get_session() -> None:
    """Sessions should round-trip through save and get."""
    storage = _make_storage()
    session = Session(source_ip="10.0.0.2")
    storage.save_session(session)
    loaded = storage.get_session(session.id)
    assert loaded is not None
    assert loaded.source_ip == "10.0.0.2"


def test_get_recent_events() -> None:
    """get_recent_events should return events in reverse chronological order."""
    storage = _make_storage()
    for i in range(5):
        event = RequestEvent(
            source_ip="10.0.0.1",
            method="GET",
            path=f"/test/{i}",
        )
        storage.save_event(event)
    events = storage.get_recent_events(limit=3)
    assert len(events) == 3


def test_get_events_by_classification() -> None:
    """Filtering by classification should return only matching events."""
    storage = _make_storage()

    event1 = RequestEvent(
        source_ip="10.0.0.1",
        method="GET",
        path="/test/1",
        classification=AttackClassification.AI_AGENT,
    )
    event2 = RequestEvent(
        source_ip="10.0.0.2",
        method="GET",
        path="/test/2",
        classification=AttackClassification.HUMAN,
    )
    storage.save_event(event1)
    storage.save_event(event2)

    ai_events = storage.get_events_by_classification(AttackClassification.AI_AGENT)
    assert len(ai_events) == 1
    assert ai_events[0].source_ip == "10.0.0.1"


def test_count_events() -> None:
    """count_events should return accurate count."""
    storage = _make_storage()
    assert storage.count_events() == 0
    storage.save_event(RequestEvent(source_ip="10.0.0.1", method="GET", path="/test"))
    assert storage.count_events() == 1


def test_session_event_tracking() -> None:
    """update_session_with_event should track request IDs and endpoints."""
    storage = _make_storage()
    session = Session(source_ip="10.0.0.1")
    event = RequestEvent(
        source_ip="10.0.0.1",
        method="POST",
        path="/api/v1/payments",
        trap_type="rest_api",
    )

    updated = storage.update_session_with_event(session, event)
    assert updated.request_count == 1
    assert event.id in updated.request_ids
    assert "/api/v1/payments" in updated.endpoints_hit
    assert "rest_api" in updated.trap_types_triggered


def test_get_or_create_session() -> None:
    """get_or_create_session should reuse recent sessions."""
    storage = _make_storage()
    s1 = storage.get_or_create_session("10.0.0.1")
    s2 = storage.get_or_create_session("10.0.0.1")
    assert s1.id == s2.id
