"""Tests for core data models."""

from datetime import datetime

from sundew.models import (
    AttackClassification,
    AuthScheme,
    FingerprintScores,
    Persona,
    PersonaPack,
    RequestEvent,
    ResponseTemplate,
    Session,
)


def test_persona_creation() -> None:
    """Persona model should accept all required fields."""
    persona = Persona(
        seed=42,
        company_name="TestCorp",
        industry="fintech",
        api_style="rest",
        framework_fingerprint="express/4.18.2",
        error_style="rfc7807",
        auth_scheme=AuthScheme.BEARER,
        data_theme="payments",
        server_header="nginx/1.24.0",
    )
    assert persona.company_name == "TestCorp"
    assert persona.industry == "fintech"
    assert persona.endpoint_prefix == "/api/v1"
    assert persona.response_latency_ms == 50


def test_persona_get_endpoint() -> None:
    """Persona.get_endpoint should combine prefix with path."""
    persona = Persona(
        seed=1,
        company_name="Test",
        industry="saas",
        api_style="rest",
        framework_fingerprint="django/4.2",
        error_style="simple_json",
        auth_scheme=AuthScheme.API_KEY_HEADER,
        data_theme="users",
        server_header="nginx/1.24.0",
        endpoint_prefix="/v2",
    )
    assert persona.get_endpoint("/users") == "/v2/users"
    assert persona.get_endpoint("users") == "/v2/users"


def test_request_event_defaults() -> None:
    """RequestEvent should populate ID and timestamp automatically."""
    event = RequestEvent(source_ip="10.0.0.1", method="GET", path="/api/v1/test")
    assert event.id is not None
    assert isinstance(event.timestamp, datetime)
    assert event.classification == AttackClassification.UNKNOWN
    assert event.fingerprint_scores.composite == 0.0


def test_session_defaults() -> None:
    """Session should initialize with empty collections."""
    session = Session(source_ip="10.0.0.1")
    assert session.request_count == 0
    assert session.request_ids == []
    assert session.classification == AttackClassification.UNKNOWN


def test_fingerprint_scores_bounds() -> None:
    """FingerprintScores should enforce 0.0-1.0 bounds."""
    scores = FingerprintScores(timing_regularity=0.5, composite=0.8)
    assert scores.timing_regularity == 0.5
    assert scores.composite == 0.8


def test_response_template() -> None:
    """ResponseTemplate should hold template body with placeholders."""
    template = ResponseTemplate(
        endpoint="/api/v1/test",
        body_template='{"id": "{{random_id}}", "ts": "{{timestamp}}"}',
    )
    assert "{{random_id}}" in template.body_template
    assert template.status_code == 200


def test_persona_pack_structure() -> None:
    """PersonaPack should hold templates and persona defaults."""
    pack = PersonaPack(
        name="test",
        industry="saas",
        templates=[
            ResponseTemplate(
                endpoint="/api/v1/users",
                body_template='{"users": []}',
            )
        ],
    )
    assert len(pack.templates) == 1
    assert pack.industry == "saas"


def test_attack_classification_values() -> None:
    """AttackClassification enum should have all expected values."""
    assert AttackClassification.UNKNOWN == "unknown"
    assert AttackClassification.HUMAN == "human"
    assert AttackClassification.AUTOMATED == "automated"
    assert AttackClassification.AI_ASSISTED == "ai_assisted"
    assert AttackClassification.AI_AGENT == "ai_agent"
