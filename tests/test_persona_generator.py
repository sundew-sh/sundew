"""Tests for persona generation."""

import tempfile
from pathlib import Path

from sundew.models import Persona
from sundew.persona.generator import (
    generate_persona,
    load_persona_from_yaml,
    save_persona_to_yaml,
)


def test_generate_persona_deterministic() -> None:
    """Same seed should produce the same persona."""
    p1 = generate_persona(seed=12345)
    p2 = generate_persona(seed=12345)
    assert p1.company_name == p2.company_name
    assert p1.industry == p2.industry
    assert p1.data_theme == p2.data_theme
    assert p1.seed == p2.seed == 12345


def test_generate_persona_different_seeds() -> None:
    """Different seeds should produce different personas."""
    p1 = generate_persona(seed=1)
    p2 = generate_persona(seed=2)
    assert p1.seed != p2.seed


def test_generate_persona_random_seed() -> None:
    """Persona without seed should get a random seed assigned."""
    p = generate_persona()
    assert isinstance(p, Persona)
    assert isinstance(p.seed, int)
    assert p.company_name != ""


def test_save_and_load_persona() -> None:
    """Round-trip save and load should preserve persona fields."""
    persona = generate_persona(seed=42)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "persona.yaml"
        save_persona_to_yaml(persona, path)
        loaded = load_persona_from_yaml(path)

    assert loaded.seed == persona.seed
    assert loaded.company_name == persona.company_name
    assert loaded.industry == persona.industry
    assert loaded.data_theme == persona.data_theme
    assert loaded.auth_scheme == persona.auth_scheme


def test_persona_fields_populated() -> None:
    """Generated persona should have all required fields populated."""
    persona = generate_persona(seed=99)
    assert persona.company_name
    assert persona.industry
    assert persona.api_style
    assert persona.framework_fingerprint
    assert persona.error_style
    assert persona.auth_scheme
    assert persona.data_theme
    assert persona.server_header
    assert persona.endpoint_prefix
    assert persona.mcp_server_name
    assert persona.mcp_tool_prefix
    assert 10 <= persona.response_latency_ms <= 2000
