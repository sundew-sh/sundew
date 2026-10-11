"""Tests for persona generation."""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from sundew.cli import main
from sundew.models import Persona
from sundew.persona.generator import (
    DATA_THEMES,
    INDUSTRIES,
    MCP_TOOL_PREFIXES,
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


def test_generate_persona_industry_override() -> None:
    """An explicit industry should be honored for every supported industry."""
    for industry in INDUSTRIES:
        p = generate_persona(seed=7, industry=industry)
        assert p.industry == industry
        assert p.data_theme in DATA_THEMES[industry]
        assert p.mcp_tool_prefix in MCP_TOOL_PREFIXES[industry]


def test_generate_persona_industry_override_deterministic() -> None:
    """Same seed and industry should produce the same persona."""
    assert generate_persona(seed=7, industry="fintech") == generate_persona(
        seed=7, industry="fintech"
    )


def test_generate_persona_industry_override_keeps_company() -> None:
    """Overriding the industry should not change the seed's company name."""
    base = generate_persona(seed=7)
    for industry in INDUSTRIES:
        assert generate_persona(seed=7, industry=industry).company_name == base.company_name


def test_generate_persona_unknown_industry() -> None:
    """An unknown industry should be rejected."""
    with pytest.raises(ValueError, match="Unknown industry"):
        generate_persona(seed=7, industry="casino")


def test_cli_generate_industry() -> None:
    """`sundew generate --industry` should produce a persona in that industry."""
    result = CliRunner().invoke(main, ["generate", "-i", "fintech", "-s", "7", "--json-output"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["industry"] == "fintech"
