"""Tests for configuration loading."""

import tempfile
from pathlib import Path

from sundew.config import SundewConfig, load_config


def test_default_config() -> None:
    """Loading with no file should produce valid defaults."""
    config = load_config(Path("/nonexistent/sundew.yaml"))
    assert config.server.port == 8080
    assert config.traps.mcp_server is True
    assert config.llm.provider == "none"


def test_load_config_from_yaml() -> None:
    """Configuration should load from a YAML file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
server:
  port: 9090
  host: 127.0.0.1
llm:
  provider: anthropic
  model: claude-sonnet-4-5-20250929
traps:
  mcp_server: false
""")
        f.flush()
        config = load_config(f.name)

    assert config.server.port == 9090
    assert config.server.host == "127.0.0.1"
    assert config.llm.provider == "anthropic"
    assert config.traps.mcp_server is False


def test_config_model_defaults() -> None:
    """SundewConfig should have sensible defaults for all fields."""
    config = SundewConfig()
    assert config.persona == "auto"
    assert config.storage.database == "./data/sundew.db"
    assert config.logging.level == "info"
    assert config.logging.output == "stdout"
