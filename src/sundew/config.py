"""Configuration loading and validation for Sundew."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class TrapsConfig(BaseModel):
    """Configuration for which trap modules are enabled."""

    mcp_server: bool = True
    rest_api: bool = True
    ai_discovery: bool = True


class LLMConfig(BaseModel):
    """Configuration for the LLM provider used in persona generation."""

    provider: str = Field(
        default="none",
        description="LLM provider: ollama, anthropic, openai, none",
    )
    model: str = Field(default="llama3", description="Model name to use")
    base_url: str | None = Field(default=None, description="Custom base URL for the LLM API")
    api_key: str | None = Field(default=None, description="API key (reads from env if not set)")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2048, ge=1)


class ServerConfig(BaseModel):
    """Configuration for the FastAPI server."""

    host: str = "0.0.0.0"
    port: int = 8080


class StorageConfig(BaseModel):
    """Configuration for data storage backends."""

    database: str = "./data/sundew.db"
    log_file: str = "./data/events.jsonl"


class LoggingConfig(BaseModel):
    """Configuration for logging output."""

    level: str = "info"
    output: str = "stdout"


class SundewConfig(BaseModel):
    """Top-level Sundew configuration."""

    traps: TrapsConfig = Field(default_factory=TrapsConfig)
    persona: str = Field(
        default="auto",
        description="Persona source: 'auto' for random generation, or path to YAML file",
    )
    llm: LLMConfig = Field(default_factory=LLMConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def load_config(path: str | Path | None = None) -> SundewConfig:
    """Load Sundew configuration from a YAML file.

    Args:
        path: Path to the YAML config file. If None, uses 'sundew.yaml'
              in the current directory, falling back to defaults.

    Returns:
        A validated SundewConfig instance.
    """
    path = Path("sundew.yaml") if path is None else Path(path)

    if path.exists():
        with open(path) as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
        return SundewConfig.model_validate(raw)

    return SundewConfig()
