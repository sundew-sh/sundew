# Contributing to Sundew

Thank you for your interest in contributing to Sundew. This guide will help you get started.

## Development Setup

**Requirements:**

- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Docker (for integration tests)
- Ollama (optional, for persona generation)

**Clone and install:**

```bash
git clone https://github.com/sundew-sh/sundew.git
cd sundew

# Using uv (recommended)
uv sync --all-extras

# Or using pip
pip install -e ".[dev,all]"
```

**Verify the setup:**

```bash
make lint    # ruff check + mypy
make test    # pytest
make run     # start Sundew locally
```

## Code Style

Sundew uses strict, consistent conventions:

- **Python 3.11+** -- use modern syntax (type unions with `|`, `match` statements where appropriate)
- **Type hints everywhere** -- all function signatures, all return types, all class attributes
- **Ruff** for linting and formatting -- config in `pyproject.toml`, line length 100
- **mypy** in strict mode -- no `Any` types without justification
- **Docstrings** on all public functions and classes (Google style)

Run before committing:

```bash
make lint   # ruff check + ruff format --check + mypy
make fmt    # auto-format with ruff
```

## Project Structure

```
sundew/
├── src/sundew/
│   ├── __init__.py
│   ├── cli.py              # CLI commands (serve, generate, query, mcp-client)
│   ├── server.py           # FastAPI app
│   ├── persona/
│   │   ├── generator.py    # Persona generation logic
│   │   ├── engine.py       # Response template generation via LLM
│   │   └── packs/          # Pre-built persona packs
│   ├── traps/
│   │   ├── mcp.py          # MCP server trap
│   │   ├── api.py          # REST API trap
│   │   └── discovery.py    # AI discovery endpoints
│   ├── fingerprint.py      # Request fingerprinting
│   ├── classify.py         # Session classification
│   ├── storage.py          # SQLite + JSONL logging
│   ├── mcp_client.py       # MCP server for researchers
│   └── models.py           # Pydantic data models
├── tests/
│   ├── test_persona.py
│   ├── test_traps.py
│   ├── test_fingerprint.py
│   ├── test_security.py
│   └── simulate/           # AI agent traffic simulator
├── docs/                   # Mintlify documentation source
└── scripts/
    └── generate_demo_data.py
```

## Making Changes

### 1. Create a branch

```bash
git checkout -b your-feature-name
```

### 2. Write code

Follow the code style above. Key principles:

- **No TODOs in code** -- future work goes in ROADMAP.md or GitHub issues
- **Tests for every change** -- aim for the behavior, not implementation details
- **Security first** -- never execute user-supplied code. See SECURITY.md.

### 3. Test

```bash
make test           # unit tests
make test-coverage  # with coverage report
make lint           # linting + type checking
make audit          # security audit (pip-audit + bandit)
```

### 4. Submit a pull request

- Write a clear title and description
- Reference any related issues
- Ensure CI passes
- One focused change per PR

## How to Add a New Persona Pack

Persona packs let Sundew run without an LLM. Each pack is a JSON file in `src/sundew/persona/packs/` containing pre-generated response templates for a specific industry theme.

**1. Create the pack file:**

```bash
# Generate from an existing persona
sundew generate --persona your-industry --export src/sundew/persona/packs/your-industry.json

# Or create manually
```

**2. Pack structure:**

```json
{
  "meta": {
    "industry": "e-commerce",
    "description": "Online retail platform",
    "version": "1.0.0"
  },
  "persona": {
    "company_name": "Meridian Commerce",
    "industry": "e-commerce",
    "api_style": "rest",
    "framework_fingerprint": "express",
    "auth_scheme": "bearer_jwt",
    "data_theme": "retail",
    "response_latency_ms": [60, 280],
    "server_header": "nginx/1.25.3",
    "endpoint_prefix": "/api/v1"
  },
  "endpoints": {
    "/api/v1/products": {
      "GET": {
        "status": 200,
        "headers": {},
        "body": {}
      }
    }
  },
  "mcp_tools": [],
  "discovery": {}
}
```

**3. Requirements for a good pack:**

- Realistic company name and industry context
- At least 5 REST endpoints with varied response structures
- MCP tools that match the industry theme
- Realistic fake data (valid UUIDs, plausible emails, real-looking timestamps)
- Error responses that match the persona's error style
- No overlap with existing packs in field names or response patterns

**4. Test it:**

```bash
sundew serve --persona src/sundew/persona/packs/your-industry.json
# Verify endpoints work, responses look realistic
```

## How to Add a New Trap Type

Traps are modules in `src/sundew/traps/` that serve deceptive endpoints.

**1. Create the trap module:**

```python
# src/sundew/traps/your_trap.py
"""Your trap description."""

from __future__ import annotations

from fastapi import APIRouter, Request

from sundew.models import Persona
from sundew.fingerprint import FingerprintCollector

router = APIRouter()


def create_router(persona: Persona, collector: FingerprintCollector) -> APIRouter:
    """Create trap routes shaped by the deployment persona."""

    @router.get("/your-endpoint")
    async def your_endpoint(request: Request) -> dict:
        collector.record(request, signal="your_signal")
        # Return persona-appropriate response from template cache
        return persona.get_response("/your-endpoint", "GET")

    return router
```

**2. Key requirements:**

- Every trap MUST read from the persona -- no hardcoded response content
- Every request MUST be recorded via `FingerprintCollector`
- Responses MUST come from the pre-generated template cache
- No LLM calls at runtime
- No execution of user-supplied input

**3. Register the trap:**

Add your trap to the server setup in `src/sundew/server.py` and the config schema in `sundew.yaml`.

**4. Add tests:**

```python
# tests/test_traps.py
async def test_your_trap_with_fintech_persona():
    ...

async def test_your_trap_with_saas_persona():
    ...

async def test_your_trap_records_fingerprint():
    ...
```

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for our responsible disclosure process. Do not open public issues for security vulnerabilities.

## Code of Conduct

Be respectful, constructive, and inclusive. We're building research infrastructure to understand AI agent behavior -- a topic that benefits from diverse perspectives.

## Questions?

- Open a [GitHub Discussion](https://github.com/sundew-sh/sundew/discussions)
- Read the [docs](https://docs.sundew.sh)
- Check existing issues before filing new ones

Thank you for helping make Sundew better.
