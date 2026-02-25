# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sundew is an open-source carnivorous honeypot that detects and classifies autonomous AI agent attacks. It deploys realistic-looking services (REST APIs, MCP servers, AI discovery endpoints) that attract AI agents, then fingerprints and classifies their behavior. Every deployment gets a unique identity via a persona engine.

## Commands

```bash
# Install
make dev                  # Install with dev dependencies

# Run
make run                  # Start honeypot server (sundew serve)
sundew serve --host 0.0.0.0 --port 8080
sundew generate --industry fintech --seed 42
sundew query --type ai_agent --last 24h

# Test
make test                 # pytest tests/ -v --tb=short
pytest tests/test_fingerprint.py -v   # Single test file
pytest tests/test_traps.py::test_name -v  # Single test

# Lint & Format
make lint                 # ruff check + ruff format --check + mypy
make format               # ruff check --fix + ruff format

# Security
make audit                # pip-audit + bandit + security tests

# Docker
make docker               # Build image
make docker-up / docker-down
```

## Architecture

```
CLI (cli.py) → FastAPI Server (server.py)
                    │
    ┌───────────────┼───────────────┐
    │               │               │
  Traps          Persona        Fingerprint
  (traps/)       (persona/)     Middleware
    │               │               │
  - api.py        generator.py   5 signals:
  - mcp.py        engine.py     timing, path enum,
  - discovery.py  packs/*.json  headers, prompt leak,
    │               │           MCP behavior
    │               │               │
    └───────────────┼───────────────┘
                    │
              Classification (classify.py)
              Score thresholds:
              <0.3 human, 0.3-0.6 automated,
              0.6-0.8 ai_assisted, >0.8 ai_agent
                    │
              Storage (storage.py)
              SQLite + JSONL
```

**Request flow:** Incoming request → fingerprint middleware scores it → routed to matching trap → trap uses persona templates for realistic responses → event logged to storage → session aggregated and classified.

**Persona system:** `generator.py` creates deterministic personas from seeds (company name, industry, auth scheme, endpoints, etc.). `engine.py` generates response templates via LLM (Ollama/Anthropic/OpenAI/Bedrock) with fallback to pre-built packs (fintech, healthcare, saas). Templates are cached in `data/template_cache.json`.

**Traps:** Each trap type serves persona-shaped deceptive content:
- `api.py` - REST API with industry-specific endpoints and auth
- `mcp.py` - JSON-RPC 2.0 MCP server with fake tools
- `discovery.py` - robots.txt, .well-known/ai-plugin.json, openapi.json

**MCP Client** (`mcp_client.py`): Separate from the MCP trap — this exposes honeypot data to researchers via MCP tools (get_recent_attacks, classify_session, export_indicators).

## Code Conventions

- Python 3.11+ with full type hints (mypy strict mode)
- Ruff for linting (line length: 100)
- Pydantic v2 for all data models and config
- async/await throughout (FastAPI + httpx)
- No TODOs in code — use ROADMAP.md

## Security Invariants

These are enforced by `test_security.py` via AST analysis and must never be violated:

1. **No code execution from external input** — no eval/exec/subprocess on user data
2. **MCP tool responses are hardcoded fiction only** — never real data
3. **Canary tokens must be safe** — IPs use RFC 1918 ranges, domains use .example.com/.test, API keys use `sk-sundew-FAKE-` prefix, OAuth tokens use `sundew-fake-token-` prefix
4. **Read-only container filesystem** (except /app/data)
5. **No outbound network from honeypot** (except optional LLM calls during setup)

## Key Data Models (models.py)

- **Persona** — generated identity (company, industry, auth scheme, endpoints, latency range)
- **RequestEvent** — single captured request with fingerprint scores and classification
- **Session** — aggregated requests from one source IP with overall classification
- **AttackClassification** — enum: UNKNOWN, HUMAN, AUTOMATED, AI_ASSISTED, AI_AGENT

## Configuration

`sundew.yaml` at repo root. Key sections: `traps` (enable/disable), `persona` (auto or path), `llm` (provider/model/region), `server` (host/port), `storage` (db/log paths), `logging` (level). LLM providers: ollama, anthropic, openai, bedrock, none.
