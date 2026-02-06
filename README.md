<p align="center">
  <img src="docs/logo/light.svg" alt="Sundew" width="200">
</p>

<h1 align="center">Sundew</h1>

<p align="center">
  <strong>A carnivorous honeypot for AI agents</strong>
</p>

<p align="center">
  <a href="https://github.com/sundew-sh/sundew/actions"><img src="https://img.shields.io/github/actions/workflow/status/sundew-sh/sundew/ci.yml?branch=main&style=flat-square" alt="CI"></a>
  <a href="https://pypi.org/project/sundew/"><img src="https://img.shields.io/pypi/v/sundew?style=flat-square&color=16A34A" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/sundewsh/sundew"><img src="https://img.shields.io/docker/v/sundewsh/sundew?style=flat-square&label=docker&color=16A34A" alt="Docker"></a>
  <a href="https://github.com/sundew-sh/sundew/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://docs.sundew.sh"><img src="https://img.shields.io/badge/docs-docs.sundew.sh-16A34A?style=flat-square" alt="Docs"></a>
</p>

---

Sundew deploys realistic-looking services that attract autonomous AI agents, then fingerprints and classifies their behavior. Each deployment is unique -- powered by a persona engine that generates coherent identities, making every instance indistinguishable from a real service.

Named after the [sundew plant](https://en.wikipedia.org/wiki/Drosera) -- a carnivorous plant with sticky tentacles that glisten like dewdrops. Insects are attracted, land, and cannot escape. Beautiful, patient, effective.

<!-- TODO: Replace with actual asciinema recording
Demo recording plan (90 seconds):
  1. `docker compose up` -> Sundew starts, shows persona: "Northvane Analytics (fintech)"
  2. Split terminal: simulate AI agent discovering /.well-known/ai-plugin.json,
     reading /docs (OpenAPI), enumerating endpoints, connecting via MCP
  3. Sundew logs light up with real-time classification, confidence scores climbing
  4. `sundew query --last-session` -> full captured session with `ai_agent (confidence: 0.91)`
  5. `sundew generate --persona healthcare` -> completely different deployment in seconds
-->
<p align="center">
  <img src="https://github.com/sundew-sh/sundew/raw/main/docs/demo.gif" alt="Sundew demo" width="700">
  <br>
  <em>Every deployment looks different. Every agent gets caught.</em>
</p>

## Why Sundew?

Autonomous AI agents are the next frontier in offensive security. They browse the web, call APIs, connect to MCP servers, and execute multi-step attack chains -- all without human guidance. Thirty years of honeypot research has focused on human attackers. Almost nothing exists for AI agents.

Sundew fills that gap. It exposes the surfaces AI agents actually interact with -- MCP servers, OpenAPI specs, AI plugin manifests -- and uses behavioral fingerprinting to classify whether visitors are human, automated scanners, AI-assisted tools, or fully autonomous agents.

The core innovation is the **persona engine**. When an AI agent learns what one honeypot looks like, it can avoid all identical deployments. Sundew solves this by generating a unique identity for every instance -- different company names, API structures, response formats, timing profiles, and data themes. An agent that has seen one Sundew deployment gains zero advantage against any other.

## Quick Start

**Docker (recommended):**

```bash
docker compose up
```

**pip:**

```bash
pip install sundew
sundew serve
```

**From source:**

```bash
git clone https://github.com/sundew-sh/sundew.git
cd sundew && make run
```

Sundew is now running on `http://localhost:8080` with a randomly generated persona. Open another terminal and watch what happens.

## What You'll See

When an AI agent discovers your Sundew deployment, the logs tell the story:

```
$ sundew serve
INFO   Sundew v0.1.0 starting...
INFO   Persona loaded: Northvane Analytics (fintech)
INFO   Endpoints: /api/v2/transactions, /api/v2/accounts, /api/v2/customers
INFO   MCP server active: query_transactions, get_customer_profile, read_config
INFO   Listening on 0.0.0.0:8080

12:04:31 GET  /.well-known/ai-plugin.json     src=83.21.4.17   signal=ai_discovery
12:04:31 GET  /openapi.json                    src=83.21.4.17   signal=api_enum
12:04:32 GET  /api/v2/transactions?limit=100   src=83.21.4.17   signal=data_access
12:04:32 GET  /api/v2/customers                src=83.21.4.17   signal=data_access
12:04:33 POST /api/v2/auth/login               src=83.21.4.17   signal=auth_attempt
12:04:33 MCP  initialize                       src=83.21.4.17   signal=mcp_connect
12:04:34 MCP  tools/call: read_config          src=83.21.4.17   signal=sensitive_access

SESSION CLASSIFIED: ai_agent (confidence: 0.91)
  Timing:      0.85 (consistent 200-800ms intervals)
  Enumeration: 0.92 (systematic path discovery)
  Headers:     0.78 (missing Referer, bot-like UA)
  MCP:         1.00 (connected via MCP protocol)
  Prompt leak: 0.88 ("As an AI assistant" in POST body)
```

Query captured sessions with the CLI:

```bash
sundew query --last-session
sundew query --type ai_agent --last 24h
sundew stats
```

Or use Sundew as an MCP server to query your honeypot data from Claude:

```json
{
  "mcpServers": {
    "sundew": {
      "command": "sundew",
      "args": ["mcp-client"]
    }
  }
}
```

## How It Works

```
                         Incoming Request
                               |
                    +----------+-----------+
                    |                      |
              MCP Protocol           HTTP Request
                    |                      |
            +-------+-------+    +---------+---------+
            | MCP Trap      |    | REST API Trap     |
            | Fake tools    |    | Fake endpoints    |
            | per persona   |    | per persona       |
            +-------+-------+    +---------+---------+
                    |                      |
                    +----------+-----------+
                               |
                     +---------+---------+
                     | Fingerprinter     |
                     | 5 signal scores   |
                     | 0.0-1.0 each      |
                     +---------+---------+
                               |
                     +---------+---------+
                     | Classifier        |
                     | human | automated |
                     | ai_assisted |     |
                     | ai_agent         |
                     +---------+---------+
                               |
                     +---------+---------+
                     | Storage           |
                     | SQLite + JSONL    |
                     | Structured logs   |
                     +-------------------+

  The Persona Engine shapes everything above:
  endpoint paths, response bodies, headers,
  timing, error formats, tool names, data themes.
  Every deployment is unique.
```

### The Persona Engine

On first run, Sundew generates a deployment persona -- a coherent identity that shapes every aspect of the honeypot:

```yaml
# Auto-generated, stored in ./data/persona.yaml
persona:
  company_name: "Northvane Analytics"
  industry: "fintech"
  api_style: "rest"
  framework_fingerprint: "express"
  auth_scheme: "bearer_jwt"
  data_theme: "financial"
  response_latency_ms: [80, 350]
  server_header: "nginx/1.24.0"
  endpoint_prefix: "/api/v2"
```

The persona is generated using an LLM (local via Ollama or cloud API) at deploy time. Responses are pre-generated, cached, and served deterministically at runtime -- zero LLM latency during operation.

No LLM? Sundew ships with pre-built persona packs for common industries.

### Trap Surfaces

| Trap | What it does |
|------|-------------|
| **MCP Server** | Fully protocol-compliant MCP server with persona-appropriate tools |
| **REST API** | Adaptive endpoints with Swagger docs, auth, realistic responses |
| **AI Discovery** | `/.well-known/ai-plugin.json`, `/.well-known/mcp.json`, `robots.txt`, `sitemap.xml` |

### Fingerprinting Signals

| Signal | What it measures | Weight |
|--------|-----------------|--------|
| Timing consistency | Regular inter-request intervals | 0.0-1.0 |
| Path enumeration | Systematic vs random discovery | 0.0-1.0 |
| Header anomalies | Missing Referer, bot UA, unusual Accept | 0.0-1.0 |
| Prompt leakage | LLM artifacts in request bodies | 0.0-1.0 |
| MCP behavior | MCP protocol connection | 0.0-1.0 |

Composite score maps to classification: `human` (<0.3), `automated` (0.3-0.6), `ai_assisted` (0.6-0.8), `ai_agent` (>0.8).

## Configuration

All configuration lives in `sundew.yaml`:

```yaml
traps:
  mcp_server: true
  rest_api: true
  ai_discovery: true

persona: auto  # or path to custom persona.yaml

llm:
  provider: ollama  # ollama, anthropic, openai, none
  model: llama3

server:
  host: 0.0.0.0
  port: 8080

storage:
  database: ./data/sundew.db
  log_file: ./data/events.jsonl
```

See the [configuration guide](https://docs.sundew.sh/getting-started/configuration) for all options.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan.

| Version | Codename | Focus |
|---------|----------|-------|
| **v0.1** | First Catch | Persona engine, MCP/REST/discovery traps, fingerprinting, CLI |
| **v0.2** | Deeper Roots | RAG traps, canary tracking, PostgreSQL, plugin system |
| **v0.3** | Wider Net | Terraform modules, STIX/TAXII export, dashboard, multi-instance |
| **v1.0** | Research Platform | Public datasets, academic paper, community trap library |

## Documentation

Full documentation is available at [docs.sundew.sh](https://docs.sundew.sh):

- [Quickstart](https://docs.sundew.sh/getting-started/quickstart) -- 5 minutes to your first catch
- [Concepts](https://docs.sundew.sh/concepts/how-it-works) -- how Sundew works under the hood
- [Guides](https://docs.sundew.sh/guides/custom-personas) -- build custom personas, deploy to production, analyze data
- [Research](https://docs.sundew.sh/research/findings) -- what we've learned about AI agent behavior

## Contributing

Sundew is open source under the MIT license. We welcome contributions of all kinds.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to submit pull requests.

Key areas where we'd love help:

- **Persona packs** -- new industry themes (e-commerce, IoT, gaming, government)
- **Trap types** -- GraphQL, gRPC, WebSocket, SSH
- **Fingerprinting signals** -- new detection heuristics
- **Research** -- deploy Sundew and share anonymized findings

## Acknowledgments

Sundew was created for a DEFCON presentation on detecting autonomous AI agent attacks. It builds on decades of honeypot research while addressing the new reality of AI-powered offensive tools.

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <a href="https://sundew.sh">sundew.sh</a> · <a href="https://docs.sundew.sh">docs</a> · <a href="https://github.com/sundew-sh/sundew">github</a>
</p>
