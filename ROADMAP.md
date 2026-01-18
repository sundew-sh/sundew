# Sundew Roadmap

## Phase 1: Foundation (Current)
- [x] Core data models and configuration
- [x] Persona generator with deterministic seeding
- [x] LLM-powered response template engine (Ollama, Anthropic, OpenAI, fallback packs)
- [x] Pre-built persona packs (fintech, saas, healthcare)
- [x] SQLite storage backend with structured JSON logging
- [x] FastAPI server with persona-aware response serving
- [x] CLI (serve, generate, query, mcp-client)
- [x] MCP server for researcher access
- [x] Docker and docker-compose deployment
- [ ] REST API trap endpoints
- [ ] MCP server trap endpoints
- [ ] AI discovery trap endpoints (robots.txt, .well-known/ai-plugin.json)
- [ ] Request fingerprinting middleware
- [ ] Session correlation and analysis

## Phase 2: Detection Intelligence
- [ ] Behavioral fingerprinting heuristics (timing, header analysis, path traversal)
- [ ] Machine learning classification model for AI agent detection
- [ ] Known AI agent signature database
- [ ] Real-time alerting (webhook, Slack, email)
- [ ] Dashboard for monitoring active sessions
- [ ] STIX/TAXII export for threat intelligence sharing

## Phase 3: Advanced Deception
- [ ] Dynamic endpoint generation based on observed probing patterns
- [ ] Adaptive response modification to prolong engagement
- [ ] Canary token injection in API responses
- [ ] Fake credential honeytokens with tracking
- [ ] Multi-stage interaction graphs (auth -> discovery -> exploitation)
- [ ] GraphQL trap with introspection support

## Phase 4: Research Platform
- [ ] Multi-instance coordination for distributed deployment
- [ ] Centralized data aggregation from multiple honeypots
- [ ] Research dataset export (anonymized)
- [ ] Automated report generation for attack campaigns
- [ ] Plugin system for custom trap modules
- [ ] Community persona pack registry

## Phase 5: Ecosystem
- [ ] Web UI for configuration and monitoring
- [ ] Terraform/Pulumi deployment modules
- [ ] Kubernetes Helm chart
- [ ] Integration with SIEM platforms (Splunk, Elastic, Sentinel)
- [ ] Automated response playbooks
- [ ] Public threat intelligence feed
