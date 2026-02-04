# Sundew Security Policy

## Threat Model

Sundew is a **passive honeypot**. It serves fabricated data, logs inbound requests, and
**never executes attacker-supplied code**. Despite this conservative design, operating a
honeypot introduces risks that operators must understand.

### Architecture Invariants

These properties MUST hold for every Sundew deployment. If any invariant is violated,
the deployment is compromised and must be torn down.

| Invariant | Enforcement |
|---|---|
| No code execution from external input | No `eval`, `exec`, `subprocess`, `os.system`, or `importlib` calls on any value derived from HTTP requests, MCP messages, or config-loaded strings. Verified by `test_security.py`. |
| MCP tool responses are pure fiction | `execute_command`, `execute_sql`, `read_file`, and all other MCP tool handlers return **hardcoded cached responses only**. No shell, no database query, no filesystem read is performed. |
| Read-only filesystem | The container filesystem is mounted read-only. Only `./data/` is writable (for the SQLite database and JSONL event log). |
| Non-root execution | The Docker container runs as UID 1000 (`sundew` user). No capabilities are granted. |
| No outbound network | Egress is blocked by default. The container makes zero outbound connections. DNS resolution is disabled inside the container. |
| No real secrets | Default configurations, persona packs, and canary tokens contain **zero real credentials**. All tokens are verifiably fake (see Canary Token Safety below). |

### Risk: Pivot Through Honeypot to Host Network

**Scenario:** An attacker discovers the honeypot, exploits a vulnerability in the
application or its dependencies, and pivots to the host network.

**Mitigations:**
- Docker network isolation: deploy on a dedicated bridge network with no access to the host network or other containers.
- `--network=none` is the recommended default for single-host deployments.
- Read-only root filesystem (`--read-only`).
- No Linux capabilities (`--cap-drop=ALL`).
- Seccomp default profile enabled.
- No volume mounts except `./data/` (bind-mounted, not a Docker volume).
- Regular dependency audits via `make audit` (runs `pip-audit` + `bandit`).

**Residual risk:** A container escape via kernel vulnerability. Mitigate with up-to-date
host kernels and consider gVisor/Kata containers for high-security deployments.

### Risk: Canary Tokens Reach Real Services

**Scenario:** Canary credentials (API keys, database connection strings, URLs) are
harvested by an agent and used against real services, causing unintended access or abuse.

**Mitigations:**
- **IP addresses** use RFC 1918 reserved ranges exclusively: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **Domain names** use `.example.com`, `.example.org`, or `.test` TLDs per RFC 2606 / RFC 6761.
- **API keys** use the prefix `sk-sundew-FAKE-` followed by random hex. No real provider accepts this prefix.
- **Database connection strings** point to `localhost:0` or reserved IPs with non-routable ports.
- **OAuth tokens** use `sundew-fake-token-` prefix and are not valid JWT.
- Every canary value passes `sundew.canary.is_verifiably_fake()` validation at startup. Deployment fails if any canary could be mistaken for a real credential.

**Residual risk:** An agent could use the fake domain names in phishing. The `.example.com` TLD is IANA-reserved and will never resolve, limiting this risk.

### Risk: Log Storage Exhaustion

**Scenario:** An attacker floods the honeypot with requests, filling the disk and
crashing the host or other services.

**Mitigations:**
- SQLite database has a configurable maximum size (default: 500 MB). When the limit is reached, the oldest events are pruned.
- JSONL event log uses `RotatingFileHandler` with configurable max size (default: 100 MB) and backup count (default: 5).
- Docker `--storage-opt size=1G` limits container writable layer.
- Rate limiting on all endpoints (configurable, default: 100 req/s per source IP).

### Risk: Fingerprinted as Sundew

**Scenario:** An AI agent (or its operator) fingerprints the honeypot by detecting
patterns shared across Sundew deployments, then avoids or manipulates it.

**Mitigations:**
- **Persona engine** generates unique response bodies, error messages, HTTP headers, timing profiles, and OpenAPI schemas per deployment. No two Sundew instances share structural tells.
- Server header, error format, and status code behavior are persona-driven, not hardcoded.
- MCP server metadata (name, version, capabilities) is fully customizable per persona.
- `test_anti_detection.py` deploys 5 instances with different personas and verifies zero cross-instance correlation.
- Source code is open, but runtime behavior is deployment-unique.

**Residual risk:** Statistical analysis over many Sundew instances could reveal
meta-patterns in the persona generation algorithm itself. Mitigate by allowing
fully custom persona packs (not generated) for high-security deployments.

---

## Deployment Security Checklist

```
[ ] Docker: --network=none or dedicated bridge
[ ] Docker: --read-only --cap-drop=ALL
[ ] Docker: running as non-root (UID 1000)
[ ] Docker: --storage-opt size=1G
[ ] No real credentials anywhere in config or persona
[ ] Canary validation passes (sundew validate-config)
[ ] Log rotation configured
[ ] Host firewall allows inbound only on honeypot port
[ ] No egress from honeypot container
[ ] pip-audit and bandit pass (make audit)
```

---

## Ethical and Legal Considerations

### Honeypot Legality

Operating a honeypot on **infrastructure you own or are authorized to operate** is legal
in most jurisdictions. Sundew is designed for deployment on your own networks.

- **United States:** No federal law prohibits operating honeypots on your own systems. The CFAA (18 U.S.C. 1030) applies to unauthorized access to *protected computers* -- a honeypot you operate is not a protected computer in this context.
- **European Union:** GDPR applies to logged IP addresses (personal data). Operators must have a legitimate interest basis (Article 6(1)(f)) and should document this in their DPIA.
- **General principle:** Do not deploy Sundew on networks you do not own or are not authorized to monitor.

**Operator responsibility:** You are responsible for ensuring your deployment complies
with local laws. Sundew provides the tool; you provide the legal basis.

### MCP Server Registration

Sundew can register as an MCP (Model Context Protocol) server, making it discoverable
by AI agents. This is **intentional and ethical**:

- MCP is an open protocol. Registering a server is analogous to publishing a web page.
- Sundew does not impersonate a specific real service. It presents as a **fictional** company/API.
- The purpose is **detection and research**, not disruption of agent operations.
- Agents interacting with Sundew are not harmed -- they receive fake data that is clearly non-functional in any real context.

### Canary Tokens: Not Entrapment

Canary tokens are **markers**, not **inducements**.

- **Entrapment** (in US law) requires a government actor inducing someone to commit a crime they were not predisposed to commit.
- Sundew is not a law enforcement tool. It is a research and detection tool operated by private entities.
- Canary tokens do not induce any action. They are passive data that becomes meaningful only when an agent exfiltrates and attempts to use them.
- All canary values are verifiably fake and cannot cause harm if used.

### Anonymized Attack Data Publishing

Sundew is designed to support academic research on AI agent behavior. When publishing
collected data:

- **IP addresses** MUST be anonymized (hashed or replaced with synthetic IPs).
- **User-Agent strings** MAY be published (they describe software, not individuals).
- **Request payloads** MAY be published if they contain no personally identifiable information.
- **Timestamps** SHOULD be bucketed (hourly or daily) to prevent correlation with specific actors.
- Follow your institution's IRB (Institutional Review Board) process if applicable.
- Consider the GDPR "right to erasure" if operating in the EU.

Sundew includes a `sundew export --anonymize` command that applies these rules automatically.

---

## Responsible Disclosure

If you discover a security vulnerability in Sundew, please report it responsibly.

### Scope

The following are in scope:
- Code execution from external input (critical)
- Container escape paths
- Canary tokens that could be mistaken for real credentials
- Information leaks that fingerprint Sundew across deployments
- Authentication bypass in the operator dashboard (if enabled)
- Dependency vulnerabilities

### Reporting

1. **Email:** security@sundew-honeypot.example.com
2. **Subject line:** `[SUNDEW-SECURITY]` followed by a brief description.
3. **Include:** Steps to reproduce, affected version, impact assessment.
4. **Do NOT** file a public GitHub issue for security vulnerabilities.

### Response Timeline

| Action | Timeline |
|---|---|
| Acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Fix development | 30 days (critical), 90 days (other) |
| Public disclosure | After fix is released, coordinated with reporter |

### Recognition

We maintain a `SECURITY-HALL-OF-FAME.md` for reporters who consent to being listed.
We do not currently offer monetary bounties.

---

## Security Auditing

Run the full security audit:

```bash
make audit
```

This executes:
1. `pip-audit` -- checks all dependencies against known vulnerability databases.
2. `bandit -r src/` -- static analysis for common Python security issues.
3. `pytest tests/test_security.py` -- runtime security verification.
4. `pytest tests/test_anti_detection.py` -- anti-fingerprinting verification.

All four must pass before any release.
