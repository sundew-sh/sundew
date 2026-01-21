"""Deterministic persona generation for unique honeypot deployments."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import yaml

from sundew.models import AuthScheme, Persona

COMPANY_PREFIXES = [
    "Nova",
    "Apex",
    "Cirrus",
    "Vortex",
    "Helix",
    "Prism",
    "Nexus",
    "Vertex",
    "Stratos",
    "Cipher",
    "Pulse",
    "Quantum",
    "Atlas",
    "Zenith",
    "Flux",
    "Ember",
    "Cobalt",
    "Nimbus",
    "Drift",
    "Forge",
    "Lumen",
    "Crest",
]

COMPANY_SUFFIXES = [
    "Systems",
    "Labs",
    "AI",
    "Cloud",
    "Data",
    "Tech",
    "Platform",
    "IO",
    "Solutions",
    "Analytics",
    "Works",
    "Logic",
    "Base",
    "Hub",
    "Core",
    "Stack",
    "Flow",
    "Net",
    "API",
    "Ops",
]

INDUSTRIES = ["fintech", "saas", "healthcare", "ecommerce", "devtools", "logistics"]

API_STYLES = ["rest", "graphql", "jsonrpc"]

FRAMEWORKS = [
    "express/4.18.2",
    "django/4.2",
    "rails/7.1",
    "spring-boot/3.2.0",
    "fastapi/0.109.0",
    "flask/3.0.0",
    "nestjs/10.3.0",
    "gin/1.9.1",
    "laravel/10.40",
    "actix-web/4.4",
]

ERROR_STYLES = ["rfc7807", "simple_json", "html", "xml"]

DATA_THEMES: dict[str, list[str]] = {
    "fintech": ["payments", "transactions", "accounts", "transfers", "invoices"],
    "saas": ["users", "workspaces", "subscriptions", "integrations", "webhooks"],
    "healthcare": ["patients", "appointments", "records", "prescriptions", "providers"],
    "ecommerce": ["products", "orders", "carts", "inventory", "reviews"],
    "devtools": ["repositories", "builds", "deployments", "pipelines", "artifacts"],
    "logistics": ["shipments", "warehouses", "routes", "tracking", "carriers"],
}

SERVER_HEADERS = [
    "nginx/1.24.0",
    "nginx/1.25.3",
    "Apache/2.4.58",
    "cloudflare",
    "AmazonS3",
    "gws",
    "Microsoft-IIS/10.0",
    "openresty/1.25.3.1",
]

ENDPOINT_PREFIXES = [
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/rest/v1",
    "/api",
    "/service/api",
]

MCP_SERVER_NAMES = [
    "data-api",
    "platform-api",
    "core-service",
    "main-api",
    "backend",
    "service-hub",
    "api-gateway",
    "data-service",
]

MCP_TOOL_PREFIXES: dict[str, list[str]] = {
    "fintech": ["payment_", "txn_", "account_", "finance_"],
    "saas": ["workspace_", "user_", "tenant_", "app_"],
    "healthcare": ["patient_", "clinical_", "health_", "medical_"],
    "ecommerce": ["product_", "order_", "catalog_", "shop_"],
    "devtools": ["repo_", "build_", "deploy_", "pipeline_"],
    "logistics": ["shipment_", "route_", "warehouse_", "tracking_"],
}


def generate_persona(seed: int | None = None) -> Persona:
    """Generate a random but internally consistent persona.

    Uses a deterministic seed so the same seed always produces the same
    persona. If no seed is provided, a random one is chosen.

    Args:
        seed: Optional integer seed for reproducible generation.

    Returns:
        A fully populated Persona instance.
    """
    if seed is None:
        seed = random.randint(0, 2**31 - 1)

    rng = random.Random(seed)

    industry = rng.choice(INDUSTRIES)
    company_name = f"{rng.choice(COMPANY_PREFIXES)}{rng.choice(COMPANY_SUFFIXES)}"
    data_theme = rng.choice(DATA_THEMES[industry])
    endpoint_prefix = rng.choice(ENDPOINT_PREFIXES)
    mcp_tool_prefix = rng.choice(MCP_TOOL_PREFIXES[industry])

    return Persona(
        seed=seed,
        company_name=company_name,
        industry=industry,
        api_style=rng.choice(API_STYLES),
        framework_fingerprint=rng.choice(FRAMEWORKS),
        error_style=rng.choice(ERROR_STYLES),
        auth_scheme=rng.choice(list(AuthScheme)),
        data_theme=data_theme,
        response_latency_ms=rng.randint(20, 300),
        server_header=rng.choice(SERVER_HEADERS),
        endpoint_prefix=endpoint_prefix,
        extra_headers=_generate_extra_headers(rng, industry),
        mcp_server_name=rng.choice(MCP_SERVER_NAMES),
        mcp_tool_prefix=mcp_tool_prefix,
    )


def load_persona_from_yaml(path: str | Path) -> Persona:
    """Load a persona from a YAML file.

    Args:
        path: Path to the YAML file containing persona configuration.

    Returns:
        A validated Persona instance.

    Raises:
        FileNotFoundError: If the YAML file does not exist.
        ValueError: If the YAML content is invalid.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Persona file not found: {path}")

    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    return Persona.model_validate(raw)


def save_persona_to_yaml(persona: Persona, path: str | Path) -> Path:
    """Save a persona to a YAML file.

    Args:
        persona: The Persona instance to save.
        path: Destination file path.

    Returns:
        The resolved Path where the persona was saved.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = persona.model_dump()
    scheme = data["auth_scheme"]
    data["auth_scheme"] = scheme.value if hasattr(scheme, "value") else scheme

    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    return path.resolve()


def _generate_extra_headers(rng: random.Random, industry: str) -> dict[str, str]:
    """Generate realistic extra HTTP headers for a persona.

    Args:
        rng: Seeded random instance for deterministic output.
        industry: The industry theme to influence header choices.

    Returns:
        A dict of extra HTTP header name-value pairs.
    """
    headers: dict[str, str] = {}

    if rng.random() < 0.6:
        headers["X-Request-Id"] = "{{request_id}}"
    if rng.random() < 0.4:
        headers["X-RateLimit-Limit"] = str(rng.choice([100, 500, 1000, 5000]))
    if rng.random() < 0.3:
        headers["X-Powered-By"] = rng.choice(["Express", "Django", "Rails", "Spring"])
    if rng.random() < 0.5:
        headers["X-Response-Time"] = "{{response_time_ms}}ms"

    return headers
