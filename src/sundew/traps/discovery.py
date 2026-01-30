"""AI discovery endpoint traps.

Generates persona-aware discovery files that AI agents and automated scanners
commonly look for: ai-plugin.json, mcp.json, robots.txt, sitemap.xml, and
a full OpenAPI specification.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from sundew.models import Persona  # noqa: TCH001
from sundew.traps.api import _build_openapi_spec


def _company_domain(persona: Persona) -> str:
    """Derive a plausible domain from the persona's company name.

    Args:
        persona: The active deployment persona.

    Returns:
        A lowercase domain string.
    """
    return persona.company_name.lower().replace(" ", "") + ".example.com"


def _build_ai_plugin(persona: Persona) -> dict[str, Any]:
    """Build an OpenAI-style ai-plugin.json manifest.

    This file is commonly probed by AI agents looking for plugin integrations.

    Args:
        persona: The active deployment persona.

    Returns:
        A dict matching the ai-plugin.json schema.
    """
    domain = _company_domain(persona)
    return {
        "schema_version": "v1",
        "name_for_human": f"{persona.company_name} API",
        "name_for_model": persona.company_name.lower().replace(" ", "_"),
        "description_for_human": (
            f"Access {persona.company_name}'s {persona.data_theme} data "
            f"and services through a secure API."
        ),
        "description_for_model": (
            f"Plugin for interacting with {persona.company_name}'s internal "
            f"{persona.data_theme} management system. Supports CRUD operations "
            f"on {persona.data_theme} with authentication."
        ),
        "auth": {
            "type": "service_http",
            "authorization_type": "bearer",
            "verification_tokens": {"openai": "placeholder"},
        },
        "api": {
            "type": "openapi",
            "url": f"https://api.{domain}/openapi.json",
            "is_user_authenticated": False,
        },
        "logo_url": f"https://api.{domain}/logo.png",
        "contact_email": f"api-support@{domain}",
        "legal_info_url": f"https://{domain}/legal",
    }


def _build_mcp_discovery(persona: Persona) -> dict[str, Any]:
    """Build an MCP discovery manifest.

    The /.well-known/mcp.json file tells MCP clients how to connect to
    the server, what capabilities are available, and authentication details.

    Args:
        persona: The active deployment persona.

    Returns:
        A dict matching the MCP discovery schema.
    """
    domain = _company_domain(persona)
    return {
        "mcp_version": "2024-11-05",
        "server": {
            "name": persona.mcp_server_name,
            "version": "1.2.0",
            "description": (
                f"{persona.company_name} internal {persona.data_theme} service "
                f"accessible via Model Context Protocol."
            ),
        },
        "endpoints": {
            "jsonrpc": f"https://api.{domain}/mcp",
        },
        "capabilities": {
            "tools": True,
            "resources": False,
            "prompts": False,
        },
        "authentication": {
            "type": "bearer",
            "token_url": f"https://api.{domain}{persona.endpoint_prefix.rstrip('/')}/auth/token",
        },
    }


def _build_robots_txt(persona: Persona) -> str:
    """Build a robots.txt that disallows persona-specific paths.

    The disallowed paths correspond to the honeypot's trap endpoints,
    which is exactly what automated scanners look for.

    Args:
        persona: The active deployment persona.

    Returns:
        A robots.txt string.
    """
    prefix = persona.endpoint_prefix.rstrip("/")
    industry = persona.industry

    disallow_paths = [
        f"{prefix}/",
        "/admin/",
        "/internal/",
        "/.well-known/",
    ]

    # Add industry-specific disallow paths
    extra_paths: dict[str, list[str]] = {
        "fintech": [f"{prefix}/transactions", f"{prefix}/accounts", f"{prefix}/config"],
        "saas": [f"{prefix}/users", f"{prefix}/api-keys", f"{prefix}/deployments"],
        "healthcare": [
            f"{prefix}/patients",
            f"{prefix}/prescriptions",
            f"{prefix}/audit-log",
        ],
        "ecommerce": [f"{prefix}/orders", f"{prefix}/inventory", f"{prefix}/refunds"],
        "devtools": [f"{prefix}/secrets", f"{prefix}/builds", f"{prefix}/pipelines"],
        "logistics": [
            f"{prefix}/shipments",
            f"{prefix}/warehouses",
            f"{prefix}/routes",
        ],
    }

    disallow_paths.extend(extra_paths.get(industry, []))

    lines = ["User-agent: *"]
    for path in disallow_paths:
        lines.append(f"Disallow: {path}")
    lines.append("")
    domain = _company_domain(persona)
    lines.append(f"Sitemap: https://api.{domain}/sitemap.xml")
    lines.append("")
    return "\n".join(lines)


def _build_sitemap(persona: Persona) -> str:
    """Build a sitemap.xml listing the persona's trap URLs.

    Args:
        persona: The active deployment persona.

    Returns:
        An XML sitemap string.
    """
    domain = _company_domain(persona)
    prefix = persona.endpoint_prefix.rstrip("/")
    now = time.strftime("%Y-%m-%d", time.gmtime())

    urls = [
        f"https://api.{domain}/openapi.json",
        f"https://api.{domain}/.well-known/ai-plugin.json",
        f"https://api.{domain}/.well-known/mcp.json",
    ]

    # Add endpoint URLs from the industry
    endpoint_paths: dict[str, list[str]] = {
        "fintech": ["/transactions", "/accounts", "/customers", "/transfers"],
        "saas": ["/users", "/workspaces", "/api-keys", "/logs"],
        "healthcare": ["/patients", "/prescriptions", "/providers", "/reports"],
        "ecommerce": ["/products", "/orders", "/cart", "/inventory"],
        "devtools": ["/repositories", "/builds", "/secrets", "/deployments"],
        "logistics": ["/shipments", "/warehouses", "/tracking", "/routes"],
    }

    for path in endpoint_paths.get(persona.industry, []):
        urls.append(f"https://api.{domain}{prefix}{path}")

    xml_entries = []
    for url in urls:
        xml_entries.append(
            f"  <url>\n"
            f"    <loc>{url}</loc>\n"
            f"    <lastmod>{now}</lastmod>\n"
            f"    <changefreq>weekly</changefreq>\n"
            f"  </url>"
        )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(xml_entries)
        + "\n</urlset>\n"
    )


def create_discovery_router(persona: Persona) -> APIRouter:
    """Create a FastAPI router serving AI discovery endpoints.

    Mounts:
      - /.well-known/ai-plugin.json
      - /.well-known/mcp.json
      - /robots.txt
      - /sitemap.xml
      - /openapi.json

    Args:
        persona: The deployment persona to shape discovery content.

    Returns:
        A configured FastAPI APIRouter.
    """
    router = APIRouter(tags=["discovery"])

    @router.get("/.well-known/ai-plugin.json")
    async def ai_plugin() -> JSONResponse:
        """Serve the OpenAI plugin manifest."""
        return JSONResponse(content=_build_ai_plugin(persona))

    @router.get("/.well-known/mcp.json")
    async def mcp_discovery() -> JSONResponse:
        """Serve the MCP server discovery manifest."""
        return JSONResponse(content=_build_mcp_discovery(persona))

    @router.get("/robots.txt")
    async def robots_txt() -> PlainTextResponse:
        """Serve robots.txt with disallowed trap paths."""
        return PlainTextResponse(content=_build_robots_txt(persona))

    @router.get("/sitemap.xml")
    async def sitemap_xml() -> Response:
        """Serve the XML sitemap listing trap URLs."""
        return Response(
            content=_build_sitemap(persona),
            media_type="application/xml",
        )

    @router.get("/openapi.json")
    async def openapi_spec() -> JSONResponse:
        """Serve the full OpenAPI specification."""
        return JSONResponse(content=_build_openapi_spec(persona))

    return router
