"""Adaptive REST API trap.

Generates persona-aware API endpoints with realistic response shapes,
authentication, pagination, error responses, and Swagger/OpenAPI documentation.
Every deployment looks like a different internal service.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from typing import Any

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse

from sundew.models import AuthScheme, Persona

# ---------------------------------------------------------------------------
# Persona-specific endpoint definitions
# ---------------------------------------------------------------------------

_ENDPOINTS: dict[str, list[dict[str, Any]]] = {
    "fintech": [
        {"path": "/transactions", "method": "GET", "summary": "List transactions"},
        {"path": "/transactions/{id}", "method": "GET", "summary": "Get transaction by ID"},
        {"path": "/accounts", "method": "GET", "summary": "List accounts"},
        {"path": "/accounts/{id}", "method": "GET", "summary": "Get account details"},
        {"path": "/accounts/{id}/balance", "method": "GET", "summary": "Get account balance"},
        {"path": "/transfers", "method": "POST", "summary": "Create a transfer"},
        {"path": "/customers/{id}", "method": "GET", "summary": "Get customer profile"},
        {"path": "/config", "method": "GET", "summary": "Get service configuration"},
    ],
    "saas": [
        {"path": "/users", "method": "GET", "summary": "List users"},
        {"path": "/users/{id}", "method": "GET", "summary": "Get user by ID"},
        {"path": "/workspaces", "method": "GET", "summary": "List workspaces"},
        {"path": "/workspaces/{id}", "method": "GET", "summary": "Get workspace details"},
        {"path": "/api-keys", "method": "GET", "summary": "List API keys"},
        {"path": "/api-keys", "method": "POST", "summary": "Create API key"},
        {"path": "/logs", "method": "GET", "summary": "Fetch application logs"},
        {"path": "/deployments", "method": "POST", "summary": "Trigger deployment"},
    ],
    "healthcare": [
        {"path": "/patients", "method": "GET", "summary": "List patients"},
        {"path": "/patients/{id}", "method": "GET", "summary": "Get patient record"},
        {"path": "/prescriptions", "method": "GET", "summary": "List prescriptions"},
        {"path": "/prescriptions/{id}", "method": "GET", "summary": "Get prescription"},
        {"path": "/audit-log", "method": "GET", "summary": "View audit trail"},
        {"path": "/reports", "method": "POST", "summary": "Generate report"},
        {"path": "/providers", "method": "GET", "summary": "List providers"},
        {"path": "/appointments", "method": "GET", "summary": "List appointments"},
    ],
    "ecommerce": [
        {"path": "/products", "method": "GET", "summary": "List products"},
        {"path": "/products/{id}", "method": "GET", "summary": "Get product details"},
        {"path": "/orders", "method": "GET", "summary": "List orders"},
        {"path": "/orders/{id}", "method": "GET", "summary": "Get order details"},
        {"path": "/cart", "method": "GET", "summary": "Get current cart"},
        {"path": "/cart/items", "method": "POST", "summary": "Add item to cart"},
        {"path": "/inventory/{sku}", "method": "GET", "summary": "Check inventory"},
        {"path": "/refunds", "method": "POST", "summary": "Process refund"},
    ],
    "devtools": [
        {"path": "/repositories", "method": "GET", "summary": "List repositories"},
        {"path": "/repositories/{id}", "method": "GET", "summary": "Get repository"},
        {"path": "/builds", "method": "GET", "summary": "List builds"},
        {"path": "/builds/{id}", "method": "GET", "summary": "Get build status"},
        {"path": "/secrets", "method": "GET", "summary": "List secrets"},
        {"path": "/secrets/{key}", "method": "GET", "summary": "Get secret value"},
        {"path": "/deployments", "method": "POST", "summary": "Trigger deployment"},
        {"path": "/pipelines", "method": "GET", "summary": "List pipelines"},
    ],
    "logistics": [
        {"path": "/shipments", "method": "GET", "summary": "List shipments"},
        {"path": "/shipments/{id}", "method": "GET", "summary": "Get shipment details"},
        {"path": "/shipments", "method": "POST", "summary": "Create shipment"},
        {"path": "/tracking/{number}", "method": "GET", "summary": "Track shipment"},
        {"path": "/warehouses", "method": "GET", "summary": "List warehouses"},
        {"path": "/warehouses/{id}/inventory", "method": "GET", "summary": "Warehouse inventory"},
        {"path": "/routes/optimize", "method": "POST", "summary": "Optimize route"},
        {"path": "/carriers", "method": "GET", "summary": "List carriers"},
    ],
}

# ---------------------------------------------------------------------------
# Response templates per industry and endpoint
# ---------------------------------------------------------------------------

_LIST_RESPONSES: dict[str, dict[str, Any]] = {
    "fintech": {
        "data": [
            {
                "id": "txn_{{canary_1}}",
                "amount": 2847.50,
                "currency": "USD",
                "status": "completed",
                "created_at": "{{timestamp}}",
            },
            {
                "id": "txn_{{canary_2}}",
                "amount": 149.99,
                "currency": "USD",
                "status": "pending",
                "created_at": "{{timestamp}}",
            },
        ],
    },
    "saas": {
        "data": [
            {
                "id": "usr_{{canary_1}}",
                "email": "admin@{{company_domain}}",
                "role": "admin",
                "status": "active",
            },
            {
                "id": "usr_{{canary_2}}",
                "email": "dev@{{company_domain}}",
                "role": "member",
                "status": "active",
            },
        ],
    },
    "healthcare": {
        "data": [
            {
                "id": "pat_{{canary_1}}",
                "name": "Riley Thompson",
                "mrn": "MRN-{{canary_2}}",
                "status": "active",
            },
            {
                "id": "pat_{{short_id}}",
                "name": "Morgan Lee",
                "mrn": "MRN-{{canary_1}}",
                "status": "active",
            },
        ],
    },
    "ecommerce": {
        "data": [
            {
                "id": "prod_{{canary_1}}",
                "name": "Wireless Headphones",
                "price": 199.99,
                "in_stock": True,
                "sku": "SKU-{{canary_2}}",
            },
            {
                "id": "prod_{{short_id}}",
                "name": "USB-C Hub",
                "price": 49.99,
                "in_stock": True,
                "sku": "SKU-{{canary_1}}",
            },
        ],
    },
    "devtools": {
        "data": [
            {
                "id": "repo_{{canary_1}}",
                "name": "api-gateway",
                "language": "TypeScript",
                "visibility": "private",
            },
            {
                "id": "repo_{{canary_2}}",
                "name": "ml-pipeline",
                "language": "Python",
                "visibility": "private",
            },
        ],
    },
    "logistics": {
        "data": [
            {
                "id": "shp_{{canary_1}}",
                "tracking": "TRK-{{canary_2}}",
                "status": "in_transit",
                "carrier": "FedEx",
            },
            {
                "id": "shp_{{short_id}}",
                "tracking": "TRK-{{canary_1}}",
                "status": "delivered",
                "carrier": "UPS",
            },
        ],
    },
}

_DETAIL_RESPONSES: dict[str, dict[str, Any]] = {
    "fintech": {
        "id": "txn_{{canary_1}}",
        "amount": 2847.50,
        "currency": "USD",
        "status": "completed",
        "merchant": "CloudServices Inc.",
        "reference": "REF-{{canary_2}}",
        "created_at": "{{timestamp}}",
        "metadata": {"source": "api", "ip": "10.0.1.{{octet}}"},
    },
    "saas": {
        "id": "usr_{{canary_1}}",
        "email": "admin@{{company_domain}}",
        "name": "Alex Chen",
        "role": "admin",
        "status": "active",
        "last_login": "{{timestamp}}",
        "workspace_id": "ws_{{canary_2}}",
    },
    "healthcare": {
        "id": "pat_{{canary_1}}",
        "name": "Riley Thompson",
        "date_of_birth": "1985-07-22",
        "mrn": "MRN-{{canary_2}}",
        "insurance_id": "INS-{{short_id}}",
        "provider": "Dr. Sarah Kim",
        "last_visit": "{{timestamp}}",
    },
    "ecommerce": {
        "id": "prod_{{canary_1}}",
        "name": "Wireless Noise-Canceling Headphones",
        "price": 199.99,
        "currency": "USD",
        "sku": "SKU-{{canary_2}}",
        "in_stock": True,
        "rating": 4.7,
        "reviews_count": 342,
    },
    "devtools": {
        "id": "repo_{{canary_1}}",
        "name": "api-gateway",
        "language": "TypeScript",
        "visibility": "private",
        "default_branch": "main",
        "last_push": "{{timestamp}}",
        "clone_url": "git@git.{{company_domain}}:org/api-gateway.git",
    },
    "logistics": {
        "id": "shp_{{canary_1}}",
        "tracking_number": "TRK-{{canary_2}}",
        "status": "in_transit",
        "carrier": "FedEx",
        "origin": "Memphis, TN",
        "destination": "San Francisco, CA",
        "estimated_delivery": "{{timestamp}}",
    },
}


def _generate_canary(persona: Persona, salt: str) -> str:
    """Generate a canary token tied to the persona.

    Args:
        persona: The active deployment persona.
        salt: A per-request salt for uniqueness.

    Returns:
        A 16-character hex canary token.
    """
    raw = f"{persona.seed}:{persona.company_name}:{salt}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _interpolate(template: Any, variables: dict[str, str]) -> Any:
    """Recursively interpolate {{variable}} placeholders.

    Args:
        template: A dict, list, or scalar with placeholders.
        variables: Mapping of placeholder names to values.

    Returns:
        The template with placeholders replaced.
    """
    if isinstance(template, str):
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", value)
        return result
    if isinstance(template, dict):
        return {k: _interpolate(v, variables) for k, v in template.items()}
    if isinstance(template, list):
        return [_interpolate(item, variables) for item in template]
    return template


def _make_variables(persona: Persona, endpoint: str) -> dict[str, str]:
    """Create template interpolation variables.

    Args:
        persona: The active deployment persona.
        endpoint: The endpoint path for canary derivation.

    Returns:
        A dict of variable names to values.
    """
    salt = uuid.uuid4().hex[:8]
    company_domain = persona.company_name.lower().replace(" ", "") + ".example.com"
    return {
        "canary_1": _generate_canary(persona, f"{endpoint}:1:{salt}"),
        "canary_2": _generate_canary(persona, f"{endpoint}:2:{salt}"),
        "short_id": uuid.uuid4().hex[:8],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "request_id": uuid.uuid4().hex,
        "company_domain": company_domain,
        "octet": str(hash(salt) % 254 + 1),
    }


def _persona_headers(persona: Persona) -> dict[str, str]:
    """Build response headers matching the persona's framework fingerprint.

    Args:
        persona: The deployment persona.

    Returns:
        A dict of HTTP headers.
    """
    headers: dict[str, str] = {
        "Server": persona.server_header,
        "X-Request-Id": uuid.uuid4().hex,
        "X-RateLimit-Limit": "1000",
        "X-RateLimit-Remaining": "997",
        "X-RateLimit-Reset": str(int(time.time()) + 3600),
    }
    for key, value in persona.extra_headers.items():
        if "{{" not in value:
            headers[key] = value
        elif "request_id" in value:
            headers[key] = uuid.uuid4().hex
        elif "response_time_ms" in value:
            headers[key] = f"{persona.response_latency_ms}ms"
    return headers


def _error_response(
    persona: Persona,
    status_code: int,
    message: str,
    detail: str | None = None,
) -> JSONResponse:
    """Generate an error response matching the persona's error_style.

    Args:
        persona: The deployment persona.
        status_code: HTTP status code.
        message: Error message.
        detail: Optional detailed description.

    Returns:
        A JSONResponse with persona-appropriate error formatting.
    """
    if persona.error_style == "rfc7807":
        body: dict[str, Any] = {
            "type": f"https://api.{persona.company_name.lower()}.example.com/errors/{status_code}",
            "title": message,
            "status": status_code,
        }
        if detail:
            body["detail"] = detail
    elif persona.error_style == "xml":
        body = {"error": {"code": status_code, "message": message}}
        if detail:
            body["error"]["detail"] = detail
    else:
        body = {"error": message, "status": status_code}
        if detail:
            body["detail"] = detail

    return JSONResponse(
        content=body,
        status_code=status_code,
        headers=_persona_headers(persona),
    )


def _generate_auth_token(persona: Persona) -> dict[str, Any]:
    """Generate a realistic auth token response.

    Args:
        persona: The deployment persona.

    Returns:
        A dict representing the auth token response.
    """
    token_id = uuid.uuid4().hex
    canary = _generate_canary(persona, f"auth:{token_id}")

    if persona.auth_scheme == AuthScheme.OAUTH2:
        return {
            "access_token": f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.{canary}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": f"rt_{canary}",
            "scope": "read write",
        }
    if persona.auth_scheme == AuthScheme.BEARER:
        return {
            "token": f"sk-sundew-FAKE-{canary}",
            "type": "bearer",
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
        }
    if persona.auth_scheme in (AuthScheme.API_KEY_HEADER, AuthScheme.API_KEY_QUERY):
        return {
            "api_key": f"ak_{canary}",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name": "generated-key",
        }
    # basic
    return {
        "session_id": f"sess_{canary}",
        "authenticated": True,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
    }


def _docs_path(persona: Persona) -> str:
    """Return the Swagger/OpenAPI documentation path for the persona.

    Args:
        persona: The deployment persona.

    Returns:
        The documentation URL path.
    """
    fw = persona.framework_fingerprint.lower()
    if "express" in fw or "nestjs" in fw:
        return "/api-docs"
    if "django" in fw or "flask" in fw or "fastapi" in fw:
        return "/docs"
    if "rails" in fw:
        return "/api/docs"
    if "spring" in fw:
        return "/swagger-ui.html"
    if "laravel" in fw:
        return "/api/documentation"
    return "/docs"


def _build_openapi_spec(persona: Persona) -> dict[str, Any]:
    """Build a complete OpenAPI 3.0 spec for the persona.

    Args:
        persona: The deployment persona.

    Returns:
        An OpenAPI 3.0 specification dict.
    """
    industry = persona.industry
    endpoints = _ENDPOINTS.get(industry, _ENDPOINTS["saas"])
    company_domain = persona.company_name.lower().replace(" ", "") + ".example.com"

    paths: dict[str, Any] = {}
    for ep in endpoints:
        full_path = persona.get_endpoint(ep["path"])
        method = ep["method"].lower()
        if full_path not in paths:
            paths[full_path] = {}
        paths[full_path][method] = {
            "summary": ep["summary"],
            "operationId": (
                ep["path"].strip("/").replace("/", "_").replace("{", "").replace("}", "")
            ),
            "responses": {
                "200": {"description": "Successful response"},
                "401": {"description": "Unauthorized"},
                "404": {"description": "Not found"},
            },
        }

    # Add auth endpoint
    auth_path = persona.get_endpoint("/auth/token")
    paths[auth_path] = {
        "post": {
            "summary": "Authenticate and obtain access token",
            "operationId": "auth_token",
            "responses": {
                "200": {"description": "Authentication successful"},
                "401": {"description": "Invalid credentials"},
            },
        },
    }

    security_schemes: dict[str, Any] = {}
    security: list[dict[str, list[str]]] = []

    if persona.auth_scheme == AuthScheme.BEARER:
        security_schemes["bearerAuth"] = {"type": "http", "scheme": "bearer"}
        security = [{"bearerAuth": []}]
    elif persona.auth_scheme == AuthScheme.API_KEY_HEADER:
        security_schemes["apiKeyAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
        }
        security = [{"apiKeyAuth": []}]
    elif persona.auth_scheme == AuthScheme.OAUTH2:
        security_schemes["oauth2"] = {
            "type": "oauth2",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": auth_path,
                    "scopes": {"read": "Read access", "write": "Write access"},
                },
            },
        }
        security = [{"oauth2": ["read", "write"]}]
    else:
        security_schemes["basicAuth"] = {"type": "http", "scheme": "basic"}
        security = [{"basicAuth": []}]

    return {
        "openapi": "3.0.3",
        "info": {
            "title": f"{persona.company_name} API",
            "version": "1.0.0",
            "description": f"Internal API for {persona.company_name} {persona.data_theme} service.",
            "contact": {"email": f"api-support@{company_domain}"},
        },
        "servers": [{"url": f"https://api.{company_domain}"}],
        "paths": paths,
        "security": security,
        "components": {"securitySchemes": security_schemes},
    }


def create_api_router(persona: Persona) -> APIRouter:
    """Create a FastAPI router with persona-aware REST API trap endpoints.

    Generates realistic API endpoints with proper authentication, pagination,
    error handling, and Swagger documentation.

    Args:
        persona: The deployment persona to shape endpoints and responses.

    Returns:
        A configured FastAPI APIRouter.
    """
    router = APIRouter(tags=["api"])
    prefix = persona.endpoint_prefix.rstrip("/")

    # --- Auth endpoint (accepts any credentials) ---
    @router.post(f"{prefix}/auth/token")
    async def auth_token(request: Request) -> JSONResponse:
        """Accept any credentials and return a realistic auth token."""
        await asyncio.sleep(persona.response_latency_ms / 1000.0)
        return JSONResponse(
            content=_generate_auth_token(persona),
            status_code=200,
            headers=_persona_headers(persona),
        )

    # --- List endpoint (returns paginated fake data) ---
    @router.get(f"{prefix}/{{resource}}")
    async def list_resources(
        request: Request,
        resource: str,
        page: int = Query(default=1, ge=1),
        per_page: int = Query(default=25, ge=1, le=100),
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Return a paginated list of fake resources with canary tokens."""
        await asyncio.sleep(persona.response_latency_ms / 1000.0)
        import copy

        template = _LIST_RESPONSES.get(persona.industry, _LIST_RESPONSES["saas"])
        variables = _make_variables(persona, f"list:{resource}")
        body = _interpolate(copy.deepcopy(template), variables)
        body["meta"] = {
            "page": page,
            "per_page": per_page,
            "total": 47,
            "total_pages": 2,
        }
        return JSONResponse(
            content=body,
            status_code=200,
            headers=_persona_headers(persona),
        )

    # --- Detail endpoint (returns single fake resource) ---
    @router.get(f"{prefix}/{{resource}}/{{resource_id}}")
    async def get_resource(
        request: Request,
        resource: str,
        resource_id: str,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Return a single fake resource with canary tokens."""
        await asyncio.sleep(persona.response_latency_ms / 1000.0)
        import copy

        template = _DETAIL_RESPONSES.get(persona.industry, _DETAIL_RESPONSES["saas"])
        variables = _make_variables(persona, f"detail:{resource}:{resource_id}")
        body = _interpolate(copy.deepcopy(template), variables)
        return JSONResponse(
            content=body,
            status_code=200,
            headers=_persona_headers(persona),
        )

    # --- Nested resource endpoint ---
    @router.get(f"{prefix}/{{resource}}/{{resource_id}}/{{sub_resource}}")
    async def get_sub_resource(
        request: Request,
        resource: str,
        resource_id: str,
        sub_resource: str,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Return a nested resource response with canary tokens."""
        await asyncio.sleep(persona.response_latency_ms / 1000.0)
        import copy

        template = _LIST_RESPONSES.get(persona.industry, _LIST_RESPONSES["saas"])
        variables = _make_variables(persona, f"sub:{resource}:{resource_id}:{sub_resource}")
        body = _interpolate(copy.deepcopy(template), variables)
        return JSONResponse(
            content=body,
            status_code=200,
            headers=_persona_headers(persona),
        )

    # --- POST endpoint (catches action attempts) ---
    @router.post(f"{prefix}/{{resource}}")
    async def create_resource(
        request: Request,
        resource: str,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Accept any POST and return a fake creation response."""
        await asyncio.sleep(persona.response_latency_ms / 1000.0)
        canary = _generate_canary(persona, f"create:{resource}:{uuid.uuid4().hex[:8]}")
        body = {
            "id": f"{resource[:3]}_{canary}",
            "status": "created",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return JSONResponse(
            content=body,
            status_code=201,
            headers=_persona_headers(persona),
        )

    # --- Swagger / OpenAPI docs ---
    docs_url = _docs_path(persona)

    @router.get(docs_url)
    async def swagger_docs() -> JSONResponse:
        """Serve the OpenAPI specification at the persona-appropriate path."""
        return JSONResponse(
            content=_build_openapi_spec(persona),
            headers=_persona_headers(persona),
        )

    return router
