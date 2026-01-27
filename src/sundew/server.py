"""FastAPI server for Sundew honeypot.

Serves persona-shaped trap endpoints with middleware hooks for
request fingerprinting and session tracking.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager, suppress
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from sundew.config import SundewConfig, load_config
from sundew.interpolation import interpolate
from sundew.models import Persona, RequestEvent
from sundew.persona.engine import PersonaEngine
from sundew.persona.generator import generate_persona, load_persona_from_yaml
from sundew.storage import StorageBackend
from sundew.traps import create_api_router, create_discovery_router, create_mcp_router

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

logger = logging.getLogger(__name__)


class SundewServer:
    """Core server that manages the honeypot lifecycle.

    Orchestrates persona loading, template generation, storage
    initialization, and FastAPI application setup.
    """

    def __init__(self, config: SundewConfig | None = None) -> None:
        """Initialize the Sundew server.

        Args:
            config: Optional configuration. If None, loads from sundew.yaml.
        """
        self.config = config or load_config()
        self.persona: Persona | None = None
        self.engine: PersonaEngine | None = None
        self.storage: StorageBackend | None = None
        self.app = self._create_app()

    def _create_app(self) -> FastAPI:
        """Create and configure the FastAPI application.

        Returns:
            A configured FastAPI instance with middleware and routes.
        """

        @asynccontextmanager
        async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
            await self._startup()
            yield
            self._shutdown()

        app = FastAPI(
            title="API Service",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
            lifespan=lifespan,
        )

        app.middleware("http")(self._fingerprint_middleware)

        @app.get("/health")
        async def health_check() -> dict[str, str]:
            return {"status": "ok"}

        return app

    def _mount_trap_routers(self) -> None:
        """Mount trap routers after persona is loaded.

        Adds discovery, API, and MCP routers, then the catch-all fallback.
        The catch-all must be registered last so specific trap routes match first.
        """
        if self.persona is None:
            return

        if self.config.traps.ai_discovery:
            self.app.include_router(create_discovery_router(self.persona))

        if self.config.traps.rest_api:
            self.app.include_router(create_api_router(self.persona))

        if self.config.traps.mcp_server:
            self.app.include_router(create_mcp_router(self.persona))

        @self.app.api_route(
            "/{path:path}",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        )
        async def catch_all(request: Request, path: str) -> Response:
            return await self._handle_request(request, path)

    async def _startup(self) -> None:
        """Initialize persona, engine, and storage on server start."""
        self.persona = _resolve_persona(self.config)
        logger.info(
            "Loaded persona: %s (%s / %s)",
            self.persona.company_name,
            self.persona.industry,
            self.persona.data_theme,
        )

        self.engine = PersonaEngine(
            persona=self.persona,
            llm_config=self.config.llm,
            data_dir=self.config.storage.database.rsplit("/", 1)[0]
            if "/" in self.config.storage.database
            else "./data",
        )
        await self.engine.initialize()

        self.storage = StorageBackend(
            db_path=self.config.storage.database,
            log_path=self.config.storage.log_file,
        )

        self._mount_trap_routers()

        logger.info(
            "Sundew honeypot started on %s:%d with %d templates",
            self.config.server.host,
            self.config.server.port,
            len(self.engine.get_all_templates()),
        )

    def _shutdown(self) -> None:
        """Clean up resources on server shutdown."""
        logger.info("Sundew honeypot shutting down")

    async def _fingerprint_middleware(self, request: Request, call_next: object) -> Response:
        """Middleware that records request metadata for fingerprinting.

        Args:
            request: The incoming FastAPI Request.
            call_next: The next middleware/handler in the chain.

        Returns:
            The response from the handler.
        """
        start_time = time.monotonic()
        response: Response = await call_next(request)  # type: ignore[call-arg]
        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        if self.persona:
            response.headers["Server"] = self.persona.server_header
            for key, value in self.persona.extra_headers.items():
                source_ip = request.client.host if request.client else "unknown"
                response.headers[key] = interpolate(value, {"source_ip": source_ip})
            response.headers["X-Response-Time"] = f"{elapsed_ms}ms"

        return response

    async def _handle_request(self, request: Request, path: str) -> Response:
        """Handle an incoming request by matching to templates and recording.

        Args:
            request: The incoming FastAPI Request.
            path: The captured URL path.

        Returns:
            A persona-shaped Response.
        """
        full_path = f"/{path}"
        source_ip = request.client.host if request.client else "0.0.0.0"

        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else None
        body_json = None
        if body_str and request.headers.get("content-type", "").startswith("application/json"):
            with suppress(json.JSONDecodeError):
                body_json = json.loads(body_str)

        event = RequestEvent(
            source_ip=source_ip,
            source_port=request.client.port if request.client else None,
            method=request.method,
            path=full_path,
            query_params=dict(request.query_params),
            headers=dict(request.headers),
            body=body_str,
            body_json=body_json,
            content_type=request.headers.get("content-type"),
            user_agent=request.headers.get("user-agent"),
        )

        if self.storage:
            session = self.storage.get_or_create_session(source_ip)
            event.session_id = session.id
            self.storage.save_event(event)
            self.storage.update_session_with_event(session, event)

        response = self._match_template(full_path, request.method, source_ip)

        if self.persona and self.persona.response_latency_ms > 0:
            jitter = self.persona.response_latency_ms * 0.2
            delay_ms = self.persona.response_latency_ms + (time.monotonic() % jitter)
            await asyncio.sleep(delay_ms / 1000.0)

        return response

    def _match_template(self, path: str, method: str, source_ip: str) -> Response:
        """Find and render a matching response template.

        Args:
            path: The request path.
            method: The HTTP method.
            source_ip: The requester's IP address.

        Returns:
            A rendered Response, or a 404 if no template matches.
        """
        if self.engine is None:
            return JSONResponse({"error": "not_initialized"}, status_code=503)

        template = self.engine.get_template(path, method)

        if template is None:
            templates = self.engine.get_all_templates()
            for t in templates:
                if _path_matches(path, t.endpoint) and t.method.upper() == method.upper():
                    template = t
                    break

        if template is None:
            return self._error_response(404, "not_found", f"No route matches {method} {path}")

        context = {"source_ip": source_ip}
        body = interpolate(template.body_template, context)
        headers = {k: interpolate(v, context) for k, v in template.headers.items()}

        return Response(
            content=body,
            status_code=template.status_code,
            media_type=template.content_type,
            headers=headers,
        )

    def _error_response(self, status_code: int, error_type: str, message: str) -> Response:
        """Generate an error response shaped by the persona's error style.

        Args:
            status_code: HTTP status code.
            error_type: Machine-readable error type string.
            message: Human-readable error message.

        Returns:
            A persona-styled error Response.
        """
        if self.persona is None:
            body = json.dumps({"error": error_type, "message": message})
            return Response(content=body, status_code=status_code, media_type="application/json")

        style = self.persona.error_style

        if style == "rfc7807":
            body = json.dumps(
                {
                    "type": f"about:blank#{error_type}",
                    "title": error_type.replace("_", " ").title(),
                    "status": status_code,
                    "detail": message,
                    "instance": f"/errors/{interpolate('{{request_id}}')}",
                }
            )
        elif style == "xml":
            body = (
                f'<?xml version="1.0"?>\n'
                f"<error><code>{error_type}</code>"
                f"<message>{message}</message>"
                f"<status>{status_code}</status></error>"
            )
            return Response(content=body, status_code=status_code, media_type="application/xml")
        elif style == "html":
            body = f"<html><body><h1>{status_code}</h1><p>{message}</p></body></html>"
            return Response(content=body, status_code=status_code, media_type="text/html")
        else:
            body = json.dumps({"error": error_type, "message": message})

        return Response(content=body, status_code=status_code, media_type="application/json")


def _path_matches(request_path: str, template_path: str) -> bool:
    """Check if a request path matches a template path pattern.

    Template paths may contain {{variable}} segments that match
    any single path component.

    Args:
        request_path: The actual request path.
        template_path: The template path pattern with {{variables}}.

    Returns:
        True if the paths match.
    """
    req_parts = request_path.strip("/").split("/")
    tpl_parts = template_path.strip("/").split("/")

    if len(req_parts) != len(tpl_parts):
        return False

    for req_part, tpl_part in zip(req_parts, tpl_parts, strict=False):
        if tpl_part.startswith("{{") and tpl_part.endswith("}}"):
            continue
        if req_part != tpl_part:
            return False

    return True


def _resolve_persona(config: SundewConfig) -> Persona:
    """Resolve the deployment persona from configuration.

    Args:
        config: The Sundew configuration.

    Returns:
        A Persona instance, either loaded from file or generated.
    """
    if config.persona == "auto":
        return generate_persona()

    try:
        return load_persona_from_yaml(config.persona)
    except FileNotFoundError:
        logger.warning(
            "Persona file '%s' not found, generating random persona",
            config.persona,
        )
        return generate_persona()


def create_app(config_path: str | None = None) -> FastAPI:
    """Create a Sundew FastAPI application.

    This is the main entry point for ASGI servers like uvicorn.

    Args:
        config_path: Optional path to the sundew.yaml config file.

    Returns:
        A configured FastAPI application.
    """
    config = load_config(config_path)
    server = SundewServer(config)
    return server.app
