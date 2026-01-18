"""Core data models for Sundew honeypot."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class AttackClassification(enum.StrEnum):
    """Classification of an observed request or session."""

    UNKNOWN = "unknown"
    HUMAN = "human"
    AUTOMATED = "automated"
    AI_ASSISTED = "ai_assisted"
    AI_AGENT = "ai_agent"


class AuthScheme(enum.StrEnum):
    """Supported authentication scheme styles for persona generation."""

    BEARER = "bearer"
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    BASIC = "basic"
    OAUTH2 = "oauth2"


class Persona(BaseModel):
    """A unique deployment identity that shapes every aspect of the honeypot.

    The persona determines endpoint paths, response bodies, error messages,
    HTTP headers, timing characteristics, fake data themes, API documentation,
    and MCP tool names. Every deployment gets a unique persona to prevent
    fingerprinting across instances.
    """

    seed: int = Field(description="Deterministic seed for reproducible generation")
    company_name: str = Field(description="Fake company name used in responses and docs")
    industry: str = Field(description="Industry vertical: fintech, saas, healthcare, etc.")
    api_style: str = Field(description="API convention: rest, graphql, jsonrpc")
    framework_fingerprint: str = Field(
        description="Simulated framework identity: express, django, rails, spring"
    )
    error_style: str = Field(description="Error response format: rfc7807, simple_json, html, xml")
    auth_scheme: AuthScheme = Field(description="Authentication scheme to simulate")
    data_theme: str = Field(
        description="Domain-specific data theme: payments, users, patients, tickets"
    )
    response_latency_ms: int = Field(
        default=50,
        ge=10,
        le=2000,
        description="Simulated base response latency in milliseconds",
    )
    server_header: str = Field(description="Value for the Server HTTP header, e.g. 'nginx/1.24.0'")
    endpoint_prefix: str = Field(
        default="/api/v1",
        description="URL prefix for all API trap endpoints",
    )
    extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional HTTP headers to include in responses",
    )
    mcp_server_name: str = Field(
        default="data-api",
        description="Name for the exposed MCP server trap",
    )
    mcp_tool_prefix: str = Field(
        default="",
        description="Prefix for MCP tool names to match persona theme",
    )

    def get_endpoint(self, path: str) -> str:
        """Return the full endpoint path with the persona's prefix.

        Args:
            path: The relative path segment (e.g., '/users').

        Returns:
            The full endpoint path including the persona prefix.
        """
        prefix = self.endpoint_prefix.rstrip("/")
        path = path if path.startswith("/") else f"/{path}"
        return f"{prefix}{path}"


class FingerprintScores(BaseModel):
    """Scores from various fingerprinting heuristics applied to a request.

    Each score ranges from 0.0 (certainly human) to 1.0 (certainly AI agent).
    """

    timing_regularity: float = Field(
        default=0.0, ge=0.0, le=1.0, description="How regular the request timing is"
    )
    header_anomaly: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Unusual or missing standard headers"
    )
    path_traversal: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Pattern of systematic endpoint exploration",
    )
    tool_calling_pattern: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Matches known AI tool-calling patterns"
    )
    credential_stuffing: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Attempts multiple auth credentials"
    )
    user_agent_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="User-Agent analysis score"
    )
    composite: float = Field(default=0.0, ge=0.0, le=1.0, description="Weighted composite score")


class RequestEvent(BaseModel):
    """A single captured HTTP request with fingerprinting analysis.

    Every request that hits the honeypot is recorded as a RequestEvent,
    including full headers, body, and the results of fingerprint analysis.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    session_id: str | None = Field(
        default=None, description="ID of the session this request belongs to"
    )
    source_ip: str = Field(description="Source IP address")
    source_port: int | None = Field(default=None, description="Source port")
    method: str = Field(description="HTTP method: GET, POST, etc.")
    path: str = Field(description="Request path")
    query_params: dict[str, str] = Field(
        default_factory=dict, description="Parsed query parameters"
    )
    headers: dict[str, str] = Field(default_factory=dict, description="Request headers")
    body: str | None = Field(default=None, description="Request body as string")
    body_json: dict[str, Any] | None = Field(
        default=None, description="Parsed JSON body if applicable"
    )
    content_type: str | None = Field(default=None, description="Content-Type header value")
    user_agent: str | None = Field(default=None, description="User-Agent header value")
    fingerprint_scores: FingerprintScores = Field(default_factory=FingerprintScores)
    classification: AttackClassification = Field(default=AttackClassification.UNKNOWN)
    trap_type: str | None = Field(
        default=None, description="Which trap caught this request: rest_api, mcp, discovery"
    )
    matched_endpoint: str | None = Field(
        default=None, description="The trap endpoint pattern that matched"
    )
    response_status: int | None = Field(default=None, description="HTTP status code returned")
    notes: str | None = Field(default=None, description="Analyst or automated notes")


class Session(BaseModel):
    """A group of related requests from the same source.

    Sessions group requests by source IP and temporal proximity,
    allowing analysis of attack patterns over time.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    source_ip: str = Field(description="Source IP address for this session")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request_count: int = Field(default=0, description="Total requests in this session")
    request_ids: list[str] = Field(
        default_factory=list, description="Ordered list of RequestEvent IDs"
    )
    classification: AttackClassification = Field(default=AttackClassification.UNKNOWN)
    fingerprint_scores: FingerprintScores = Field(
        default_factory=FingerprintScores,
        description="Aggregate fingerprint scores for the session",
    )
    endpoints_hit: list[str] = Field(
        default_factory=list, description="Unique endpoints accessed in order"
    )
    trap_types_triggered: list[str] = Field(
        default_factory=list, description="Trap types triggered during session"
    )
    tags: list[str] = Field(default_factory=list, description="Analyst tags")
    notes: str | None = Field(default=None, description="Analyst or automated notes")


class ResponseTemplate(BaseModel):
    """A pre-generated response template for a trap endpoint.

    Templates are generated at deployment time (optionally by LLM) and
    cached. At runtime, variable interpolation replaces placeholders
    like {{timestamp}}, {{request_id}}, and {{random_id}}.
    """

    endpoint: str = Field(description="The endpoint pattern this template serves")
    method: str = Field(default="GET", description="HTTP method")
    status_code: int = Field(default=200, description="HTTP status code")
    content_type: str = Field(default="application/json")
    headers: dict[str, str] = Field(default_factory=dict, description="Additional response headers")
    body_template: str = Field(description="Response body with {{variable}} placeholders")
    description: str = Field(default="", description="Human-readable description of this endpoint")


class PersonaPack(BaseModel):
    """A pre-built collection of response templates for a specific industry theme.

    Persona packs provide a complete set of realistic API responses without
    requiring LLM generation, serving as the fallback when no LLM provider
    is configured.
    """

    name: str = Field(description="Pack name matching industry theme")
    industry: str = Field(description="Industry this pack targets")
    description: str = Field(default="")
    persona_defaults: dict[str, Any] = Field(
        default_factory=dict,
        description="Default persona field values for this industry",
    )
    templates: list[ResponseTemplate] = Field(
        default_factory=list, description="Pre-built response templates"
    )
