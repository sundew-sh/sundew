"""Persona engine: LLM-powered response template generation and caching.

The engine generates response templates at deployment time and caches them.
At runtime, templates are served with variable interpolation — zero LLM latency.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from sundew.models import Persona, PersonaPack, ResponseTemplate

if TYPE_CHECKING:
    from sundew.config import LLMConfig

logger = logging.getLogger(__name__)

TEMPLATE_CACHE_FILE = "template_cache.json"

SYSTEM_PROMPT = """You are a response template generator for a realistic API honeypot.
Given a company persona, generate realistic API response templates that look like
a real production API. Templates use {{variable}} placeholders for dynamic values.

Available placeholders:
- {{timestamp}} — current ISO 8601 timestamp
- {{request_id}} — unique request ID
- {{random_id}} — random UUID
- {{random_int}} — random integer
- {{source_ip}} — requester's IP

Respond with valid JSON only. No markdown, no explanation."""


class PersonaEngine:
    """Manages response template generation, caching, and retrieval.

    The engine supports multiple LLM backends for generating realistic
    response templates shaped by the deployment persona. Templates are
    cached in a JSON file and SQLite database for fast runtime access.
    """

    def __init__(
        self,
        persona: Persona,
        llm_config: LLMConfig,
        data_dir: str | Path = "./data",
    ) -> None:
        """Initialize the persona engine.

        Args:
            persona: The deployment persona that shapes all responses.
            llm_config: Configuration for the LLM provider.
            data_dir: Directory for storing cache files and database.
        """
        self.persona = persona
        self.llm_config = llm_config
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._templates: dict[str, ResponseTemplate] = {}
        self._db_path = self.data_dir / "templates.db"
        self._cache_path = self.data_dir / TEMPLATE_CACHE_FILE
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database for template caching."""
        conn = sqlite3.connect(str(self._db_path))
        conn.execute(
            """CREATE TABLE IF NOT EXISTS templates (
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                headers TEXT NOT NULL,
                body_template TEXT NOT NULL,
                description TEXT NOT NULL,
                PRIMARY KEY (endpoint, method)
            )"""
        )
        conn.commit()
        conn.close()

    async def initialize(self, force_regenerate: bool = False) -> None:
        """Generate or load response templates for the current persona.

        Attempts to load from cache first. If no cache exists or
        force_regenerate is True, generates new templates using the
        configured LLM provider or falls back to persona packs.

        Args:
            force_regenerate: If True, regenerate even if cache exists.
        """
        if not force_regenerate and self._load_from_cache():
            logger.info(
                "Loaded %d templates from cache for persona '%s'",
                len(self._templates),
                self.persona.company_name,
            )
            return

        provider = self.llm_config.provider.lower()

        if provider == "none":
            logger.info("No LLM provider configured, using persona packs")
            await self._load_from_packs()
        elif provider == "ollama":
            await self._generate_with_ollama()
        elif provider == "anthropic":
            await self._generate_with_anthropic()
        elif provider == "openai":
            await self._generate_with_openai()
        else:
            logger.warning("Unknown LLM provider '%s', falling back to packs", provider)
            await self._load_from_packs()

        self._save_to_cache()
        logger.info(
            "Generated %d templates for persona '%s'",
            len(self._templates),
            self.persona.company_name,
        )

    def get_template(self, endpoint: str, method: str = "GET") -> ResponseTemplate | None:
        """Retrieve a cached response template for an endpoint.

        Args:
            endpoint: The endpoint path pattern.
            method: The HTTP method.

        Returns:
            The matching ResponseTemplate, or None if not found.
        """
        key = f"{method.upper()}:{endpoint}"
        return self._templates.get(key)

    def get_all_templates(self) -> list[ResponseTemplate]:
        """Return all cached response templates.

        Returns:
            List of all ResponseTemplate instances.
        """
        return list(self._templates.values())

    def register_template(self, template: ResponseTemplate) -> None:
        """Register a response template in the cache.

        Args:
            template: The ResponseTemplate to register.
        """
        key = f"{template.method.upper()}:{template.endpoint}"
        self._templates[key] = template

    def _load_from_cache(self) -> bool:
        """Load templates from the JSON cache file.

        Returns:
            True if cache was loaded successfully, False otherwise.
        """
        if not self._cache_path.exists():
            return False

        try:
            with open(self._cache_path) as f:
                raw: list[dict[str, Any]] = json.load(f)

            for item in raw:
                template = ResponseTemplate.model_validate(item)
                self.register_template(template)
            return bool(self._templates)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Failed to load template cache: %s", exc)
            return False

    def _save_to_cache(self) -> None:
        """Save all templates to the JSON cache file and SQLite database."""
        templates_data = [t.model_dump() for t in self._templates.values()]

        with open(self._cache_path, "w") as f:
            json.dump(templates_data, f, indent=2)

        conn = sqlite3.connect(str(self._db_path))
        conn.execute("DELETE FROM templates")
        for t in self._templates.values():
            conn.execute(
                """INSERT OR REPLACE INTO templates
                   (endpoint, method, status_code, content_type,
                    headers, body_template, description)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    t.endpoint,
                    t.method,
                    t.status_code,
                    t.content_type,
                    json.dumps(t.headers),
                    t.body_template,
                    t.description,
                ),
            )
        conn.commit()
        conn.close()

    async def _load_from_packs(self) -> None:
        """Load templates from pre-built persona packs matching the industry."""
        pack = _load_persona_pack(self.persona.industry)
        if pack is None:
            logger.warning(
                "No persona pack found for industry '%s', using default",
                self.persona.industry,
            )
            pack = _load_persona_pack("saas")

        if pack is None:
            logger.error("No persona packs available, generating minimal defaults")
            self._generate_minimal_defaults()
            return

        for template in pack.templates:
            adjusted = _adjust_template_to_persona(template, self.persona)
            self.register_template(adjusted)

    def _generate_minimal_defaults(self) -> None:
        """Generate a minimal set of default templates without LLM or packs."""
        prefix = self.persona.endpoint_prefix.rstrip("/")
        theme = self.persona.data_theme

        defaults = [
            ResponseTemplate(
                endpoint=f"{prefix}/{theme}",
                method="GET",
                status_code=200,
                body_template=json.dumps(
                    {
                        "data": [],
                        "meta": {"total": 0, "page": 1, "per_page": 20},
                        "request_id": "{{request_id}}",
                    }
                ),
                description=f"List {theme}",
            ),
            ResponseTemplate(
                endpoint=f"{prefix}/{theme}/{{random_id}}",
                method="GET",
                status_code=200,
                body_template=json.dumps(
                    {
                        "id": "{{random_id}}",
                        "created_at": "{{timestamp}}",
                        "updated_at": "{{timestamp}}",
                    }
                ),
                description=f"Get single {theme} item",
            ),
            ResponseTemplate(
                endpoint=f"{prefix}/{theme}",
                method="POST",
                status_code=201,
                body_template=json.dumps(
                    {
                        "id": "{{random_id}}",
                        "created_at": "{{timestamp}}",
                        "status": "created",
                    }
                ),
                description=f"Create {theme} item",
            ),
            ResponseTemplate(
                endpoint=f"{prefix}/health",
                method="GET",
                status_code=200,
                body_template=json.dumps(
                    {
                        "status": "healthy",
                        "timestamp": "{{timestamp}}",
                        "version": "1.0.0",
                    }
                ),
                description="Health check endpoint",
            ),
        ]

        for template in defaults:
            self.register_template(template)

    async def _generate_with_ollama(self) -> None:
        """Generate response templates using a local Ollama instance."""
        base_url = self.llm_config.base_url or "http://localhost:11434"
        prompt = _build_generation_prompt(self.persona)

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{base_url}/api/generate",
                    json={
                        "model": self.llm_config.model,
                        "prompt": prompt,
                        "system": SYSTEM_PROMPT,
                        "stream": False,
                        "options": {
                            "temperature": self.llm_config.temperature,
                            "num_predict": self.llm_config.max_tokens,
                        },
                    },
                )
                response.raise_for_status()
                result = response.json()
                self._parse_llm_response(result.get("response", ""))

        except (httpx.HTTPError, KeyError) as exc:
            logger.warning("Ollama generation failed: %s, falling back to packs", exc)
            await self._load_from_packs()

    async def _generate_with_anthropic(self) -> None:
        """Generate response templates using the Anthropic API."""
        try:
            import anthropic
        except ImportError:
            logger.warning("anthropic package not installed, falling back to packs")
            await self._load_from_packs()
            return

        api_key = self.llm_config.api_key
        prompt = _build_generation_prompt(self.persona)

        try:
            client = anthropic.Anthropic(api_key=api_key)
            message = client.messages.create(
                model=self.llm_config.model,
                max_tokens=self.llm_config.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            text = message.content[0].text
            self._parse_llm_response(text)

        except Exception as exc:
            logger.warning("Anthropic generation failed: %s, falling back to packs", exc)
            await self._load_from_packs()

    async def _generate_with_openai(self) -> None:
        """Generate response templates using the OpenAI API."""
        try:
            import openai
        except ImportError:
            logger.warning("openai package not installed, falling back to packs")
            await self._load_from_packs()
            return

        api_key = self.llm_config.api_key
        prompt = _build_generation_prompt(self.persona)

        try:
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=self.llm_config.model,
                max_tokens=self.llm_config.max_tokens,
                temperature=self.llm_config.temperature,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
            text = response.choices[0].message.content or ""
            self._parse_llm_response(text)

        except Exception as exc:
            logger.warning("OpenAI generation failed: %s, falling back to packs", exc)
            await self._load_from_packs()

    def _parse_llm_response(self, text: str) -> None:
        """Parse LLM output into response templates.

        Args:
            text: Raw LLM response text expected to be a JSON array.
        """
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1])

        try:
            raw: list[dict[str, Any]] = json.loads(text)
            for item in raw:
                template = ResponseTemplate.model_validate(item)
                self.register_template(template)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Failed to parse LLM response: %s", exc)
            self._generate_minimal_defaults()


def _build_generation_prompt(persona: Persona) -> str:
    """Build the prompt for LLM-based template generation.

    Args:
        persona: The deployment persona to generate templates for.

    Returns:
        A formatted prompt string for the LLM.
    """
    return f"""Generate realistic API response templates for this company:

Company: {persona.company_name}
Industry: {persona.industry}
API Style: {persona.api_style}
Data Theme: {persona.data_theme}
Endpoint Prefix: {persona.endpoint_prefix}
Error Style: {persona.error_style}
Auth Scheme: {persona.auth_scheme.value}

Generate a JSON array of response templates. Each template should have:
- endpoint: path with the given prefix
- method: HTTP method (GET, POST, PUT, DELETE)
- status_code: appropriate HTTP status
- content_type: "application/json"
- headers: dict of extra headers
- body_template: realistic JSON response body using {{{{timestamp}}}},
  {{{{request_id}}}}, {{{{random_id}}}}, {{{{random_int}}}} placeholders
- description: what this endpoint does

Generate at least 8 endpoints covering:
1. List collection (GET {persona.endpoint_prefix}/{persona.data_theme})
2. Get single item (GET {persona.endpoint_prefix}/{persona.data_theme}/{{{{random_id}}}})
3. Create item (POST)
4. Update item (PUT)
5. Delete item (DELETE)
6. Health check
7. API documentation / OpenAPI spec endpoint
8. Auth token endpoint
9. Error responses (401, 403, 404, 429)
"""


def _load_persona_pack(industry: str) -> PersonaPack | None:
    """Load a pre-built persona pack for the given industry.

    Args:
        industry: The industry name matching a pack filename.

    Returns:
        A PersonaPack instance, or None if not found.
    """
    pack_dir = Path(__file__).parent / "packs"
    pack_file = pack_dir / f"{industry}.json"

    if not pack_file.exists():
        return None

    try:
        with open(pack_file) as f:
            raw: dict[str, Any] = json.load(f)
        return PersonaPack.model_validate(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to load persona pack '%s': %s", industry, exc)
        return None


def _adjust_template_to_persona(template: ResponseTemplate, persona: Persona) -> ResponseTemplate:
    """Adjust a pack template to match the current persona's configuration.

    Replaces generic endpoint prefixes and data themes with persona-specific
    values.

    Args:
        template: The original template from a persona pack.
        persona: The active persona to adjust for.

    Returns:
        A new ResponseTemplate adjusted for the persona.
    """
    endpoint = template.endpoint
    prefix = persona.endpoint_prefix.rstrip("/")

    for generic_prefix in ["/api/v1", "/api/v2", "/v1", "/api"]:
        if endpoint.startswith(generic_prefix):
            endpoint = prefix + endpoint[len(generic_prefix) :]
            break

    body = template.body_template
    body = body.replace("{{company_name}}", persona.company_name)

    return ResponseTemplate(
        endpoint=endpoint,
        method=template.method,
        status_code=template.status_code,
        content_type=template.content_type,
        headers={**template.headers, **persona.extra_headers},
        body_template=body,
        description=template.description,
    )
