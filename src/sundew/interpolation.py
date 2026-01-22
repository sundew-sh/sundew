"""Runtime variable interpolation for response templates.

Replaces {{variable}} placeholders with dynamic values at request time,
ensuring zero LLM latency during operation.
"""

from __future__ import annotations

import random
import re
import uuid
from datetime import UTC, datetime

VARIABLE_PATTERN = re.compile(r"\{\{(\w+)\}\}")


def interpolate(template: str, context: dict[str, str] | None = None) -> str:
    """Replace {{variable}} placeholders in a template string.

    Built-in variables:
        - {{timestamp}}: Current ISO 8601 timestamp
        - {{request_id}}: New UUID for this request
        - {{random_id}}: Random UUID
        - {{random_int}}: Random integer (1000-999999)
        - {{source_ip}}: Requester IP (from context)
        - {{response_time_ms}}: Simulated response time

    Additional variables can be supplied via the context dict.

    Args:
        template: The template string with {{variable}} placeholders.
        context: Optional dict of additional variable values.

    Returns:
        The interpolated string with all placeholders replaced.
    """
    merged: dict[str, str] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "request_id": uuid.uuid4().hex,
        "random_id": uuid.uuid4().hex,
        "random_int": str(random.randint(1000, 999999)),
        "response_time_ms": str(random.randint(1, 50)),
    }

    if context:
        merged.update(context)

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return merged.get(key, match.group(0))

    return VARIABLE_PATTERN.sub(_replace, template)
