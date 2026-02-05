"""Tests for runtime variable interpolation."""

from sundew.interpolation import interpolate


def test_timestamp_placeholder() -> None:
    """{{timestamp}} should be replaced with an ISO timestamp."""
    result = interpolate("time: {{timestamp}}")
    assert "{{timestamp}}" not in result
    assert "time: " in result


def test_request_id_placeholder() -> None:
    """{{request_id}} should be replaced with a hex string."""
    result = interpolate("id: {{request_id}}")
    assert "{{request_id}}" not in result
    parts = result.split("id: ")
    assert len(parts[1]) == 32


def test_random_id_placeholder() -> None:
    """{{random_id}} should produce a different value each call."""
    r1 = interpolate("{{random_id}}")
    r2 = interpolate("{{random_id}}")
    assert r1 != r2 or len(r1) == 32


def test_custom_context() -> None:
    """Custom context values should override built-in placeholders."""
    result = interpolate("ip: {{source_ip}}", {"source_ip": "192.168.1.1"})
    assert result == "ip: 192.168.1.1"


def test_unknown_placeholder_preserved() -> None:
    """Unknown placeholders should be left as-is."""
    result = interpolate("{{unknown_var}}")
    assert result == "{{unknown_var}}"


def test_multiple_placeholders() -> None:
    """Multiple placeholders in one template should all be replaced."""
    template = '{"id": "{{request_id}}", "ts": "{{timestamp}}", "n": {{random_int}}}'
    result = interpolate(template)
    assert "{{request_id}}" not in result
    assert "{{timestamp}}" not in result
    assert "{{random_int}}" not in result


def test_no_placeholders() -> None:
    """Template without placeholders should pass through unchanged."""
    template = '{"status": "ok"}'
    assert interpolate(template) == template
