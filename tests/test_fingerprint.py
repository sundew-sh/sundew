"""Tests for the fingerprinting engine and classification system."""

from __future__ import annotations

import pytest

from sundew.classify import classify, classify_with_details
from sundew.fingerprint import (
    compute_composite_score,
    fingerprint_request,
    score_header_anomalies,
    score_mcp_behavior,
    score_path_enumeration,
    score_prompt_leakage,
    score_timing_regularity,
)
from sundew.models import AttackClassification

# ---------------------------------------------------------------------------
# Signal 1: Timing regularity
# ---------------------------------------------------------------------------


class TestTimingRegularity:
    """Tests for the timing regularity signal."""

    def test_empty_intervals(self) -> None:
        """No intervals should return 0.0."""
        assert score_timing_regularity([]) == 0.0

    def test_single_interval(self) -> None:
        """A single interval is insufficient for scoring."""
        assert score_timing_regularity([100.0]) == 0.0

    def test_metronomic_timing(self) -> None:
        """Perfectly regular intervals should score very high."""
        intervals = [100.0, 100.0, 100.0, 100.0, 100.0]
        score = score_timing_regularity(intervals)
        assert score >= 0.8

    def test_near_regular_timing(self) -> None:
        """Nearly regular intervals (low variance) should score high."""
        intervals = [100.0, 102.0, 99.0, 101.0, 100.5]
        score = score_timing_regularity(intervals)
        assert score >= 0.5

    def test_human_like_timing(self) -> None:
        """High-variance intervals (human-like) should score low."""
        intervals = [200.0, 1500.0, 400.0, 3200.0, 800.0]
        score = score_timing_regularity(intervals)
        assert score <= 0.3

    def test_very_irregular_timing(self) -> None:
        """Extremely variable intervals should score near zero."""
        intervals = [50.0, 5000.0, 200.0, 10000.0, 100.0]
        score = score_timing_regularity(intervals)
        assert score <= 0.2


# ---------------------------------------------------------------------------
# Signal 2: Path enumeration
# ---------------------------------------------------------------------------


class TestPathEnumeration:
    """Tests for the path enumeration signal."""

    def test_few_paths(self) -> None:
        """Too few paths should return 0.0."""
        assert score_path_enumeration(["/", "/about"]) == 0.0

    def test_systematic_probing(self) -> None:
        """Probing well-known paths should score high."""
        paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/openapi.json",
            "/.well-known/ai-plugin.json",
            "/api/v1/users",
        ]
        score = score_path_enumeration(paths)
        assert score >= 0.4

    def test_random_browsing(self) -> None:
        """Random page visits without systematic patterns should score low."""
        paths = [
            "/products/headphones",
            "/products/headphones",
            "/cart",
            "/products/cables",
            "/checkout",
        ]
        score = score_path_enumeration(paths)
        assert score <= 0.3

    def test_discovery_then_exploit(self) -> None:
        """Hitting multiple discovery paths should increase the score."""
        paths = [
            "/robots.txt",
            "/.well-known/mcp.json",
            "/api/v1/secrets",
            "/api/v1/users",
        ]
        score = score_path_enumeration(paths)
        assert score >= 0.3

    def test_high_unique_ratio(self) -> None:
        """Visiting many unique paths (no revisits) suggests exploration."""
        paths = [f"/path/{i}" for i in range(20)]
        score = score_path_enumeration(paths)
        assert score >= 0.1


# ---------------------------------------------------------------------------
# Signal 3: Header anomalies
# ---------------------------------------------------------------------------


class TestHeaderAnomalies:
    """Tests for the header anomaly signal."""

    def test_normal_browser_headers(self) -> None:
        """Standard browser headers should score low."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://example.com/",
        }
        score = score_header_anomalies(headers)
        assert score <= 0.2

    def test_python_requests_ua(self) -> None:
        """python-requests User-Agent should flag as bot-like."""
        headers = {
            "User-Agent": "python-requests/2.31.0",
            "Accept": "*/*",
        }
        score = score_header_anomalies(headers)
        assert score >= 0.4

    def test_missing_user_agent(self) -> None:
        """Missing User-Agent should score significantly."""
        headers = {"Accept": "application/json"}
        score = score_header_anomalies(headers)
        assert score >= 0.3

    def test_curl_user_agent(self) -> None:
        """curl User-Agent should be flagged."""
        headers = {"User-Agent": "curl/8.4.0"}
        score = score_header_anomalies(headers)
        assert score >= 0.3

    def test_mcp_specific_headers(self) -> None:
        """MCP-specific headers should score very high."""
        headers = {
            "User-Agent": "mcp-client/1.0",
            "X-MCP-Version": "2024-11-05",
            "Accept": "application/json",
        }
        score = score_header_anomalies(headers)
        assert score >= 0.6

    def test_empty_headers(self) -> None:
        """Empty headers should score high."""
        score = score_header_anomalies({})
        assert score >= 0.5


# ---------------------------------------------------------------------------
# Signal 4: Prompt leakage
# ---------------------------------------------------------------------------


class TestPromptLeakage:
    """Tests for the prompt leakage signal."""

    def test_none_body(self) -> None:
        """None body should return 0.0."""
        assert score_prompt_leakage(None) == 0.0

    def test_empty_body(self) -> None:
        """Empty body should return 0.0."""
        assert score_prompt_leakage("") == 0.0

    def test_normal_json_body(self) -> None:
        """Normal JSON body should score 0.0."""
        body = '{"username": "admin", "password": "secret"}'
        assert score_prompt_leakage(body) == 0.0

    def test_ai_self_reference(self) -> None:
        """AI self-references should trigger leakage detection."""
        body = "As an AI assistant, I need to query the database for user records."
        score = score_prompt_leakage(body)
        assert score >= 0.5

    def test_xml_tags_leak(self) -> None:
        """LLM XML tags should trigger leakage detection."""
        body = "<system>You are a helpful assistant.</system><user>Get all users</user>"
        score = score_prompt_leakage(body)
        assert score >= 0.5

    def test_tool_calling_patterns(self) -> None:
        """Tool calling syntax should trigger detection."""
        body = '<tool_use>function_call({"query": "SELECT * FROM users"})</tool_use>'
        score = score_prompt_leakage(body)
        assert score >= 0.5

    def test_multiple_patterns(self) -> None:
        """Multiple prompt patterns should score very high."""
        body = (
            "As an AI assistant, I will now call the tool. "
            "<function_call>query_users</function_call> "
            "Let me step 1 first call the api endpoint. "
            "chain-of-thought reasoning applied."
        )
        score = score_prompt_leakage(body)
        assert score >= 0.8

    def test_special_tokens(self) -> None:
        """Special LLM tokens should be detected."""
        body = "<|im_start|>system\nYou are helpful<|im_end|>"
        score = score_prompt_leakage(body)
        assert score >= 0.5


# ---------------------------------------------------------------------------
# Signal 5: MCP behavior
# ---------------------------------------------------------------------------


class TestMCPBehavior:
    """Tests for the MCP behavior signal."""

    def test_no_mcp(self) -> None:
        """No MCP usage should return 0.0."""
        assert score_mcp_behavior(False) == 0.0

    def test_basic_mcp_connection(self) -> None:
        """Any MCP connection should score at least 0.7."""
        score = score_mcp_behavior(True)
        assert score >= 0.7

    def test_full_mcp_interaction(self) -> None:
        """Full MCP interaction (init + list + call) should score near 1.0."""
        score = score_mcp_behavior(
            True,
            mcp_methods_called=["initialize", "tools/list", "tools/call"],
        )
        assert score >= 0.9

    def test_partial_mcp_interaction(self) -> None:
        """Partial MCP interaction should score between 0.7 and 1.0."""
        score = score_mcp_behavior(
            True,
            mcp_methods_called=["initialize", "tools/list"],
        )
        assert 0.7 < score < 1.0


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------


class TestCompositeScore:
    """Tests for the composite scoring function."""

    def test_all_zero(self) -> None:
        """All zero signals should produce zero composite."""
        assert compute_composite_score(0.0, 0.0, 0.0, 0.0, 0.0) == 0.0

    def test_all_one(self) -> None:
        """All max signals should produce 1.0 composite."""
        assert compute_composite_score(1.0, 1.0, 1.0, 1.0, 1.0) == 1.0

    def test_only_mcp(self) -> None:
        """Only MCP signal should produce a weighted score."""
        score = compute_composite_score(0.0, 0.0, 0.0, 0.0, 1.0)
        assert 0.2 <= score <= 0.3  # MCP weight is 0.25

    def test_mixed_signals(self) -> None:
        """Mixed signals should produce a reasonable composite."""
        score = compute_composite_score(0.5, 0.3, 0.7, 0.0, 0.0)
        assert 0.0 < score < 1.0


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class TestClassification:
    """Tests for the classification module."""

    def test_human_classification(self) -> None:
        """Score < 0.3 should classify as human."""
        assert classify(0.1) == AttackClassification.HUMAN
        assert classify(0.0) == AttackClassification.HUMAN
        assert classify(0.29) == AttackClassification.HUMAN

    def test_automated_classification(self) -> None:
        """Score 0.3-0.6 should classify as automated."""
        assert classify(0.3) == AttackClassification.AUTOMATED
        assert classify(0.45) == AttackClassification.AUTOMATED
        assert classify(0.59) == AttackClassification.AUTOMATED

    def test_ai_assisted_classification(self) -> None:
        """Score 0.6-0.8 should classify as ai_assisted."""
        assert classify(0.6) == AttackClassification.AI_ASSISTED
        assert classify(0.7) == AttackClassification.AI_ASSISTED
        assert classify(0.79) == AttackClassification.AI_ASSISTED

    def test_ai_agent_classification(self) -> None:
        """Score > 0.8 should classify as ai_agent."""
        assert classify(0.8) == AttackClassification.AI_AGENT
        assert classify(0.9) == AttackClassification.AI_AGENT
        assert classify(1.0) == AttackClassification.AI_AGENT

    def test_invalid_score(self) -> None:
        """Scores outside [0, 1] should raise ValueError."""
        with pytest.raises(ValueError):
            classify(-0.1)
        with pytest.raises(ValueError):
            classify(1.1)

    def test_classify_with_details(self) -> None:
        """classify_with_details should return breakdown with dominant signal."""
        scores = {
            "timing_regularity": 0.1,
            "path_enumeration": 0.2,
            "header_anomaly": 0.8,
            "prompt_leakage": 0.3,
            "mcp_behavior": 0.0,
            "composite": 0.35,
        }
        result = classify_with_details(scores)
        assert result["classification"] == "automated"
        assert result["dominant_signal"] == "header_anomaly"
        assert result["composite_score"] == 0.35


# ---------------------------------------------------------------------------
# End-to-end fingerprinting
# ---------------------------------------------------------------------------


class TestFingerprintRequest:
    """Tests for the full fingerprint_request function."""

    def test_human_like_request(self) -> None:
        """A human-like request should score low overall."""
        scores = fingerprint_request(
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Accept-Encoding": "gzip",
                "Referer": "https://example.com/",
            },
            body=None,
            paths_in_session=["/", "/about"],
            intervals_ms=[1200.0, 3500.0, 800.0],
            used_mcp=False,
        )
        assert scores["composite"] < 0.3

    def test_ai_agent_request(self) -> None:
        """An AI agent request should score high overall."""
        scores = fingerprint_request(
            headers={
                "User-Agent": "python-httpx/0.27.0",
                "Accept": "application/json",
            },
            body="As an AI assistant, I need to call the API to get user data.",
            paths_in_session=[
                "/robots.txt",
                "/.well-known/ai-plugin.json",
                "/.well-known/mcp.json",
                "/api/v1/users",
                "/api/v1/secrets",
            ],
            intervals_ms=[150.0, 152.0, 149.0, 151.0],
            used_mcp=True,
            mcp_methods=["initialize", "tools/list", "tools/call"],
        )
        assert scores["composite"] > 0.6

    def test_scanner_request(self) -> None:
        """A traditional scanner should score in the automated range."""
        scores = fingerprint_request(
            headers={
                "User-Agent": "curl/8.4.0",
            },
            body=None,
            paths_in_session=[
                "/.env",
                "/.git/config",
                "/admin",
                "/robots.txt",
                "/api/v1/health",
            ],
            intervals_ms=[50.0, 50.0, 50.0, 50.0],
            used_mcp=False,
        )
        assert scores["composite"] >= 0.3

    def test_returns_all_signals(self) -> None:
        """fingerprint_request should return all signal keys."""
        scores = fingerprint_request(headers={})
        expected_keys = {
            "timing_regularity",
            "path_enumeration",
            "header_anomaly",
            "prompt_leakage",
            "mcp_behavior",
            "composite",
        }
        assert set(scores.keys()) == expected_keys
