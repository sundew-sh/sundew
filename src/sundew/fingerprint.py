"""Request fingerprinting engine for detecting AI agent behavior.

Analyzes HTTP requests across 5 signal dimensions to determine whether
traffic originates from a human, automated scanner, AI-assisted tool,
or fully autonomous AI agent.

Each signal produces a score from 0.0 (certainly human) to 1.0
(certainly AI agent). The composite score is a weighted combination.
"""

from __future__ import annotations

import re
import statistics

# ---------------------------------------------------------------------------
# Signal 1: Timing consistency
# ---------------------------------------------------------------------------


def score_timing_regularity(interval_ms_list: list[float]) -> float:
    """Score how regular the inter-request timing intervals are.

    Humans have irregular timing with wide variance. Automated tools and
    AI agents tend to produce very consistent intervals.

    Args:
        interval_ms_list: List of inter-request intervals in milliseconds.

    Returns:
        A score from 0.0 (irregular, human-like) to 1.0 (metronomic).
    """
    if len(interval_ms_list) < 2:
        return 0.0

    mean = statistics.mean(interval_ms_list)
    if mean == 0:
        return 1.0

    stdev = statistics.stdev(interval_ms_list)
    cv = stdev / mean  # coefficient of variation

    # Humans typically have CV > 0.5, bots < 0.15
    if cv < 0.05:
        return 1.0
    if cv < 0.15:
        return 0.8
    if cv < 0.3:
        return 0.5
    if cv < 0.5:
        return 0.3
    return 0.1


# ---------------------------------------------------------------------------
# Signal 2: Path enumeration patterns
# ---------------------------------------------------------------------------

_SYSTEMATIC_PATTERNS = [
    re.compile(r"^/\.(well-known|git|env|svn|DS_Store)"),
    re.compile(r"^/(robots\.txt|sitemap\.xml|openapi\.json)"),
    re.compile(r"^/api/(v\d+/)?[a-z]+$"),
    re.compile(r"^/(admin|internal|debug|config|status|health)"),
]


def score_path_enumeration(paths: list[str]) -> float:
    """Score whether path access patterns suggest systematic enumeration.

    AI agents and scanners tend to methodically probe well-known paths
    and API endpoints in a predictable order, while humans navigate
    through links and bookmarks.

    Args:
        paths: Ordered list of accessed URL paths.

    Returns:
        A score from 0.0 (random browsing) to 1.0 (systematic scanning).
    """
    if len(paths) < 3:
        return 0.0

    score = 0.0
    unique_paths = set(paths)

    # Check for systematic probing of well-known paths
    systematic_hits = sum(
        1 for p in unique_paths if any(pat.match(p) for pat in _SYSTEMATIC_PATTERNS)
    )
    if systematic_hits >= 3:
        score += 0.4
    elif systematic_hits >= 1:
        score += 0.2

    # Check for alphabetical or sequential ordering
    sorted_paths = sorted(unique_paths)
    actual_order = list(dict.fromkeys(paths))  # unique, preserving order
    if actual_order == sorted_paths:
        score += 0.3

    # High unique-path-to-total ratio suggests exploration
    unique_ratio = len(unique_paths) / len(paths)
    if unique_ratio > 0.9:
        score += 0.2
    elif unique_ratio > 0.7:
        score += 0.1

    # Check for discovery-then-exploit pattern
    discovery_paths = {
        "/robots.txt",
        "/sitemap.xml",
        "/openapi.json",
        "/.well-known/ai-plugin.json",
        "/.well-known/mcp.json",
    }
    visited_discovery = unique_paths & discovery_paths
    if len(visited_discovery) >= 2:
        score += 0.2

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Signal 3: Header anomalies
# ---------------------------------------------------------------------------

_BOT_UA_PATTERNS = [
    re.compile(r"python-requests", re.IGNORECASE),
    re.compile(r"python-httpx", re.IGNORECASE),
    re.compile(r"node-fetch", re.IGNORECASE),
    re.compile(r"axios", re.IGNORECASE),
    re.compile(r"httpie", re.IGNORECASE),
    re.compile(r"curl", re.IGNORECASE),
    re.compile(r"wget", re.IGNORECASE),
    re.compile(r"go-http-client", re.IGNORECASE),
    re.compile(r"java/", re.IGNORECASE),
    re.compile(r"openai", re.IGNORECASE),
    re.compile(r"anthropic", re.IGNORECASE),
    re.compile(r"langchain", re.IGNORECASE),
    re.compile(r"llama", re.IGNORECASE),
    re.compile(r"mcp-client", re.IGNORECASE),
    re.compile(r"bot|crawler|spider|scraper", re.IGNORECASE),
]

_BROWSER_UA_PATTERNS = [
    re.compile(r"Mozilla/5\.0.*Chrome/", re.IGNORECASE),
    re.compile(r"Mozilla/5\.0.*Firefox/", re.IGNORECASE),
    re.compile(r"Mozilla/5\.0.*Safari/", re.IGNORECASE),
]


def score_header_anomalies(headers: dict[str, str]) -> float:
    """Score header anomalies that suggest non-human traffic.

    Checks for missing Referer, bot-like User-Agent, unusual Accept
    headers, and other patterns common in automated requests.

    Args:
        headers: Request headers as a case-insensitive dict.

    Returns:
        A score from 0.0 (normal browser) to 1.0 (clearly automated).
    """
    # Normalize header keys to lowercase
    h = {k.lower(): v for k, v in headers.items()}
    score = 0.0

    # Missing or empty User-Agent
    ua = h.get("user-agent", "")
    if not ua:
        score += 0.3
    else:
        # Bot-like User-Agent
        if any(pat.search(ua) for pat in _BOT_UA_PATTERNS):
            score += 0.3
        # Not a browser
        elif not any(pat.search(ua) for pat in _BROWSER_UA_PATTERNS):
            score += 0.2

    # Missing Referer on API calls (browsers usually have one)
    if "referer" not in h:
        score += 0.1

    # Unusual Accept header (not typical browser default)
    accept = h.get("accept", "")
    if accept == "application/json":
        score += 0.1
    elif accept == "*/*":
        score += 0.05
    elif not accept:
        score += 0.15

    # Missing typical browser headers
    if "accept-language" not in h:
        score += 0.1
    if "accept-encoding" not in h:
        score += 0.05

    # Presence of AI/MCP specific headers
    if "x-mcp-version" in h or "x-openai-api-key" in h:
        score += 0.3

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Signal 4: Prompt leakage
# ---------------------------------------------------------------------------

_PROMPT_LEAK_PATTERNS = [
    re.compile(r"as an ai\b", re.IGNORECASE),
    re.compile(r"as a language model\b", re.IGNORECASE),
    re.compile(r"i'?m an ai\b", re.IGNORECASE),
    re.compile(r"i'?m a language model\b", re.IGNORECASE),
    re.compile(r"</?(?:system|user|assistant|human|tool_use|tool_result)\b", re.IGNORECASE),
    re.compile(r"</?(?:function_call|observation|thought|thinking|scratchpad)\b", re.IGNORECASE),
    re.compile(r"\bfunction_call\s*\(", re.IGNORECASE),
    re.compile(r"\btool_call\b", re.IGNORECASE),
    re.compile(r"```(?:json|xml|yaml)\s*\{", re.IGNORECASE),
    re.compile(r"<\|(?:im_start|im_end|system|user|assistant)\|>", re.IGNORECASE),
    re.compile(
        r"\b(?:step \d+|let me|i will now|first,? i)\b.*\b(?:api|endpoint|request)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?:chain.?of.?thought|reasoning|tool.?use)", re.IGNORECASE),
]


def score_prompt_leakage(body: str | None) -> float:
    """Score whether request body contains LLM artifacts.

    AI agents sometimes leak prompt patterns, XML tags, chain-of-thought
    reasoning, or tool-calling syntax into request bodies.

    Args:
        body: The request body as a string, or None.

    Returns:
        A score from 0.0 (no leakage) to 1.0 (clear LLM artifacts).
    """
    if not body:
        return 0.0

    matches = sum(1 for pat in _PROMPT_LEAK_PATTERNS if pat.search(body))

    if matches >= 4:
        return 1.0
    if matches >= 2:
        return 0.8
    if matches >= 1:
        return 0.5
    return 0.0


# ---------------------------------------------------------------------------
# Signal 5: MCP behavior
# ---------------------------------------------------------------------------


def score_mcp_behavior(
    used_mcp: bool,
    mcp_methods_called: list[str] | None = None,
) -> float:
    """Score based on MCP protocol usage.

    Connecting via the MCP protocol is a very strong signal that the
    client is an AI agent, since humans don't typically speak JSON-RPC
    MCP directly.

    Args:
        used_mcp: Whether the client sent any MCP JSON-RPC requests.
        mcp_methods_called: Optional list of MCP methods called.

    Returns:
        A score from 0.0 (no MCP usage) to 1.0 (full MCP interaction).
    """
    if not used_mcp:
        return 0.0

    score = 0.7  # base score for any MCP connection

    if mcp_methods_called:
        if "initialize" in mcp_methods_called:
            score += 0.1
        if "tools/list" in mcp_methods_called:
            score += 0.1
        if "tools/call" in mcp_methods_called:
            score += 0.1

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------

_WEIGHTS = {
    "timing_regularity": 0.15,
    "path_enumeration": 0.20,
    "header_anomaly": 0.20,
    "prompt_leakage": 0.20,
    "mcp_behavior": 0.25,
}


def compute_composite_score(
    timing_regularity: float,
    path_enumeration: float,
    header_anomaly: float,
    prompt_leakage: float,
    mcp_behavior: float,
) -> float:
    """Compute the weighted composite fingerprint score.

    Args:
        timing_regularity: Score from timing analysis.
        path_enumeration: Score from path pattern analysis.
        header_anomaly: Score from header analysis.
        prompt_leakage: Score from body content analysis.
        mcp_behavior: Score from MCP protocol usage.

    Returns:
        A composite score from 0.0 to 1.0.
    """
    raw = (
        _WEIGHTS["timing_regularity"] * timing_regularity
        + _WEIGHTS["path_enumeration"] * path_enumeration
        + _WEIGHTS["header_anomaly"] * header_anomaly
        + _WEIGHTS["prompt_leakage"] * prompt_leakage
        + _WEIGHTS["mcp_behavior"] * mcp_behavior
    )
    # Clamp to [0.0, 1.0]
    return max(0.0, min(1.0, raw))


def fingerprint_request(
    headers: dict[str, str],
    body: str | None = None,
    paths_in_session: list[str] | None = None,
    intervals_ms: list[float] | None = None,
    used_mcp: bool = False,
    mcp_methods: list[str] | None = None,
) -> dict[str, float]:
    """Run all fingerprint signals on a request/session and return scores.

    This is the main entry point for the fingerprinting engine. It runs
    all 5 signal analyzers and computes the composite score.

    Args:
        headers: Request headers dict.
        body: Request body string, if any.
        paths_in_session: Ordered list of paths accessed in the session.
        intervals_ms: Inter-request intervals in milliseconds.
        used_mcp: Whether MCP protocol was used.
        mcp_methods: List of MCP methods called.

    Returns:
        A dict with individual signal scores and the composite score.
    """
    timing = score_timing_regularity(intervals_ms or [])
    paths = score_path_enumeration(paths_in_session or [])
    header = score_header_anomalies(headers)
    prompt = score_prompt_leakage(body)
    mcp = score_mcp_behavior(used_mcp, mcp_methods)

    composite = compute_composite_score(timing, paths, header, prompt, mcp)

    return {
        "timing_regularity": timing,
        "path_enumeration": paths,
        "header_anomaly": header,
        "prompt_leakage": prompt,
        "mcp_behavior": mcp,
        "composite": composite,
    }
