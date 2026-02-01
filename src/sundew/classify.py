"""Traffic classification based on fingerprint composite scores.

Maps composite fingerprint scores to traffic classification categories:
  - < 0.3  -> human
  - 0.3-0.6 -> automated (traditional scanner / bot)
  - 0.6-0.8 -> ai_assisted (human using AI tools)
  - > 0.8  -> ai_agent (fully autonomous AI agent)
"""

from __future__ import annotations

from sundew.models import AttackClassification

# Threshold boundaries for classification
_THRESHOLD_HUMAN = 0.3
_THRESHOLD_AUTOMATED = 0.6
_THRESHOLD_AI_ASSISTED = 0.8


def classify(composite_score: float) -> AttackClassification:
    """Classify traffic based on the composite fingerprint score.

    Args:
        composite_score: A score from 0.0 to 1.0 produced by the
            fingerprinting engine's composite scoring.

    Returns:
        An AttackClassification enum value.

    Raises:
        ValueError: If composite_score is outside the [0.0, 1.0] range.
    """
    if composite_score < 0.0 or composite_score > 1.0:
        raise ValueError(f"Composite score must be between 0.0 and 1.0, got {composite_score}")

    if composite_score < _THRESHOLD_HUMAN:
        return AttackClassification.HUMAN
    if composite_score < _THRESHOLD_AUTOMATED:
        return AttackClassification.AUTOMATED
    if composite_score < _THRESHOLD_AI_ASSISTED:
        return AttackClassification.AI_ASSISTED
    return AttackClassification.AI_AGENT


def classify_with_details(
    scores: dict[str, float],
) -> dict[str, str | float]:
    """Classify and return a detailed breakdown.

    Args:
        scores: A dict with individual signal scores and a 'composite' key,
            as returned by fingerprint.fingerprint_request().

    Returns:
        A dict containing the classification, composite score,
        individual signal scores, and the dominant signal.
    """
    composite = scores.get("composite", 0.0)
    classification = classify(composite)

    signal_names = [k for k in scores if k != "composite"]
    dominant = max(signal_names, key=lambda k: scores[k]) if signal_names else "none"

    return {
        "classification": classification.value,
        "composite_score": composite,
        "dominant_signal": dominant,
        **{k: scores[k] for k in signal_names},
    }
