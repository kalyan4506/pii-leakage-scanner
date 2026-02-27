"""
Transparent risk scoring for detected PII.

This module aggregates:
- severity_weight (how sensitive the PII type is)
- confidence (how likely the detected value is "real" vs dummy/example)

into a final score (0-100) and a label that is easy to explain:

Each PII finding contributes a "risk contribution" in [0, 1]:
    contribution = severity_weight * confidence

Multiple findings combine with a simple capped accumulation:
    combined_risk = 1 - Π(1 - contribution_i)
    final_score   = combined_risk * 100

Explanation (non-technical):
- Every sensitive item adds risk.
- If we see multiple items, overall risk increases.
- The score never goes above 100.
- Lower confidence (e.g., looks like an example) reduces that item's impact.
"""

from __future__ import annotations

from typing import Any, Iterable, Literal, Mapping, Optional, Sequence, TypedDict
from typing import Any, Iterable, Literal, Mapping, Sequence, TypedDict


RiskLabel = Literal["low", "medium", "high", "critical"]


class ScoredItemDict(TypedDict, total=False):
    # Input fields (commonly produced by other modules)
    type: str
    value: str
    file: str
    line_number: int
    severity_weight: float
    confidence: float

    # Output fields added by this module
    contribution: float


class RiskScoreResult(TypedDict):
    score: float
    label: RiskLabel
    item_count: int
    scored_items: list[ScoredItemDict]
    explanation: str


DEFAULT_LABEL_THRESHOLDS: Mapping[RiskLabel, float] = {
    # score >= threshold => label (highest threshold wins)
    "low": 0.0,
    "medium": 20.0,
    "high": 50.0,
    "critical": 80.0,
}


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def risk_label_for_score(
    score: float,
    *,
    thresholds: Mapping[RiskLabel, float] = DEFAULT_LABEL_THRESHOLDS,
) -> RiskLabel:
    """
    Convert a 0-100 score into a label using configurable thresholds.
    """
    # Ensure deterministic ordering: pick the highest threshold that score meets.
    ordered: Sequence[tuple[RiskLabel, float]] = sorted(thresholds.items(), key=lambda kv: kv[1])
    label: RiskLabel = ordered[0][0]
    for k, v in ordered:
        if score >= v:
            label = k
    return label


def score_pii_findings(
    items: Iterable[Mapping[str, Any]],
    *,
    default_confidence: float = 1.0,
    thresholds: Mapping[RiskLabel, float] = DEFAULT_LABEL_THRESHOLDS,
) -> RiskScoreResult:
    """
    Aggregate PII findings into a final (score, label).

    Expected per-item keys:
    - severity_weight: float in [0,1] (required)
    - confidence: float in [0,1] (optional; defaults to `default_confidence`)

    Any additional keys (type/value/file/line_number/rationale/...) are preserved in the breakdown.
    """
    scored_items: list[ScoredItemDict] = []
    product_not_risky = 1.0

    for raw in items:
        if "severity_weight" not in raw:
            raise KeyError("Each item must include 'severity_weight' (0..1).")

        sev = _clamp01(float(raw["severity_weight"]))
        conf = _clamp01(float(raw.get("confidence", default_confidence)))
        contribution = _clamp01(sev * conf)

        # Combine risks with diminishing returns, capped at 1.0.
        product_not_risky *= (1.0 - contribution)

        scored: ScoredItemDict = dict(raw)  # type: ignore[assignment]
        scored["contribution"] = float(contribution)
        scored_items.append(scored)

    combined_risk = 1.0 - _clamp01(product_not_risky)
    score = float(round(combined_risk * 100.0, 2))
    label = risk_label_for_score(score, thresholds=thresholds)

    explanation = (
        "We assign each finding an impact (severity x confidence). "
        "We then combine impacts so multiple findings raise the overall risk, "
        "with diminishing returns, and the final score is capped at 100."
    )

    return {
        "score": score,
        "label": label,
        "item_count": len(scored_items),
        "scored_items": scored_items,
        "explanation": explanation,
    }

