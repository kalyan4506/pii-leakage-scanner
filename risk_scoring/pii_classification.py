"""
PII classification (risk level + severity weight) by PII type.

This module is intentionally simple and explainable:
- It does NOT detect PII (see `pii_detector.py`)
- It does NOT use NLP or scoring models
- It assigns risk/severity based on a configurable policy mapping per PII type

Typical usage:
1) Detect PII as dictionaries via `pii_detector.detect_pii_dicts(...)`
2) Classify those dictionaries via `classify_pii_dicts(...)`
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Literal, Mapping, MutableMapping, Optional, Sequence, TypedDict
import json

from pii_detection.pii_detector import PiiDict, PiiType


RiskLevel = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class PiiRiskProfile:
    """
    Explainable policy for a single PII type.

    - risk_level: categorical bucket for reporting/routing
    - severity_weight: numeric weight in [0.0, 1.0] for aggregation/thresholding
    - rationale: short human-readable reason (kept stable for auditability)
    """

    risk_level: RiskLevel
    severity_weight: float
    rationale: str


class PiiClassificationDict(PiiDict):
    risk_level: RiskLevel
    severity_weight: float
    rationale: str


DEFAULT_POLICY: Mapping[PiiType, PiiRiskProfile] = {
    # Email is often personal data; impact varies by context → medium by default.
    "email": PiiRiskProfile(
        risk_level="medium",
        severity_weight=0.50,
        rationale="Direct identifier; commonly personal data but typically lower impact than government ID.",
    ),
    # Phone numbers are strong identifiers and often used for OTP/login recovery → high by default.
    "phone": PiiRiskProfile(
        risk_level="high",
        severity_weight=0.70,
        rationale="Direct identifier often tied to accounts, OTP, and contactability.",
    ),
    # Aadhaar-like values represent government ID; generally high sensitivity → critical by default.
    "aadhaar": PiiRiskProfile(
        risk_level="critical",
        severity_weight=0.95,
        rationale="Government ID-like identifier with high sensitivity and regulatory implications.",
    ),
}


def _validate_profile(pii_type: str, profile: PiiRiskProfile) -> None:
    if not (0.0 <= profile.severity_weight <= 1.0):
        raise ValueError(
            f"severity_weight for {pii_type!r} must be in [0.0, 1.0], got {profile.severity_weight!r}"
        )
    if not profile.rationale.strip():
        raise ValueError(f"rationale for {pii_type!r} must be non-empty")


def validate_policy(policy: Mapping[PiiType, PiiRiskProfile]) -> None:
    for t, p in policy.items():
        _validate_profile(t, p)


def merge_policy(
    base: Mapping[PiiType, PiiRiskProfile],
    overrides: Mapping[PiiType, PiiRiskProfile],
) -> Dict[PiiType, PiiRiskProfile]:
    """
    Create a new policy by overlaying `overrides` on top of `base`.
    """
    merged: Dict[PiiType, PiiRiskProfile] = dict(base)
    merged.update(overrides)
    validate_policy(merged)
    return merged


def load_policy_from_json(path: str) -> Dict[PiiType, PiiRiskProfile]:
    """
    Load a policy mapping from a JSON file.

    Expected JSON shape:
    {
      "email":   {"risk_level": "medium", "severity_weight": 0.5,  "rationale": "..."},
      "phone":   {"risk_level": "high",   "severity_weight": 0.7,  "rationale": "..."},
      "aadhaar": {"risk_level": "critical","severity_weight": 0.95,"rationale": "..."}
    }
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    out: Dict[PiiType, PiiRiskProfile] = {}
    for k, v in raw.items():
        if k not in ("email", "phone", "aadhaar"):
            raise ValueError(f"Unknown PII type in policy JSON: {k!r}")
        out[k] = PiiRiskProfile(
            risk_level=v["risk_level"],
            severity_weight=float(v["severity_weight"]),
            rationale=str(v["rationale"]),
        )
    validate_policy(out)
    return out


def classify_pii_dict(item: PiiDict, *, policy: Mapping[PiiType, PiiRiskProfile] = DEFAULT_POLICY) -> PiiClassificationDict:
    """
    Add classification fields to one detected PII dictionary.
    """
    profile = policy[item["type"]]
    _validate_profile(item["type"], profile)

    return {
        **item,
        "risk_level": profile.risk_level,
        "severity_weight": float(profile.severity_weight),
        "rationale": profile.rationale,
    }


def classify_pii_dicts(
    items: Iterable[PiiDict],
    *,
    policy: Mapping[PiiType, PiiRiskProfile] = DEFAULT_POLICY,
) -> list[PiiClassificationDict]:
    """
    Classify a set of detected PII dictionaries into risk level + severity weights.
    """
    validate_policy(policy)
    return [classify_pii_dict(x, policy=policy) for x in items]


def classify_pii(items: Sequence[PiiDict], *, policy: Mapping[PiiType, PiiRiskProfile] = DEFAULT_POLICY) -> str:
    """
    Convenience helper that returns an overall categorical risk level for a set
    of PII items.

    The highest risk level of any item (according to the policy) wins.
    """
    if not items:
        return "low"

    order: list[RiskLevel] = ["low", "medium", "high", "critical"]
    highest: RiskLevel = "low"

    for item in items:
        profile = policy[item["type"]]
        _validate_profile(item["type"], profile)
        if order.index(profile.risk_level) > order.index(highest):
            highest = profile.risk_level

    return highest

