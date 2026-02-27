"""
Sanitize PII structures so that raw PII values are never written to logs.

Privacy & legal motivation:
- Logs may be persisted or shared; logging raw PII would extend retention and
  create compliance risk. This module provides a safe representation for
  logging (e.g. type and location only, value redacted).
"""

from __future__ import annotations

from typing import Any, Mapping

# Key that holds the actual PII value in detection/classification dicts.
PII_VALUE_KEY = "value"

# Placeholder used in logs instead of real values.
REDACTED_PLACEHOLDER = "[REDACTED]"


def sanitize_for_log(obj: Any) -> Any:
    """
    Return a copy of obj safe for logging: PII value fields are replaced
    with REDACTED_PLACEHOLDER. Nested dicts and lists are processed recursively.

    Use this whenever you log structures that might contain PII (e.g. from
    detect_pii_dicts or classify_pii_dicts).
    """
    if isinstance(obj, Mapping) and not isinstance(obj, type):
        out = {}
        for k, v in obj.items():
            if k == PII_VALUE_KEY:
                out[k] = REDACTED_PLACEHOLDER
            else:
                out[k] = sanitize_for_log(v)
        return out
    if isinstance(obj, list):
        return [sanitize_for_log(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(sanitize_for_log(item) for item in obj)
    return obj
