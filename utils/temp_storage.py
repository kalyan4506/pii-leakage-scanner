"""
In-memory temporary storage for PII detection results with Time-To-Live (TTL).

Privacy & legal motivation:
- Storing personal data (PII) even temporarily can create legal and ethical risks
  (e.g. GDPR, data minimization). This module ensures detected PII is kept only
  in memory and only for a short, configurable duration, then automatically
  removed. No PII is ever written to disk.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional

# Default retention: 10 minutes. Configurable per call to support different policies.
DEFAULT_TTL_SECONDS = 600


def _now() -> float:
    """Current time in seconds since epoch (for expiry checks)."""
    return time.time()


def _is_expired(stored_at: float, ttl_seconds: float) -> bool:
    return (_now() - stored_at) >= ttl_seconds


# In-memory store: list of { "scan_id", "stored_at", "ttl_seconds", "payload" }.
# We use a list so multiple scans can coexist; each entry has its own timestamp and TTL.
_storage: list[dict[str, Any]] = []


def _prune_expired() -> None:
    """Remove all entries that have exceeded their TTL. Call on read and write."""
    global _storage
    now = _now()
    _storage = [
        e for e in _storage
        if (now - e["stored_at"]) < e["ttl_seconds"]
    ]


def add(
    payload: Any,
    *,
    scan_id: Optional[str] = None,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
) -> str:
    """
    Store a payload (e.g. PII scan results) in memory with a timestamp and TTL.

    Args:
        payload: Arbitrary data to store (e.g. list of PII dicts or display payload).
        scan_id: Optional id for this scan; if not provided, a new UUID is generated.
        ttl_seconds: Time-to-live in seconds (default 600 = 10 minutes).

    Returns:
        The scan_id for this entry (for later retrieval).
    """
    _prune_expired()
    sid = scan_id if scan_id is not None else str(uuid.uuid4())
    entry = {
        "scan_id": sid,
        "stored_at": _now(),
        "ttl_seconds": ttl_seconds,
        "payload": payload,
    }
    _storage.append(entry)
    return sid


def get(scan_id: str) -> Optional[Any]:
    """
    Retrieve payload for a scan_id if it exists and has not expired.

    Side effect: expired entries (including others) are pruned.

    Returns:
        The stored payload, or None if not found or expired.
    """
    _prune_expired()
    for e in _storage:
        if e["scan_id"] == scan_id:
            return e["payload"]
    return None


def get_all_non_expired() -> list[tuple[str, Any]]:
    """
    Return all (scan_id, payload) pairs that are still within TTL.
    Useful for cleanup or auditing count; payloads may still contain PII.
    """
    _prune_expired()
    return [(e["scan_id"], e["payload"]) for e in _storage]


def clear() -> None:
    """Remove all entries from the store. Use for tests or explicit flush."""
    global _storage
    _storage = []
