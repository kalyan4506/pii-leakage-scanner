from typing import Any, Dict, List

from pii_detection.pii_detector import detect_pii


def _normalize_results(result: Any) -> List[Dict[str, Any]]:
    """
    Helper to treat detect_pii(...) returning either:
    - a single dict-like object
    - a list of dict-like or dataclass-like objects
    """
    if isinstance(result, dict):
        items = [result]
    elif isinstance(result, list):
        items = result
    else:
        raise AssertionError(f"Unexpected detect_pii result type: {type(result)!r}")

    normalized: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(item)
        else:
            # Fallback for dataclass-like objects (e.g., PiiMatch).
            data = {
                "type": getattr(item, "type", getattr(item, "pii_type", None)),
                "value": getattr(item, "value", None),
                "file": getattr(item, "file", getattr(item, "filename", None)),
                "line_number": getattr(item, "line_number", None),
            }
            normalized.append(data)
    return normalized


def test_detect_pii_email():
    text = "Please contact dummy.user@example.com for more information."

    raw_result = detect_pii(text)
    results = _normalize_results(raw_result)

    assert any(
        r.get("type") == "email" and r.get("value") == "dummy.user@example.com"
        for r in results
    )


def test_detect_pii_phone():
    text = "For support, call +1 555 123 4567 during office hours."

    raw_result = detect_pii(text)
    results = _normalize_results(raw_result)

    assert any(
        r.get("type") == "phone" and "555" in str(r.get("value", ""))
        for r in results
    )


def test_detect_pii_no_pii_returns_empty():
    text = "This sentence contains no identifiable contact information."

    raw_result = detect_pii(text)
    results = _normalize_results(raw_result)

    assert results == []


def test_detect_pii_multiple_pii_in_single_text():
    text = (
        "Reach out to dummy.user@example.com or call 555-987-6543 for test purposes."
    )

    raw_result = detect_pii(text)
    results = _normalize_results(raw_result)

    types = {r.get("type") for r in results}
    assert "email" in types
    assert "phone" in types
    assert len(results) >= 2

