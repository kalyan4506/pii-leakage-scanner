from risk_scoring.pii_classification import classify_pii


def test_classify_pii_high_risk_for_id_like_items():
    # Simulate high-risk government ID-like PII items.
    pii_items = [
        {"type": "aadhaar", "value": "2222 3333 4444", "file": "dummy.txt", "line_number": 1},
    ]

    result = classify_pii(pii_items)

    assert isinstance(result, str)
    assert result.lower() == "high" or result.lower() == "critical"


def test_classify_pii_medium_risk_for_email_and_phone():
    # Simulate medium-risk contact PII such as email/phone.
    pii_items = [
        {"type": "email", "value": "dummy.user@example.com", "file": "dummy.txt", "line_number": 1},
        {"type": "phone", "value": "555-123-4567", "file": "dummy.txt", "line_number": 2},
    ]

    result = classify_pii(pii_items)

    assert isinstance(result, str)
    assert result.lower() in {"medium", "high"}


def test_classify_pii_no_pii_returns_low_or_none():
    pii_items: list[dict] = []

    result = classify_pii(pii_items)

    assert isinstance(result, str)
    assert result.lower() in {"low", "none"}

