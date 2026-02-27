from risk_scoring.pii_risk_scoring import calculate_risk_score


def test_risk_score_greater_than_zero_when_pii_exists():
    pii_items = [
        {
            "type": "email",
            "value": "dummy.user@example.com",
            "file": "dummy.txt",
            "line_number": 1,
            "severity_weight": 0.5,
            "confidence": 1.0,
        }
    ]

    score = calculate_risk_score(pii_items)

    assert isinstance(score, (int, float))
    assert score > 0


def test_risk_score_increases_with_more_pii_items():
    base_items = [
        {
            "type": "email",
            "value": "dummy.user@example.com",
            "file": "dummy.txt",
            "line_number": 1,
            "severity_weight": 0.5,
            "confidence": 1.0,
        }
    ]
    more_items = base_items + [
        {
            "type": "phone",
            "value": "555-123-4567",
            "file": "dummy.txt",
            "line_number": 2,
            "severity_weight": 0.7,
            "confidence": 1.0,
        }
    ]

    score_single = calculate_risk_score(base_items)
    score_multiple = calculate_risk_score(more_items)

    assert isinstance(score_single, (int, float))
    assert isinstance(score_multiple, (int, float))
    assert score_multiple > score_single


def test_risk_score_zero_or_minimal_when_no_pii():
    pii_items: list[dict] = []

    score = calculate_risk_score(pii_items)

    assert isinstance(score, (int, float))
    assert 0 <= score <= 1

