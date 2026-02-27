import pytest

from risk_scoring import pii_spacy_validator
from risk_scoring.pii_spacy_validator import validate_with_spacy


def _fake_nlp_with_entities(entities):
    """
    Build a minimal spaCy-like nlp callable that returns a doc
    object with a predefined list of named entities.
    """

    class FakeSpan:
        def __init__(self, text: str, label_: str) -> None:
            self.text = text
            self.label_ = label_

    class FakeDoc:
        def __init__(self, text: str) -> None:
            self.text = text
            self.ents = [FakeSpan(t, l) for t, l in entities]

    def nlp(text: str) -> FakeDoc:
        return FakeDoc(text)

    return nlp


def test_validate_with_spacy_detects_person_or_gpe(monkeypatch):
    fake_nlp = _fake_nlp_with_entities(
        [
            ("Sample Person", "PERSON"),
            ("Exampleville", "GPE"),
        ]
    )
    monkeypatch.setattr(pii_spacy_validator, "_get_default_nlp", lambda model="en_core_web_sm": fake_nlp)

    text = "Sample Person moved to Exampleville."
    results = validate_with_spacy(text)

    assert isinstance(results, list)
    labels = {item.get("label") for item in results if isinstance(item, dict)}
    assert "PERSON" in labels or "GPE" in labels


def test_validate_with_spacy_handles_empty_input(monkeypatch):
    fake_nlp = _fake_nlp_with_entities([])
    monkeypatch.setattr(pii_spacy_validator, "_get_default_nlp", lambda model="en_core_web_sm": fake_nlp)

    results = validate_with_spacy("")

    assert isinstance(results, list)
    assert results == [] or len(results) == 0


def test_validate_with_spacy_skips_real_spacy_when_unavailable(monkeypatch):
    """
    Simulate an environment without a real spaCy model by mocking
    the loader so tests do not depend on spaCy being installed.
    """
    fake_nlp = _fake_nlp_with_entities([("Sample Person", "PERSON")])
    monkeypatch.setattr(pii_spacy_validator, "_get_default_nlp", lambda model="en_core_web_sm": fake_nlp)

    text = "Sample Person is used in this dummy sentence."
    results = validate_with_spacy(text)

    assert isinstance(results, list)
    assert len(results) >= 1

