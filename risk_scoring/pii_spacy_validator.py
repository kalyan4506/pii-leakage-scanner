"""
spaCy-based (rule/heuristic) validator for detected PII.

Goal: decide whether a detected PII string is likely "real" vs "dummy/example"
based on *surrounding sentence context*, without training any custom models.

This module intentionally:
- uses spaCy only for sentence segmentation + optional NER signals
- relies on transparent heuristics (keywords + simple pattern checks)
- outputs a confidence score and marks uncertain cases accordingly
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal, Optional, Sequence, TypedDict
import re

from pii_detection.file_scanner import LineRecord
from pii_detection.pii_detector import PiiDict, PiiType


Verdict = Literal["real", "dummy", "uncertain"]


class PiiValidationDict(TypedDict):
    type: PiiType
    value: str
    file: str
    line_number: int
    verdict: Verdict
    confidence: float
    context_sentence: str
    reason: str


_DUMMY_CONTEXT_RE = re.compile(
    r"""
    \b(
      example|e\.g\.|eg|sample|dummy|fake|fictional|placeholder|test|testing|demo|
      lorem|ipsum|mock|fixture|seed|stub|not\s+real|for\s+example|like\s+this
    )\b
    """,
    flags=re.IGNORECASE | re.VERBOSE,
)

_REAL_CONTEXT_RE = re.compile(
    r"""
    \b(
      contact|call|reach|email|mail|phone|mobile|whatsapp|support|helpdesk|
      customer|client|employee|user|applicant|verification|otp|kyc|uidai|aadhaar
    )\b
    """,
    flags=re.IGNORECASE | re.VERBOSE,
)

_DUMMY_EMAIL_DOMAIN_RE = re.compile(
    r"(?i)@(?:example\.com|example\.org|example\.net|test\.com|invalid|localhost)\b"
)


def _digits_only(s: str) -> str:
    return re.sub(r"\D", "", s)


def _looks_like_dummy_number(digits: str) -> bool:
    if len(digits) < 7:
        return True
    if len(set(digits)) == 1:
        return True
    if "000000" in digits or "123456" in digits or "987654" in digits:
        return True
    # Simple ascending / descending runs often used in examples
    if digits in ("1234567890", "0987654321"):
        return True
    return False


def _find_sentence_for_value(doc, value: str) -> str:
    # Prefer the sentence that actually contains the matched value.
    v = value.lower()
    for sent in getattr(doc, "sents", []):
        if v in sent.text.lower():
            return sent.text.strip()
    return doc.text.strip()


def _get_default_nlp(model: str = "en_core_web_sm"):
    """
    Load spaCy pipeline. Tries a full model first, then falls back to a blank English
    pipeline with a sentencizer (no custom training).
    """
    try:
        import spacy  # type: ignore
    except ModuleNotFoundError as e:  # pragma: no cover
        raise ModuleNotFoundError(
            "spaCy is not installed. Install it (and optionally a model) with:\n"
            "  pip install spacy\n"
            "  python -m spacy download en_core_web_sm"
        ) from e

    try:
        nlp = spacy.load(model)
    except Exception:
        nlp = spacy.blank("en")

    if "sentencizer" not in nlp.pipe_names and "parser" not in nlp.pipe_names:
        nlp.add_pipe("sentencizer")
    return nlp


def validate_detected_pii_with_spacy(
    pii: Sequence[PiiDict],
    records: Iterable[LineRecord],
    *,
    nlp=None,
    model: str = "en_core_web_sm",
) -> list[PiiValidationDict]:
    """
    Validate detected PII using surrounding sentence context (spaCy).

    Input:
    - pii: list of dictionaries from `pii_detector.detect_pii_dicts(...)`
    - records: original `LineRecord` items used to detect PII (for line text context)

    Output:
    - list of dictionaries with additional keys: verdict, confidence, context_sentence, reason
    """
    if nlp is None:
        nlp = _get_default_nlp(model=model)

    line_lookup: dict[tuple[str, int], str] = {(r.filename, r.line_number): r.line for r in records}

    out: list[PiiValidationDict] = []
    for item in pii:
        pii_type = item["type"]
        value = item["value"]
        filename = item["file"]
        line_number = item["line_number"]

        line = line_lookup.get((filename, line_number), "")
        doc = nlp(line)
        sentence = _find_sentence_for_value(doc, value)
        sent_lower = sentence.lower()

        score = 0
        reasons: list[str] = []

        if _DUMMY_CONTEXT_RE.search(sentence):
            score -= 2
            reasons.append("dummy/example keywords in sentence")

        if _REAL_CONTEXT_RE.search(sentence):
            score += 1
            reasons.append("real-world contact/verification keywords in sentence")

        if pii_type == "email":
            if _DUMMY_EMAIL_DOMAIN_RE.search(value):
                score -= 3
                reasons.append("example/test email domain")

        digits = _digits_only(value)
        if pii_type == "phone":
            if _looks_like_dummy_number(digits):
                score -= 2
                reasons.append("phone number looks like a placeholder pattern")
        elif pii_type == "aadhaar":
            # Aadhaar-like: also treat obvious sequences/repeats as likely dummy examples
            if _looks_like_dummy_number(digits) or digits.startswith("1234") or digits.endswith("9012"):
                score -= 2
                reasons.append("aadhaar-like value looks like a common example pattern")
            if "aadhaar" in sent_lower or "uidai" in sent_lower:
                score += 1
                reasons.append("aadhaar/uidai mentioned nearby")

        # Optional NER signal when using a full model: a PERSON/ORG in same sentence
        ents = getattr(doc, "ents", ())
        if ents and any(e.label_ in {"PERSON", "ORG"} for e in ents) and pii_type in {"email", "phone"}:
            score += 1
            reasons.append("person/org entity present in same sentence")

        # Map score to verdict + confidence; keep uncertain cases lower confidence.
        if score >= 2:
            verdict: Verdict = "real"
            confidence = 0.85
        elif score <= -2:
            verdict = "dummy"
            confidence = 0.85
        else:
            verdict = "uncertain"
            confidence = max(0.25, min(0.75, 0.50 + 0.10 * score))

        reason = "; ".join(reasons) if reasons else "insufficient context signals"
        out.append(
            {
                "type": pii_type,
                "value": value,
                "file": filename,
                "line_number": line_number,
                "verdict": verdict,
                "confidence": float(confidence),
                "context_sentence": sentence,
                "reason": reason,
            }
        )

    return out


def validate_with_spacy(text: str, *, model: str = "en_core_web_sm"):
    """
    Lightweight helper for validating raw text with spaCy.

    This is a simplified API intended primarily for tests and demo usage:
    it runs spaCy NER over the input text and returns a list of dictionaries
    with entity text and labels. When text is empty, an empty list is
    returned.
    """
    if not text:
        return []

    nlp = _get_default_nlp(model=model)
    doc = nlp(text)
    results: list[dict] = []
    for ent in getattr(doc, "ents", ()):
        results.append({"text": ent.text, "label": ent.label_})
    return results
