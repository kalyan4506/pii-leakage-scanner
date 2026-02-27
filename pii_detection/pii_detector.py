"""
Regex-based PII detector.

Detects (line-by-line):
- email addresses
- phone numbers (India + international, permissive formatting)
- Aadhaar-like numbers (12 digits, commonly grouped as 4-4-4)

Returns structured matches with: type, value, file, line number.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, Literal, Sequence, TypedDict
import re

from file_scanner import LineRecord, PathLike, scan_paths


PiiType = Literal["email", "phone", "aadhaar"]


@dataclass(frozen=True, slots=True)
class PiiMatch:
    pii_type: PiiType
    value: str
    filename: str
    line_number: int


class PiiDict(TypedDict):
    type: PiiType
    value: str
    file: str
    line_number: int


# Email regex (practical, not RFC-5322 complete).
# - local part: letters/digits plus common email punctuation
# - "@"
# - domain: labels separated by dots
# - TLD: 2+ letters
EMAIL_RE = re.compile(
    r"""
    \b                              # word boundary
    [a-z0-9._%+\-]+                 # local-part (common subset)
    @
    [a-z0-9.\-]+                    # domain labels
    \.
    [a-z]{2,}                       # top-level domain
    \b
    """,
    flags=re.IGNORECASE | re.VERBOSE,
)


# Phone regex (captures both international and India-like formats).
# Intent:
# - allow optional country code (+<1..3 digits>) with separators
# - allow optional trunk prefix "0" (common in India for STD/mobile dialing)
# - accept common separators: spaces, hyphens, dots, parentheses
# - keep reasonably bounded lengths to reduce false positives
#
# Notes:
# - This is intentionally permissive: it aims to *find* likely phone numbers in code/text,
#   not to validate every possible national numbering plan.
PHONE_RE = re.compile(
    r"""
    (?<!\w)                                     # don't start inside a word
    (                                           # start full match
      (?:\+?\s*\d{1,3}[\s\-.()]*)?              # optional country code
      (?:0[\s\-.()]*)?                          # optional trunk prefix (e.g., 0)
      (?:                                       # either:
        (?:[6-9]\d{2}[\s\-.()]*\d{3}[\s\-.()]*\d{4})  # India mobile (grouped 3-3-4)
        |                                       # or:
        (?:[6-9]\d{9})                           # India mobile (plain 10 digits)
        |                                       # or:
        (?:\d[\d\s\-.()]{6,}\d)                  # general international-ish number
      )
    )
    (?!\w)                                      # don't end inside a word
    """,
    flags=re.VERBOSE,
)


# Aadhaar-like regex (12 digits; often written as 4-4-4 with spaces).
# Aadhaar specifics (approximate):
# - 12 digits total
# - first digit is 2-9 (Aadhaar does not start with 0 or 1)
# This detector is "Aadhaar-like" and does not implement checksum validation.
#
# Extra guard:
# - Avoid matching a bare India-country-code + 10 digits (91xxxxxxxxxx) as Aadhaar-like.
AADHAAR_RE = re.compile(
    r"""
    (?<!\w)                 # left boundary
    (?!91\d{10}\b)          # don't treat 91 + 10 digits as Aadhaar-like
    (                       # capture the value as written
      [2-9]\d{3}            # first 4 digits (starts 2-9)
      [\s\-]?               # optional separator
      \d{4}                 # next 4 digits
      [\s\-]?               # optional separator
      \d{4}                 # last 4 digits
    )
    (?!\w)                  # right boundary
    """,
    flags=re.VERBOSE,
)


def _iter_matches_for_line(filename: str, line_number: int, line: str) -> Iterator[PiiMatch]:
    reserved_spans: list[tuple[int, int]] = []

    def overlaps_any(span: tuple[int, int]) -> bool:
        s1, e1 = span
        for s2, e2 in reserved_spans:
            if s1 < e2 and s2 < e1:
                return True
        return False

    for m in EMAIL_RE.finditer(line):
        reserved_spans.append(m.span(0))
        yield PiiMatch("email", m.group(0), filename, line_number)

    # Aadhaar-like before phones; also reserve its span so phones don't re-match it.
    for m in AADHAAR_RE.finditer(line):
        reserved_spans.append(m.span(1))
        yield PiiMatch("aadhaar", m.group(1), filename, line_number)

    for m in PHONE_RE.finditer(line):
        if overlaps_any(m.span(1)):
            continue

        raw = m.group(1).strip()
        # Heuristic: ignore very short "numbers" to reduce false positives.
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 7:
            continue

        yield PiiMatch("phone", raw, filename, line_number)


def detect_pii(records: Iterable[LineRecord]) -> Iterator[PiiMatch]:
    """
    Detect PII in an iterable of LineRecord items.
    """
    for r in records:
        yield from _iter_matches_for_line(r.filename, r.line_number, r.line)


def pii_match_to_dict(match: PiiMatch) -> PiiDict:
    """
    Convert a structured PiiMatch into a plain dictionary for easy downstream use.
    """
    return {
        "type": match.pii_type,
        "value": match.value,
        "file": match.filename,
        "line_number": match.line_number,
    }


def pii_matches_to_dicts(matches: Iterable[PiiMatch]) -> list[PiiDict]:
    """
    Materialize an iterable of matches into a clean list of dictionaries.
    """
    return [pii_match_to_dict(m) for m in matches]


def detect_pii_dicts(records: Iterable[LineRecord]) -> list[PiiDict]:
    """
    Convenience wrapper: detect PII and return a list of dictionaries.
    """
    return pii_matches_to_dicts(detect_pii(records))


def detect_pii_in_paths(
    paths: Sequence[PathLike],
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> Iterator[PiiMatch]:
    """
    Convenience wrapper to scan files from disk and detect PII.
    """
    return detect_pii(scan_paths(paths, encoding=encoding, errors=errors))


def detect_pii_dicts_in_paths(
    paths: Sequence[PathLike],
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> list[PiiDict]:
    """
    Convenience wrapper: scan files from disk, detect PII, return list of dictionaries.
    """
    return pii_matches_to_dicts(detect_pii_in_paths(paths, encoding=encoding, errors=errors))

