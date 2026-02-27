"""Tests for PII-safe log sanitization."""

import pytest

from utils.log_sanitize import REDACTED_PLACEHOLDER, sanitize_for_log


def test_sanitize_redacts_value_key():
    d = {"type": "email", "value": "user@example.com", "file": "x.txt"}
    out = sanitize_for_log(d)
    assert out["value"] == REDACTED_PLACEHOLDER
    assert out["type"] == "email"
    assert out["file"] == "x.txt"


def test_sanitize_does_not_mutate_original():
    d = {"type": "phone", "value": "9876543210"}
    out = sanitize_for_log(d)
    assert d["value"] == "9876543210"
    assert out["value"] == REDACTED_PLACEHOLDER


def test_sanitize_nested_list_of_pii_dicts():
    lst = [{"type": "email", "value": "a@b.com"}, {"type": "phone", "value": "123"}]
    out = sanitize_for_log(lst)
    assert out[0]["value"] == REDACTED_PLACEHOLDER
    assert out[1]["value"] == REDACTED_PLACEHOLDER


def test_sanitize_primitive_unchanged():
    assert sanitize_for_log(42) == 42
    assert sanitize_for_log("hello") == "hello"
    assert sanitize_for_log(None) is None
