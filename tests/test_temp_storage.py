"""Tests for in-memory TTL storage. No PII is written to disk."""

import time

import pytest

from utils import temp_storage


def setup_function():
    temp_storage.clear()


def teardown_function():
    temp_storage.clear()


def test_add_returns_scan_id():
    sid = temp_storage.add({"items": []})
    assert isinstance(sid, str)
    assert len(sid) > 0


def test_get_returns_payload_within_ttl():
    payload = {"df": [], "score": 42}
    sid = temp_storage.add(payload, ttl_seconds=60)
    assert temp_storage.get(sid) == payload


def test_get_returns_none_after_ttl_expiry():
    payload = {"x": 1}
    sid = temp_storage.add(payload, ttl_seconds=0)  # expire immediately
    time.sleep(0.01)
    # get() triggers prune; expired entry is removed
    assert temp_storage.get(sid) is None


def test_multiple_scans_coexist():
    s1 = temp_storage.add({"a": 1}, ttl_seconds=60)
    s2 = temp_storage.add({"b": 2}, ttl_seconds=60)
    assert temp_storage.get(s1) == {"a": 1}
    assert temp_storage.get(s2) == {"b": 2}


def test_prune_removes_expired_only():
    s1 = temp_storage.add({"a": 1}, ttl_seconds=0)
    time.sleep(0.01)
    s2 = temp_storage.add({"b": 2}, ttl_seconds=60)
    # get() triggers prune; s1 expired, s2 still valid
    assert temp_storage.get(s1) is None
    assert temp_storage.get(s2) == {"b": 2}


def test_clear_removes_all():
    s1 = temp_storage.add({"a": 1}, ttl_seconds=60)
    temp_storage.clear()
    assert temp_storage.get(s1) is None
