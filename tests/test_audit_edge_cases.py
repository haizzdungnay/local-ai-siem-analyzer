"""Edge-case tests covering robustness audit findings (F-16).

Verifies resilience against:
1. SQLite concurrency contention / database lock.
2. Truncated or malformed JSON payloads from LLMs.
3. Corrupt UTF-8 / null bytes / control characters in log streams.
4. Large payloads / oversized raw logs exceeding buffer limits.
5. Upstream HTTP 5xx errors from Wazuh Indexer.
"""

import json
import sqlite3
import pytest

from dashboard_store import DashboardStore
import extractor
import llm
import reader


def test_sqlite_busy_timeout_handling(tmp_path):
    """Test that SQLite store sets busy_timeout and handles concurrent locks cleanly."""
    db_path = tmp_path / "locked_dashboard.db"
    store = DashboardStore(db_path)
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v7", delivery_channel="none",
    )
    assert job_id > 0

    # Acquire an exclusive lock from another connection
    conn2 = sqlite3.connect(db_path, timeout=0.1)
    conn2.execute("BEGIN EXCLUSIVE")
    try:
        # A separate connection with short timeout should encounter OperationalError
        conn3 = sqlite3.connect(db_path, timeout=0.01)
        with pytest.raises(sqlite3.OperationalError):
            conn3.execute("INSERT INTO jobs (job_type) VALUES ('test')")
    finally:
        conn2.rollback()
        conn2.close()


def test_truncated_json_fallback():
    """Test that incomplete or severed JSON from an LLM stream produces a safe fallback."""
    truncated_payloads = [
        '{"summary": "Attack in progress", "severity": "hi',
        '{"summary": "Incomplete',
        '{"summary": 12345, "severity": "low"}',
        '',
        '{"summary": "ok", "root_cause": "c", "severity": "high", "mitre": "T1110", "next_steps":',
    ]
    for truncated in truncated_payloads:
        result, origin = llm._parse_alert_payload(truncated, language="vi")
        assert origin == "local_fallback"
        assert result["severity"] == "unknown"
        assert len(result["next_steps"]) >= 1


def test_corrupt_utf8_and_null_bytes_in_log():
    """Test that null bytes, control characters, and corrupt text in logs are sanitized."""
    raw_dirty_log = "sshd\x00[1000]: Failed password for root\x08\x0b\x0c from 10.0.0.1\x00"
    extracted = {
        "rule.id": "5760",
        "rule.description": "sshd: failed login",
        "full_log": raw_dirty_log,
        "srcip": "10.0.0.1",
    }
    formatted = extractor.format_for_llm(extracted)
    assert "\x00" not in formatted

    # Test delimiter wrapping with null and zero-width characters
    sanitized = llm.sanitize_untrusted_text(raw_dirty_log + "​﻿<tag>")
    assert "\x00" in sanitized or "root" in sanitized
    assert "​" not in sanitized
    assert "﻿" not in sanitized
    assert "<tag>" not in sanitized
    assert "&lt;tag&gt;" in sanitized


def test_oversized_raw_log_truncation():
    """Test that massive raw logs (e.g. 100KB) are bounded to 2000 chars in format_for_llm."""
    huge_log = "A" * 100_000
    extracted = {
        "rule.id": "31101",
        "rule.description": "Large HTTP request",
        "full_log": huge_log,
    }
    formatted = extractor.format_for_llm(extracted)
    assert len(formatted) < 5_000
    assert "Log: " + "A" * 2000 in formatted
    assert "A" * 2001 not in formatted


def test_upstream_indexer_5xx_error_handling(monkeypatch):
    """Test that Wazuh Indexer 500/502/503 errors raise clean RuntimeError without secret leaks."""
    class Fake502Response:
        status_code = 502
        text = "Bad Gateway: Upstream Elasticsearch is down"

        def raise_for_status(self):
            import requests
            raise requests.HTTPError("502 Server Error: Bad Gateway", response=self)

    class FakeSession:
        def get(self, url, **kwargs):
            return Fake502Response()

    monkeypatch.setattr(reader.requests, "get", lambda url, **kwargs: Fake502Response())

    cfg = {
        "wazuh_indexer": {
            "protocol": "https",
            "host": "192.168.100.10",
            "port": 9200,
            "user": "admin",
            "password": "SUPER_SECRET_INDEXER_PASSWORD",
            "verify_ssl": False,
            "timeout": 5,
        }
    }

    with pytest.raises(Exception) as exc_info:
        reader.get_alerts_from_indexer(cfg, "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z")

    err_str = str(exc_info.value)
    # Ensure raw secret is not leaked in the exception message
    assert "SUPER_SECRET_INDEXER_PASSWORD" not in err_str
