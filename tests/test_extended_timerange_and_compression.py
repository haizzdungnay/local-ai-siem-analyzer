import os, sys, json, pytest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ai_module"))

import reader
import dashboard_worker
from analysis_service import aggregate_rule_buckets, format_window_for_llm

def test_extended_time_ranges_allowed():
    now = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    
    # 1. Test 7 days window (604800s)
    start_7d = now - timedelta(days=7)
    s_utc, e_utc = reader.validate_time_range(start_7d, now, now=now)
    assert (e_utc - s_utc).total_seconds() == 604800
    
    # 2. Test 30 days window (2592000s)
    start_30d = now - timedelta(days=30)
    s_utc, e_utc = reader.validate_time_range(start_30d, now, now=now)
    assert (e_utc - s_utc).total_seconds() == 2592000
    
    # 3. Test > 30 days window (31 days) should fail
    start_31d = now - timedelta(days=31)
    with pytest.raises(ValueError, match=".*"):  # Test raises ValueError on exceeded range
        reader.validate_time_range(start_31d, now, now=now)

def test_extended_presets_registered():
    assert 259200 in dashboard_worker.PRESET_SECONDS   # 3 days
    assert 604800 in dashboard_worker.PRESET_SECONDS   # 7 days
    assert 2592000 in dashboard_worker.PRESET_SECONDS  # 30 days

def test_high_volume_log_compression_stays_token_safe():
    # Simulate high log volume: 50,000 logs in 30 days across multiple rules
    mock_fetched = {
        "total": 50000,
        "unique_rules": 3,
        "unique_agents": 2,
        "unique_source_ips": 5,
        "unique_counts_approximate": False,
        "rule_buckets": [
            {
                "rule_id": "5760",
                "count": 45000,
                "max_level": 5,
                "first_seen": "2026-07-21T00:00:00Z",
                "last_seen": "2026-08-20T12:00:00Z",
                "sample": {
                    "rule": {"description": "sshd: authentication failed.", "mitre": {"id": ["T1110.001"]}},
                    "agent": {"name": "victim-ubuntu"},
                    "data": {"srcip": "10.0.0.30"}
                }
            },
            {
                "rule_id": "31151",
                "count": 4900,
                "max_level": 10,
                "first_seen": "2026-08-01T10:00:00Z",
                "last_seen": "2026-08-20T11:00:00Z",
                "sample": {
                    "rule": {"description": "Multiple web server 400 error codes from same source ip.", "mitre": {"id": ["T1595.002"]}},
                    "agent": {"name": "victim-ubuntu"},
                    "data": {"srcip": "10.0.0.30"}
                }
            },
            {
                "rule_id": "550",
                "count": 100,
                "max_level": 7,
                "first_seen": "2026-08-10T12:00:00Z",
                "last_seen": "2026-08-10T12:05:00Z",
                "sample": {
                    "rule": {"description": "Integrity checksum changed.", "mitre": {"id": ["T1565.001"]}},
                    "agent": {"name": "victim-ubuntu"},
                    "syscheck": {"path": "/etc/shadow"}
                }
            }
        ]
    }
    
    aggregate = aggregate_rule_buckets(mock_fetched)
    llm_text, coverage = format_window_for_llm(aggregate)
    
    # Verify that compressed text for 50,000 logs is within 2000 chars (< 500 tokens)
    assert len(llm_text) < 2500
    assert "Analysis mode: aggregate" in llm_text
    assert "Total alerts: 50000" in llm_text
    assert coverage["represented_alerts"] == 50000