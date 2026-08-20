import json
import os
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ai_module"))

from extractor import extract_fields, format_for_llm
from analysis_service import aggregate_alerts, format_window_for_llm


def test_web_attack_packet_decoding():
    raw_alert_traversal = {
        "rule": {"id": "31101", "level": 5, "description": "Web server 400 error code."},
        "agent": {"id": "001", "name": "victim-ubuntu", "ip": "192.168.100.20"},
        "data": {"srcip": "192.168.100.30", "protocol": "GET", "id": "404", "url": "/etc/passwd"},
        "full_log": '192.168.100.30 - - [01/Jan/2026:00:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 437 "-" "curl/8.18.0"'
    }
    extracted = extract_fields(raw_alert_traversal)
    assert extracted["rule.id"] == "31101"
    assert extracted["data.srcip"] == "192.168.100.30"
    assert extracted["agent.name"] == "victim-ubuntu"
    
    formatted = format_for_llm(extracted)
    assert "Rule: 31101 (level 5)" in formatted
    assert "Source IP: 192.168.100.30" in formatted
    assert "GET /etc/passwd" in formatted


def test_web_xss_packet_decoding():
    raw_alert_xss = {
        "rule": {"id": "31105", "level": 6, "description": "XSS (Cross Site Scripting) attempt."},
        "agent": {"id": "001", "name": "victim-ubuntu", "ip": "192.168.100.20"},
        "data": {"srcip": "192.168.100.30", "protocol": "GET", "id": "404", "url": "/<script>alert(1)</script>"},
        "full_log": '192.168.100.30 - - [01/Jan/2026:00:00:00 +0000] "GET /<script>alert(1)</script> HTTP/1.1" 404 437 "-" "curl/8.18.0"'
    }
    extracted = extract_fields(raw_alert_xss)
    assert extracted["rule.id"] == "31105"
    assert extracted["data.srcip"] == "192.168.100.30"
    assert "<script>alert(1)</script>" in extracted["full_log"]


def test_dvwa_burst_correlation_window():
    hits = [
        {
            "_index": "wazuh-alerts-4.x-2026.08.20",
            "_id": f"hit-{i}",
            "_source": {
                "rule": {"id": "100121", "level": 10, "description": "DVWA login POST burst from one source"},
                "agent": {"name": "victim-ubuntu", "id": "001"},
                "data": {"srcip": "192.168.100.30"},
                "timestamp": "2026-08-20T10:00:00Z",
                "full_log": '192.168.100.30 - - [20/Aug/2026:10:00:00 +0000] "POST /DVWA/login.php HTTP/1.1" 302 0'
            }
        }
        for i in range(25)
    ]
    aggregate = aggregate_alerts(hits)
    assert aggregate["total_alerts"] == 25
    assert aggregate["total_groups"] == 1
    assert aggregate["groups"][0]["rule_id"] == "100121"
    assert aggregate["groups"][0]["count"] == 25