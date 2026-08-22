import json
import os
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ai_module"))

import llm
from analysis_service import aggregate_rule_buckets, format_window_for_llm


def test_ip_profile_schema_validation():
    sample_response = {
        "summary": "Attacker IP executed reconnaissance followed by credential brute force.",
        "intent": "Credential theft and unauthorized remote access",
        "severity": "high",
        "kill_chain_stages": [
            "Stage 1 (Recon): Scanned HTTP 400 error codes",
            "Stage 2 (Exploit): Probed XSS vulnerabilities",
            "Stage 3 (Credential Access): SSH login brute-force attacks"
        ],
        "targeted_assets": ["victim-ubuntu (192.168.100.20)", "/DVWA/login.php"],
        "mitre": ["T1595.002", "T1110.001"],
        "next_steps": ["Block IP 192.168.100.30 at perimeter firewall", "Rotate compromised credentials"],
        "response_language": "vi",
        "confidence": 90.0,
        "assessment_basis": {
            "observed_facts": ["15,000 alerts recorded from IP 192.168.100.30"],
            "inferences": ["Sustained brute force indicates automated tool usage"],
            "uncertainties": ["No confirmation of successful shell escape"],
            "limitations": ["Logs bounded within last 30 days"]
        }
    }
    raw = json.dumps(sample_response)
    parsed, origin = llm._parse_ip_profile_payload(raw, language="vi")
    assert origin == "model"
    assert parsed["intent"] == "Credential theft and unauthorized remote access"
    assert len(parsed["kill_chain_stages"]) == 3
    assert parsed["confidence"] == 90.0


def test_ip_profile_fallback_on_invalid_json():
    raw_invalid = "This is not valid JSON"
    parsed, origin = llm._parse_ip_profile_payload(raw_invalid, language="vi")
    assert origin == "local_fallback"
    assert parsed["severity"] == "unknown"
    assert parsed["confidence"] == 0.0
    assert "JSON" in parsed["summary"]


def test_ip_profile_large_volume_token_safety():
    mock_fetched = {
        "total": 15000,
        "unique_rules": 5,
        "unique_agents": 1,
        "unique_source_ips": 1,
        "unique_counts_approximate": False,
        "rule_buckets": [
            {
                "rule_id": "31151", "count": 9000, "max_level": 10,
                "first_seen": "2026-07-29T00:00:00Z", "last_seen": "2026-08-10T00:00:00Z",
                "sample": {"rule": {"description": "Multiple web 400 errors", "mitre": {"id": ["T1595.002"]}}}
            },
            {
                "rule_id": "5760", "count": 5000, "max_level": 5,
                "first_seen": "2026-08-01T00:00:00Z", "last_seen": "2026-08-20T00:00:00Z",
                "sample": {"rule": {"description": "sshd auth failed", "mitre": {"id": ["T1110.001"]}}}
            }
        ]
    }
    aggregate = aggregate_rule_buckets(mock_fetched)
    prompt_text, coverage = format_window_for_llm(aggregate)
    assert len(prompt_text) < 3000
    assert coverage["represented_alerts"] == 14000