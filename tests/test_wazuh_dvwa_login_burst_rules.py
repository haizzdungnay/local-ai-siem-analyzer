"""Static guardrails for the manager-side DVWA login-burst rule template."""

from pathlib import Path
import xml.etree.ElementTree as ET


RULE_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "infra"
    / "wazuh"
    / "rules"
    / "dvwa_login_burst_rules.xml"
)


def _rules_by_id():
    root = ET.parse(RULE_TEMPLATE).getroot()
    return {rule.attrib["id"]: rule for rule in root.findall("rule")}


def test_dvwa_login_burst_template_is_well_formed_and_uses_reserved_ids():
    rules = _rules_by_id()

    assert set(rules) == {"100120", "100121"}


def test_base_rule_matches_only_the_decoded_dvwa_login_post():
    base = _rules_by_id()["100120"]

    assert base.attrib["level"] == "3"
    assert base.findtext("if_sid") == "31108"
    assert base.findtext("options") == "no_log"
    match = base.findtext("match")
    assert match == '] "POST /DVWA/login.php HTTP/1.'
    assert match in '192.0.2.30 - - [date] "POST /DVWA/login.php HTTP/1.1" 302 0'
    assert match not in '192.0.2.30 - - [date] "GET /DVWA/login.php HTTP/1.1" 302 0'
    assert match not in '192.0.2.30 - - [date] "POST /DVWA/login.php?next=/ HTTP/1.1" 302 0'
    assert "failed" not in base.findtext("description").lower()


def test_correlation_requires_25_base_events_and_suppresses_repeat_alerts():
    correlation = _rules_by_id()["100121"]

    assert correlation.attrib["level"] == "10"
    assert correlation.attrib["frequency"] == "25"
    assert correlation.attrib["timeframe"] == "18"
    assert correlation.attrib["ignore"] == "120"
    assert correlation.findtext("if_matched_sid") == "100120"
    assert correlation.find("same_source_ip") is not None
    assert "at least 25 requests in 18 seconds" in correlation.findtext("description")
    assert "failed" not in correlation.findtext("description").lower()
