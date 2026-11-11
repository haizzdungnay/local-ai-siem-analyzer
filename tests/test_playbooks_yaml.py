"""Kiểm tra cấu trúc playbook Tầng 3 (ai_module/rag_data/playbooks.yaml)."""
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "ai_module" / "rag_data" / "playbooks.yaml"
WAZUH_RULES = ROOT / "ai_module" / "rag_data" / "wazuh_rules.json"
SEVERITIES = {"low", "medium", "high", "critical", "unknown"}
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _load():
    return yaml.safe_load(PLAYBOOKS.read_text(encoding="utf-8"))["playbooks"]


def _complete(entry):
    return bool(entry.get("branches")) and isinstance(entry["branches"], list)


def test_no_live_ip_in_playbooks():
    assert not IPV4.findall(PLAYBOOKS.read_text(encoding="utf-8"))


def test_complete_playbooks_are_consistent():
    known = {str(r["id"]) for r in json.loads(WAZUH_RULES.read_text(encoding="utf-8"))}
    for pb in filter(_complete, _load()):
        verify_ids = [v["id"] for v in pb["verify"]]
        assert len(verify_ids) == len(set(verify_ids)), pb["rule_id"]
        for v in pb["verify"]:
            assert v["question"] and v["query"] and v["interpret"], (pb["rule_id"], v["id"])
            for rid in re.findall(r"rule\.id:\(?([\d\sor]+)\)?", v["query"]):
                for one in re.findall(r"\d+", rid):
                    assert one in known, (pb["rule_id"], v["id"], one)
        for br in pb["branches"]:
            assert br["severity"] in SEVERITIES, (pb["rule_id"], br["id"])
            assert br["actions"], (pb["rule_id"], br["id"])
            for ref in re.findall(r"\bV\d+\b", br["when"]):
                assert ref in verify_ids, (pb["rule_id"], br["id"], ref)
        assert pb["do_not"] and pb["fp_conditions"] and pb["sources"], pb["rule_id"]


def test_5712_success_check_comes_first():
    pb = next(p for p in _load() if p["rule_id"] == "5712")
    order = [v["id"] for v in pb["verify"]]
    assert order[:2] == ["V0", "V1"]  # V0 chỉ tìm t0; câu xác minh đầu tiên là V1
    assert "5715" in pb["verify"][1]["query"]
    assert "agent.id" in pb["facts"]


def test_verify_questions_name_their_rule_ids():
    # Model 7B chép gần nguyên văn trường question và bỏ query (A/B 2026-11-09),
    # nên question phải tự nêu rule ID thì next_steps mới có rule ID.
    for pb in filter(_complete, _load()):
        for v in pb["verify"]:
            ids = re.findall(r"\d+", " ".join(re.findall(r"rule\.id:\(?([\d\sor]+)\)?", v["query"])))
            if ids:
                assert any(re.search(rf"(?<!\d){i}(?!\d)", v["question"]) for i in ids), (pb["rule_id"], v["id"])


def test_rendered_fields_have_no_internal_labels():
    # question/time_range được code in thành bước đánh số 1..n; nhãn V0/V1 không còn ý nghĩa với analyst.
    for pb in filter(_complete, _load()):
        for v in pb["verify"]:
            for field in ("question", "time_range"):
                assert not re.search(r"\bV\d\b", str(v.get(field, ""))), (pb["rule_id"], v["id"], field)


def test_template_matches_real_playbook_schema():
    # docs/playbook_template.yaml phải luôn khớp schema của playbook thật (vd. 5760),
    # để người viết chép khuôn không bị lệch tên trường.
    template = yaml.safe_load((ROOT / "docs" / "playbook_template.yaml").read_text(encoding="utf-8"))[0]
    real = next(p for p in _load() if p["rule_id"] == "5760")
    assert set(template) == set(real)
    assert set(template["verify"][0]) == set(real["verify"][0])
    assert set(template["branches"][0]) == set(real["branches"][0])
    assert template["branches"][-1]["id"] == "B_unknown"
    placeholders = set(re.findall(r"<([a-z_]+)>", " ".join(v["query"] for v in template["verify"])))
    assert placeholders <= {"srcip", "agent_id", "user", "srcuser", "dstuser", "alert_time", "t0", "t_success"}
