import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
import demo_lite  # noqa: E402


def test_demo_masks_ips_and_counts_evidence(tmp_path):
    ab = {"alert": "", "rule_id": "5712", "model": "m", "playbook_context": "srcip 10.1.2.3",
          "A_no_playbook": {"analysis": {"next_steps": ["Theo dõi IP 10.1.2.3"]}},
          "B_playbook": {"analysis": {"next_steps": ["Tìm 5715 cùng srcip 10.1.2.3", "Hỏi admin"]}}}
    page = demo_lite.build(ab)
    assert "10.1.2.3" not in page and "IP-1" in page
    assert "1/2 có rule ID" in page and "0/1 có rule ID" in page
    assert "1/2 bước xác minh" in page


def test_demo_shows_trusted_arm_when_present():
    arm = {"analysis": {"next_steps": ["Tìm 5715 từ 10.0.0.5"]}}
    page = demo_lite.build({"alert": "", "rule_id": "5712", "model": "m", "playbook_context": "",
                            "A_no_playbook": arm, "B_playbook": arm, "C_trusted_playbook": arm})
    assert "C — playbook TRUSTED" in page and "--n:3" in page
    assert "C 1/1" in page
