import json
import sys
from pathlib import Path

import pytest

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


@pytest.mark.parametrize("rule_id", ["5760", "5503"])
def test_smoke_cli_distinguishes_proposal_effective_branch_and_fallback(monkeypatch, tmp_path, capsys, rule_id):
    import playbook_ab_smoke as smoke

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["host"] == "http://localhost:11434"

        def chat(self, **kwargs):
            payload = {"summary": "s", "root_cause": "c", "severity": "low", "mitre": ""}
            if "branch_id" in kwargs["format"]["properties"]:
                payload.update(branch_id="B5_typo", branch_evidence="unverified history")
            elif "signals" in kwargs["format"]["properties"]:
                payload.update(signals={}, severity=None)
            else:
                payload["next_steps"] = ["Review alert"]
            return {"message": {"content": json.dumps(payload)}}

    alert_path, out_path = tmp_path / "alert.json", tmp_path / "smoke.json"
    alert_path.write_text(json.dumps({
        "rule": {"id": rule_id, "level": 5}, "agent": {"id": "001"},
        "full_log": "pam_unix(su:auth): failure; ruser=www-data rhost= user=root",
    }), encoding="utf-8")
    cfg = {"ollama": {"model": "mock", "base_url": "http://localhost:11434"},
           "extractor": {"fields": ["rule.id", "rule.level", "agent.id", "full_log"]}}
    monkeypatch.setattr(smoke, "load_config", lambda: cfg)
    monkeypatch.setattr(smoke, "resolve_config_paths", lambda value: value)
    monkeypatch.setattr("llm.ollama_sdk.Client", Client)
    monkeypatch.setattr(sys, "argv", ["playbook_ab_smoke.py", "--alert", str(alert_path), "--out", str(out_path)])
    monkeypatch.setattr(sys.stdout, "reconfigure", lambda **kwargs: None)
    smoke.main()
    output = capsys.readouterr().out
    stored = json.loads(out_path.read_text(encoding="utf-8"))["C_trusted_playbook"]
    assert "nhánh model chọn" not in output
    if rule_id == "5760":
        assert "nhánh model đề xuất: B5_typo" in output
        assert "nhánh hiệu lực: B_unknown" in output
        assert stored["playbook"]["proposed_branch_id"] == "B5_typo"
    else:
        assert "nhánh CODE đề xuất điều tra: B0_service_account_su (chưa xác minh)" in output
        assert "origin=local_fallback" in output
        assert stored["analysis"]["severity"] == "high"
        assert stored["playbook"]["severity_source"] == "branch_regex"
