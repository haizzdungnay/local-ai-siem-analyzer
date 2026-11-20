"""Playbook trên dashboard (cửa sổ nhiều alert): code-only, không gọi thêm LLM (2026-11-20)."""
import copy
import json

import analysis_service
import playbooks

AGENT_ID, AGENT_NAME = "001", "victim-ubuntu"


def _hit(rule_id, full_log, **data):
    return {"_index": "wazuh-alerts", "_id": f"id-{rule_id}", "_source": {
        "timestamp": "2026-07-06T21:07:40.000+0700",
        "rule": {"id": rule_id, "level": 5, "description": f"rule {rule_id}"},
        "agent": {"id": AGENT_ID, "name": AGENT_NAME},
        "data": data, "full_log": full_log,
    }}


SUDO_BASH = _hit("5402", "sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
                 srcuser="deploy", dstuser="root")
SSH_ROOT = _hit("5760", "sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2",
                srcip="203.0.113.9", dstuser="root")


def _lookup(rule_id):
    return playbooks.get_playbook(rule_id)


def test_groups_carry_agent_id_users_and_sample_time():
    group = analysis_service.aggregate_alerts([SUDO_BASH])["groups"][0]
    assert group["agent_id"] == AGENT_ID and group["agent"] == AGENT_NAME
    assert group["srcuser"] == "deploy" and group["dstuser"] == "root"
    assert group["sample_timestamp"] == "2026-07-06T21:07:40.000+0700"


def test_window_findings_use_agent_id_not_name_and_regex_signals():
    aggregate = analysis_service.aggregate_alerts([SUDO_BASH, SSH_ROOT])
    findings = {f["rule_id"]: f for f in playbooks.window_playbook_findings(aggregate, _lookup)}
    sudo, ssh = findings["5402"], findings["5760"]
    assert sudo["branch_id"] == "B2_unusual_sudo_command_or_context"
    assert ssh["branch_id"] == "B3_guessing_no_success"
    assert sudo["signals"]["S_root_shell"] == {"answer": "yes", "rule_answer": "yes"}
    text = json.dumps(findings, ensure_ascii=False)
    assert f'agent.id:\\"{AGENT_ID}\\"' in text and f'agent.id:\\"{AGENT_NAME}\\"' not in text
    assert 'data.srcuser:\\"deploy\\"' in text           # sudo: người gọi, không phải root
    assert all(f["branch_verified"] is False for f in findings.values())
    assert "model:" not in " ".join(sudo["next_steps"])    # code-only: không có câu trả lời model


def test_aggregate_mode_without_full_log_stays_unknown():
    # Chế độ aggregate không tải full_log → regex 5402 không có dữ liệu → không chọn nhánh.
    aggregate = analysis_service.aggregate_alerts([SUDO_BASH])
    aggregate["groups"][0]["sample_log"] = ""
    aggregate["groups"][0]["playbook_samples"] = []     # aggregate mode: không có danh sách mẫu
    finding = playbooks.window_playbook_findings(aggregate, _lookup)[0]
    assert finding["branch_id"] == "B_unknown"
    assert finding["signals"]["S_root_shell"]["rule_answer"] is None


def test_window_findings_respect_limit_and_disabled_playbooks():
    hits = [SUDO_BASH, SSH_ROOT]
    aggregate = analysis_service.aggregate_alerts(hits)
    assert len(playbooks.window_playbook_findings(aggregate, _lookup, max_items=1)) == 1
    assert playbooks.window_playbook_findings(aggregate, lambda rule_id: None) == []


def test_sensitive_value_keeps_user_out_of_queries_and_signal_text():
    entry = copy.deepcopy(playbooks.get_playbook("5760"))
    entry["signals"].append({"id": "S_password_in_username", "question": "q?", "sensitive_value": True})
    extracted = {"agent.id": AGENT_ID, "data.srcip": "203.0.113.9", "data.dstuser": "Matkhau@2024"}
    answers = playbooks.normalize_signals(
        {"S_password_in_username": {"answer": "yes", "value": "Matkhau@2024"}}, entry, extracted)
    assert answers["S_password_in_username"]["value"] == playbooks.REDACTED_VALUE
    steps = playbooks.render_signal_next_steps(entry, extracted, answers, "B_unknown")
    text = " ".join(steps)
    assert "Matkhau@2024" not in text
    assert "&lt;user&gt;" not in text and '"<user>"' in text   # để analyst tự điền từ alert gốc
    assert 'data.srcip:"203.0.113.9"' in text                 # field khác vẫn được điền


def test_analyze_aggregate_attaches_playbooks_without_extra_llm_call(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(analysis_service, "analyze_window", lambda prompt, **kwargs: (
        calls.append(prompt) or {"summary": "s", "severity": "low", "key_findings": [],
                                 "mitre": [], "next_steps": []},
        {"output_origin": "ollama_model"},
    ))
    cfg = {"ollama": {"base_url": "http://localhost:11434", "allow_remote": False},
           "extractor": {"fields": []}, "rag": {"enabled": False, "data_dir": str(tmp_path)},
           "dashboard": {}, "playbooks": {"enabled": True}}
    aggregate = analysis_service.aggregate_alerts([SUDO_BASH])
    output = analysis_service.AnalysisService(cfg).analyze_aggregate(aggregate, "qwen2.5:7b")
    assert len(calls) == 1                                    # chỉ một lời gọi LLM cho cả cửa sổ
    assert output["analysis"]["severity"] == "low"            # không đổi severity của cửa sổ
    assert output["analysis"]["playbooks"][0]["branch_id"] == "B2_unusual_sudo_command_or_context"
    assert output["provenance"]["playbooks"][0]["rule_id"] == "5402"
    assert "deploy" not in calls[0].split("sample_log=")[0]   # user không vào prompt cửa sổ

    cfg["playbooks"]["enabled"] = False
    output = analysis_service.AnalysisService(cfg).analyze_aggregate(aggregate, "qwen2.5:7b")
    assert "playbooks" not in output["analysis"] and output["provenance"]["playbooks"] == []


def test_dashboard_renders_playbooks_with_text_only():
    from pathlib import Path
    web = Path(__file__).resolve().parents[1] / "ai_module" / "web"
    html = (web / "index.html").read_text(encoding="utf-8")
    js = (web / "app.js").read_text(encoding="utf-8")
    assert 'id="ai-playbooks"' in html and 'id="ai-playbooks-field"' in html
    body = js.split("function renderPlaybookFindings", 1)[1].split("\n}\n", 1)[0]
    assert "innerHTML" not in body and "text(item, value)" in body   # nội dung alert không thành HTML


# --- Lab 2026-11-20: hai lỗi thấy trên dashboard thật ---
SUDO_STATUS = _hit("5402", "sudo: trnguyn : TTY=pts/0 ; PWD=/home/x ; USER=root ; COMMAND=/usr/bin/systemctl status ssh",
                   srcuser="trnguyn", dstuser="root")
PAM_SSH = _hit("5503", "sshd[9]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root",
               dstuser="root")
PAM_WWW = _hit("5503", "su[7]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/1 ruser=www-data rhost=  user=root",
               dstuser="root")
CUPS = {"_index": "x", "_id": "cups", "_source": {
    "timestamp": "2026-11-20T19:14:48.566+0700", "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed."},
    "agent": {"id": AGENT_ID, "name": AGENT_NAME}, "syscheck": {"path": "/etc/cups/subscriptions.conf"},
    "full_log": "File '/etc/cups/subscriptions.conf' modified"}}


def test_dangerous_alert_later_in_group_is_not_hidden_by_first_sample():
    # 5503 SSH (đến trước) che 5503 www-data su (đến sau) khi chỉ dùng alert đầu tiên.
    aggregate = analysis_service.aggregate_alerts([PAM_SSH, PAM_WWW])
    group = aggregate["groups"][0]
    assert group["count"] == 2 and len(group["playbook_samples"]) == 2
    finding = playbooks.window_playbook_findings(aggregate, _lookup)[0]
    assert finding["branch_id"] == "B0_service_account_su"
    assert (finding["samples_evaluated"], finding["samples_matched"]) == (2, 1)
    assert "su[7]" not in " ".join(finding["next_steps"])    # full_log không bị in ra


def test_low_level_rule_with_branch_is_listed_before_high_level_unknown():
    # 550 CUPS (level 7) không được đẩy 5402 `sudo /bin/bash` (level 3) ra khỏi danh sách.
    aggregate = analysis_service.aggregate_alerts([CUPS, CUPS, PAM_SSH, SUDO_STATUS, SUDO_BASH])
    findings = playbooks.window_playbook_findings(aggregate, _lookup, max_items=2)
    assert aggregate["groups"][0]["rule_id"] == "550"         # Wazuh xếp theo level
    assert findings[0]["rule_id"] == "5402"                   # playbook xếp theo nhánh
    assert findings[0]["branch_id"] == "B2_unusual_sudo_command_or_context"


def test_repeated_identical_alerts_do_not_fill_all_sample_slots():
    burst = [_hit("5760", f"sshd[{i}]: Failed password for root from 203.0.113.9 port {4000 + i} ssh2",
                  srcip="203.0.113.9", dstuser="root") for i in range(30)]
    other = _hit("5760", "sshd[99]: Failed password for deploy from 203.0.113.9 port 9 ssh2",
                 srcip="203.0.113.9", dstuser="deploy")
    group = analysis_service.aggregate_alerts(burst + [other])["groups"][0]
    users = [sample["dstuser"] for sample in group["playbook_samples"]]
    assert users == ["root", "deploy"]                        # chỉ khác số → cùng một mẫu


def test_basis_text_matches_whether_a_branch_was_picked():
    aggregate = analysis_service.aggregate_alerts([PAM_SSH, PAM_WWW, CUPS])
    notes = {f["rule_id"] + f["branch_id"]: f["basis"] for f in playbooks.window_playbook_findings(aggregate, _lookup)}
    assert "1/2 alert khớp nhánh này" in notes["5503B0_service_account_su"]
    assert "không alert nào đủ dữ kiện" in notes["550B_unknown"]
    assert all("khác nhau" not in note for note in notes.values())
