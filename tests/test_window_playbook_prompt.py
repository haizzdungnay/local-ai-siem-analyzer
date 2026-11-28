"""Nhánh playbook do code chọn được đưa vào prompt cửa sổ (không đổi severity, không lộ dữ liệu thô)."""
import analysis_service
import playbooks

SUDOERS_DIFF = "1a2\n> lab_nouser ALL=(ALL) NOPASSWD: ALL"
SUDOERS_LOG = ("File '/etc/sudoers.d/99-lab' modified\nMode: realtime\n"
               "Changed attributes: size,mtime,md5,sha1,sha256\nSize changed from '17' to '52'\n")


def _hit(rule_id, full_log, syscheck=None, **data):
    source = {
        "timestamp": "2026-11-25T17:00:00.000+0700",
        "rule": {"id": rule_id, "level": 7, "description": f"rule {rule_id}"},
        "agent": {"id": "001", "name": "victim-ubuntu"},
        "data": data, "full_log": full_log,
    }
    if syscheck:
        source["syscheck"] = syscheck
    return {"_index": "wazuh-alerts", "_id": f"id-{rule_id}", "_source": source}


def _service(tmp_path):
    cfg = {"ollama": {"base_url": "http://localhost:11434", "allow_remote": False},
           "extractor": {"fields": []}, "rag": {"enabled": False, "data_dir": str(tmp_path)},
           "dashboard": {}, "playbooks": {"enabled": True}}
    return analysis_service.AnalysisService(cfg)


def _fake_llm(monkeypatch, prompts, severity="low"):
    monkeypatch.setattr(analysis_service, "analyze_window", lambda prompt, **kwargs: (
        prompts.append(prompt) or {"summary": "s", "severity": severity, "key_findings": [],
                                   "mitre": [], "next_steps": []},
        {"output_origin": "ollama_model"},
    ))


def test_550_branch_is_in_prompt_but_diff_is_not(monkeypatch, tmp_path):
    prompts = []
    _fake_llm(monkeypatch, prompts)
    hit = _hit("550", SUDOERS_LOG, syscheck={"path": "/etc/sudoers.d/99-lab", "diff": SUDOERS_DIFF})
    aggregate = analysis_service.aggregate_alerts([hit])
    assert aggregate["groups"][0]["syscheck_diff"]            # diff có trong aggregate (bộ nhớ)
    output = _service(tmp_path).analyze_aggregate(aggregate, "qwen2.5:7b")
    prompt = prompts[0]
    assert "branch=B2_unverified_config_modification" in prompt
    assert "S_suspicious_diff_content" in prompt
    assert "UNVERIFIED hypotheses" in prompt
    assert "NOPASSWD" not in prompt
    assert output["provenance"]["playbook_prompt_chars"] > 0
    assert output["analysis"]["playbooks"][0]["branch_id"] == "B2_unverified_config_modification"


def test_helper_never_emits_user_or_diff_or_next_steps():
    log = "sshd[1]: Failed password for invalid user Fake@Pass2026 from 203.0.113.9 port 1 ssh2"
    sshd = _hit("5710", log, srcip="203.0.113.9", srcuser="Fake@Pass2026")
    sudoers = _hit("550", SUDOERS_LOG, syscheck={"path": "/etc/sudoers.d/99-lab", "diff": SUDOERS_DIFF})
    aggregate = analysis_service.aggregate_alerts([sshd, sudoers])
    findings = analysis_service.window_playbook_findings(
        aggregate, playbooks.get_playbook, "en")
    assert any(f["rule_id"] == "5710" for f in findings)
    # Ép 5710 thành nhánh đã chọn để chắc chắn khối không rò giá trị.
    for f in findings:
        if f["rule_id"] == "5710":
            f["branch_id"], f["branch_severity"] = "B4_x", "medium"
    block = analysis_service.format_playbook_branches_for_llm(findings, aggregate)
    assert "Fake@Pass2026" not in block and "NOPASSWD" not in block
    assert "next_steps" not in block and "sample_log" not in block
    assert "path=/etc/sudoers.d/99-lab" in block
    assert len(block) <= analysis_service.MAX_PLAYBOOK_PROMPT_CHARS
    assert len(block.splitlines()) <= analysis_service.MAX_PLAYBOOK_PROMPT_LINES + 1


def test_only_unknown_branches_add_no_block(monkeypatch, tmp_path):
    prompts = []
    _fake_llm(monkeypatch, prompts)
    cups = _hit("550", "File '/etc/cups/subscriptions.conf' modified\nMode: realtime\n",
                syscheck={"path": "/etc/cups/subscriptions.conf"})
    aggregate = analysis_service.aggregate_alerts([cups])
    output = _service(tmp_path).analyze_aggregate(aggregate, "qwen2.5:7b")
    assert output["analysis"]["playbooks"][0]["branch_id"] == "B_unknown"
    assert "Code-selected investigation branches" not in prompts[0]
    assert output["provenance"]["playbook_prompt_chars"] == 0
    assert analysis_service.format_playbook_branches_for_llm(output["analysis"]["playbooks"]) == ""


def test_severity_is_not_changed_by_playbook_branch(monkeypatch, tmp_path):
    prompts = []
    _fake_llm(monkeypatch, prompts, severity="low")
    hit = _hit("550", SUDOERS_LOG, syscheck={"path": "/etc/sudoers.d/99-lab", "diff": SUDOERS_DIFF})
    output = _service(tmp_path).analyze_aggregate(analysis_service.aggregate_alerts([hit]), "qwen2.5:7b")
    assert output["analysis"]["severity"] == "low"
