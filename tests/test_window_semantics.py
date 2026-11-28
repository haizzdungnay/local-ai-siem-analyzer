"""Khối nhánh playbook đọc được, chú giải kết quả rule, kiểm tra mâu thuẫn kết quả (job #282)."""
import pytest

import analysis_service
import dashboard_worker
import playbooks
from dashboard_store import DashboardStore
from overclaim import contradiction_check, find_contradictions

PAM_WWW = ("su[7]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 "
           "tty=pts/1 ruser=www-data rhost=  user=root")
SUDOERS_DIFF = "1a2\n> lab_nouser ALL=(ALL) NOPASSWD: ALL"
SUDOERS_LOG = ("File '/etc/sudoers.d/99-lab' modified\nMode: realtime\n"
               "Changed attributes: size,mtime,md5,sha1,sha256\nSize changed from '17' to '52'\n")
SSHD_LOG = "sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2"
ACCEPTED_LOG = "sshd[2]: Accepted password for root from 203.0.113.9 port 1 ssh2"


def _hit(rule_id, full_log, syscheck=None, **data):
    source = {"timestamp": "2026-11-25T17:00:00.000+0700",
              "rule": {"id": rule_id, "level": 5, "description": f"rule {rule_id}"},
              "agent": {"id": "001", "name": "victim-ubuntu"}, "data": data, "full_log": full_log}
    if syscheck:
        source["syscheck"] = syscheck
    return {"_index": "wazuh-alerts", "_id": f"id-{rule_id}", "_source": source}


def _cfg(tmp_path):
    return {"ollama": {"base_url": "http://localhost:11434", "allow_remote": False},
            "extractor": {"fields": []}, "rag": {"enabled": False, "data_dir": str(tmp_path)},
            "dashboard": {}, "playbooks": {"enabled": True}}


def _lab_aggregate():
    # medium (5760-style sshd) đứng trước trong aggregate; high B0 (5503 su www-data) phải lên đầu khối.
    hits = [
        _hit("550", SUDOERS_LOG, syscheck={"path": "/etc/sudoers.d/99-lab", "diff": SUDOERS_DIFF}),
        _hit("5503", PAM_WWW),
        _hit("5710", "sshd[1]: Failed password for invalid user Fake@Pass2026 from 203.0.113.9 port 1 ssh2",
             srcip="203.0.113.9", srcuser="Fake@Pass2026"),
        _hit("5715", ACCEPTED_LOG, srcip="203.0.113.9"),
    ]
    return analysis_service.aggregate_alerts(hits)


def _findings(aggregate):
    return analysis_service.window_playbook_findings(aggregate, playbooks.get_playbook, "en")


def test_block_has_human_branch_and_signal_text_high_first():
    aggregate = _lab_aggregate()
    findings = _findings(aggregate)
    # Ép thêm một nhánh medium đứng đầu danh sách để kiểm tra thứ tự theo mức nặng.
    medium = next(f for f in findings if f["rule_id"] == "5710")
    medium.update(branch_id="B4_x", branch_severity="medium")
    findings.sort(key=lambda f: f is not medium)
    block = analysis_service.format_playbook_branches_for_llm(findings, aggregate, playbooks.get_playbook)
    assert "Mention every high/critical branch below in key_findings as an unverified hypothesis" in block
    assert "UNVERIFIED" in block
    entry = playbooks.get_playbook("5503")
    when = next(b["when"] for b in entry["branches"] if b["id"] == "B0_service_account_su")
    # `when` mô tả kết quả truy vấn V1... chưa chạy: không được đưa vào khối.
    assert "V1 cho thấy su/sudo thất bại" not in block and " ".join(when.split())[:40] not in block
    assert "branch means" not in block
    assert "regex checks that matched: S_local_su_sudo" in block
    assert "verification queries have NOT been run" in block
    assert "not all of them" in block
    question = next(s["question"] for s in entry["signals"] if s["id"] == "S_service_actor")
    assert question[:50] in block
    assert block.index("branch=B0_service_account_su") < block.index("branch=B4_x")
    assert "Fake@Pass2026" not in block and "lab_nouser" not in block and "NOPASSWD: ALL" not in block
    assert "sample_log" not in block and "next_steps" not in block and "su[7]" not in block
    assert len(block) <= analysis_service.MAX_PLAYBOOK_PROMPT_CHARS
    assert len(block.splitlines()) <= analysis_service.MAX_PLAYBOOK_PROMPT_LINES + 1
    assert "\n\n" not in block


def test_block_sanitizes_yaml_whitespace_and_survives_lookup_failure():
    finding = {"rule_id": "9", "title": "T\nitle", "branch_id": "B1", "branch_severity": "high",
               "samples_matched": 1, "samples_evaluated": 1, "signals": {"S1": {"answer": "yes"}}}
    entry = {"branches": [{"id": "B1", "when": "dòng một\n\n  dòng   hai " + "x" * 400}],
             "signals": [{"id": "S1", "question": "câu\nhỏi " + "y" * 400}]}
    block = analysis_service.format_playbook_branches_for_llm([finding], None, lambda rid: entry)
    line = block.splitlines()[1]
    assert "dòng một" not in line and "câu hỏi" in line
    assert len(line) < 600
    broken = analysis_service.format_playbook_branches_for_llm(
        [finding], None, lambda rid: (_ for _ in ()).throw(RuntimeError("x")))
    assert "branch=B1" in broken


def test_high_branches_are_not_cut_by_budget():
    entry = {"branches": [{"id": "B1", "when": "w" * 300}],
             "signals": [{"id": "S1", "question": "q" * 300}]}
    findings = [{"rule_id": str(i), "title": "t", "branch_id": "B1", "branch_severity": sev,
                 "samples_matched": 1, "samples_evaluated": 1, "signals": {"S1": {"answer": "yes"}}}
                for i, sev in enumerate(["low"] * 11 + ["high"])]
    block = analysis_service.format_playbook_branches_for_llm(findings, None, lambda rid: entry)
    assert "severity=high" in block.splitlines()[1]
    assert len(block) <= analysis_service.MAX_PLAYBOOK_PROMPT_CHARS


def test_outcome_legend_lists_only_present_ids():
    aggregate = analysis_service.aggregate_alerts([
        _hit("5503", PAM_WWW), _hit("5760", SSHD_LOG, srcip="203.0.113.9"),
        _hit("5715", ACCEPTED_LOG, srcip="203.0.113.9")])
    legend = analysis_service.format_outcome_legend_for_llm(aggregate)
    failed, ok = legend.split("; ")
    assert "5503" in failed and "5760" in failed and "5715" not in failed
    assert "5715" in ok and "5503" not in ok
    assert "5303" not in legend and "5710" not in legend
    assert legend.endswith("Never describe a failure rule as a success.")
    assert len(legend) <= analysis_service.MAX_OUTCOME_LEGEND_CHARS
    assert analysis_service.format_outcome_legend_for_llm(
        analysis_service.aggregate_alerts([_hit("999999", "x")])) == ""


@pytest.mark.parametrize("text,flagged", [
    ("Sự kiện đăng nhập thành công từ IP 192.0.2.1 (rule 5503, 5760, 5715)", True),
    ("Đăng nhập thành công (rule 5715)", False),
    ("Đăng nhập không thành công (rule 5503)", False),
    ("Login succeeded (rule 5760)", True),
    ("Successful login from 203.0.113.9 (5503)", True),
    ("Đăng nhập thất bại (rule 5503), sau đó thành công (rule 5715)", False),
    ("Không có đăng nhập thành công; rule 5503 xuất hiện 8 lần", False),
    ("Phát hiện 5503 vào lúc 2026", False),
])
def test_find_contradictions(text, flagged):
    assert bool(find_contradictions(text)) is flagged


def test_contradiction_check_scans_nested_assessment_basis():
    result = {"summary": "ok", "key_findings": [],
              "assessment_basis": {"observed_facts": ["Sự kiện đăng nhập thành công (rule 5503, 5760)"]}}
    check = contradiction_check(result, {})
    assert check["status"] == "flagged" and len(check["clauses"]) == 1
    assert contradiction_check({"summary": "Đăng nhập thành công (rule 5715)"}, {})["status"] == "clean"


def _run(monkeypatch, tmp_path, aggregate, summary, prompts=None):
    def fake(prompt, **kwargs):
        if prompts is not None:
            prompts.append(prompt)
        return ({"summary": summary, "severity": "medium", "key_findings": [], "mitre": [],
                 "next_steps": []}, {"output_origin": "ollama_model"})
    monkeypatch.setattr(analysis_service, "analyze_window", fake)
    return analysis_service.AnalysisService(_cfg(tmp_path)).analyze_aggregate(aggregate, "qwen2.5:7b")


def test_analyze_aggregate_integration(monkeypatch, tmp_path):
    prompts = []
    text = "Đăng nhập thành công (rule 5503, 5715)"
    out = _run(monkeypatch, tmp_path, _lab_aggregate(), text, prompts)
    prov = out["provenance"]
    assert prov["contradiction_check"]["status"] == "flagged"
    assert prov["outcome_legend_chars"] > 0
    assert "Rule outcome legend" in prompts[0]
    assert prompts[0].index("Code-selected investigation branches") < prompts[0].index("Rule outcome legend")
    assert out["analysis"]["summary"] == text and out["analysis"]["severity"] == "medium"


def test_analyze_aggregate_without_known_rules_has_empty_legend(monkeypatch, tmp_path):
    aggregate = analysis_service.aggregate_alerts([_hit("999999", "x")])
    out = _run(monkeypatch, tmp_path, aggregate, "Không có gì")
    assert out["provenance"]["outcome_legend_chars"] == 0
    assert out["provenance"]["contradiction_check"]["status"] == "clean"


def test_worker_adds_contradiction_warning(tmp_path, monkeypatch):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job("manual_window", "2026-11-25T10:00:00.000Z", "2026-11-25T11:00:00.000Z",
                              "qwen2.5:7b", "manual-v1", language="vi", delivery_channel="none")

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi", **kwargs):
            return {"analysis": {"summary": "s", "severity": "medium", "key_findings": [],
                                 "mitre": [], "next_steps": []},
                    "coverage": {"truncated": False}, "partial": False,
                    "provenance": {"language_compliance": "full",
                                   "contradiction_check": {"status": "flagged", "clauses": ["x"]}}}

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service())
    monkeypatch.setattr(dashboard_worker, "fetch_alerts_range", lambda *a, **k: {
        "analysis_mode": "full", "total": 1, "timeline": [], "alerts": [_hit("5503", PAM_WWW)]})
    runtime._run_job(store.claim_next_job())
    assert "contradicts_rule_outcome" in store.get_job_detail(job_id)["results"][0]["warnings"]
