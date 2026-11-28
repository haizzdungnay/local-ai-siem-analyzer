"""Kiểm tra overclaim: LLM khẳng định leo thang đã xác nhận khi nhánh playbook chưa xác minh."""
import unicodedata

import pytest

import analysis_service
import dashboard_worker
from dashboard_store import DashboardStore
from overclaim import find_overclaims

PAM_WWW = ("su[7]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 "
           "tty=pts/1 ruser=www-data rhost=  user=root")


@pytest.mark.parametrize("text,flagged", [
    ("Đã xác nhận leo thang đặc quyền lên root", True),
    ("Chưa xác nhận leo thang", False),
    ("Có dấu hiệu thử leo thang từ www-data", False),
    ("Không có 5303, nhưng đã xác nhận leo thang", True),
    ("su lên root thành công", True),
    ("Không rõ nguồn gốc su lên root thành công", True),
    ("Privilege escalation confirmed", True),
    ("Possible privilege escalation attempt", False),
    ("Privilege escalation was not confirmed", False),
    ("Không phát hiện leo thang thành công", False),
    ("Chưa có bằng chứng leo thang đặc quyền thành công", False),
    ("No evidence of successful privilege escalation", False),
    (unicodedata.normalize("NFD", "Đã xác nhận leo thang"), True),
])
def test_find_overclaims(text, flagged):
    assert bool(find_overclaims(text)["overclaims"]) is flagged


def test_failure_clause_is_info_only():
    found = find_overclaims("su không thành công lên root")
    assert found["overclaims"] == []
    assert found["failure_mentions"] == ["su không thành công lên root"]


def _hit(rule_id, full_log, **data):
    return {"_index": "wazuh-alerts", "_id": f"id-{rule_id}", "_source": {
        "timestamp": "2026-11-25T17:00:00.000+0700",
        "rule": {"id": rule_id, "level": 5, "description": f"rule {rule_id}"},
        "agent": {"id": "001", "name": "victim-ubuntu"}, "data": data, "full_log": full_log}}


def _run(monkeypatch, tmp_path, hits, summary, severity="medium"):
    monkeypatch.setattr(analysis_service, "analyze_window", lambda prompt, **kw: (
        {"summary": summary, "severity": severity, "key_findings": [], "mitre": [], "next_steps": []},
        {"output_origin": "ollama_model"}))
    cfg = {"ollama": {"base_url": "http://localhost:11434", "allow_remote": False},
           "extractor": {"fields": []}, "rag": {"enabled": False, "data_dir": str(tmp_path)},
           "dashboard": {}, "playbooks": {"enabled": True}}
    aggregate = analysis_service.aggregate_alerts(hits)
    return analysis_service.AnalysisService(cfg).analyze_aggregate(aggregate, "qwen2.5:7b")


CLAIM = "Đã xác nhận leo thang đặc quyền từ www-data lên root"


def test_flagged_without_changing_text_or_severity(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, [_hit("5503", PAM_WWW)], CLAIM)
    assert out["analysis"]["playbooks"][0]["branch_id"] == "B0_service_account_su"
    check = out["provenance"]["overclaim_check"]
    assert check["status"] == "flagged" and check["overclaims"]
    assert out["analysis"]["summary"] == CLAIM and out["analysis"]["severity"] == "medium"


def test_hedged_is_clean(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, [_hit("5503", PAM_WWW)], "Có dấu hiệu thử leo thang từ www-data")
    assert out["provenance"]["overclaim_check"]["status"] == "clean"


def test_success_evidence_skips(monkeypatch, tmp_path):
    hits = [_hit("5503", PAM_WWW), _hit("5303", "su[7]: pam_unix(su:session): session opened for user root")]
    out = _run(monkeypatch, tmp_path, hits, CLAIM)
    assert out["provenance"]["overclaim_check"]["status"] == "skipped_success_evidence"


def test_only_unknown_branches_not_applicable(monkeypatch, tmp_path):
    cups = _hit("550", "File '/etc/cups/subscriptions.conf' modified\nMode: realtime\n")
    cups["_source"]["syscheck"] = {"path": "/etc/cups/subscriptions.conf"}
    out = _run(monkeypatch, tmp_path, [cups], CLAIM)
    assert out["provenance"]["overclaim_check"]["status"] == "not_applicable"


def test_worker_adds_warning_when_flagged(tmp_path, monkeypatch):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job("manual_window", "2026-11-25T10:00:00.000Z", "2026-11-25T11:00:00.000Z",
                              "qwen2.5:7b", "manual-v1", language="vi", delivery_channel="none")

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi", **kwargs):
            return {"analysis": {"summary": CLAIM, "severity": "medium", "key_findings": [],
                                 "mitre": [], "next_steps": []},
                    "coverage": {"truncated": False}, "partial": False,
                    "provenance": {"language_compliance": "full",
                                   "overclaim_check": {"status": "flagged", "overclaims": [CLAIM],
                                                       "failure_mentions": []}}}

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service())
    monkeypatch.setattr(dashboard_worker, "fetch_alerts_range", lambda *a, **k: {
        "analysis_mode": "full", "total": 1, "timeline": [],
        "alerts": [_hit("5503", PAM_WWW)]})
    runtime._run_job(store.claim_next_job())
    result = store.get_job_detail(job_id)["results"][0]
    assert "overclaim_unverified_branch" in result["warnings"]
