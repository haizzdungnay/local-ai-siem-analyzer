"""Giả thuyết ưu tiên do code dựng (job #283: LLM 7B bỏ qua nhánh B0 high dù prompt yêu cầu)."""
import copy

import analysis_service
import dashboard_reports
import dashboard_worker
import playbooks
from dashboard_store import DashboardStore
from gmail_notifier import render_gmail_report
from telegram_notifier import render_report, render_summary_report
from telegram_pdf import build_pdf_view

PAM_WWW = ("su[7]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 "
           "tty=pts/1 ruser=www-data rhost=  user=root")
SUDOERS_DIFF = "1a2\n> lab_nouser ALL=(ALL) NOPASSWD: ALL"
SUDOERS_LOG = ("File '/etc/sudoers.d/99-lab' modified\nMode: realtime\n"
               "Changed attributes: size,mtime,md5,sha1,sha256\nSize changed from '17' to '52'\n")
FAKE_PASS = "Fake@Pass2026"
VI_TITLE = "Giả thuyết ưu tiên (code, chưa xác minh)"
EN_TITLE = "Priority hypotheses (code, unverified)"


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


def _aggregate():
    return analysis_service.aggregate_alerts([
        _hit("550", SUDOERS_LOG, syscheck={"path": "/etc/sudoers.d/99-lab", "diff": SUDOERS_DIFF}),
        _hit("5503", PAM_WWW),
        _hit("5710", f"sshd[1]: Failed password for invalid user {FAKE_PASS} from 203.0.113.9 port 1 ssh2",
             srcip="203.0.113.9", srcuser=FAKE_PASS),
    ])


def _run(monkeypatch, tmp_path, aggregate, language="vi", summary="Không nhắc gì đến su"):
    def fake(prompt, **kwargs):
        return ({"summary": summary, "severity": "medium", "key_findings": ["x"], "mitre": [],
                 "next_steps": []}, {"output_origin": "ollama_model"})
    monkeypatch.setattr(analysis_service, "analyze_window", fake)
    return analysis_service.AnalysisService(_cfg(tmp_path)).analyze_aggregate(
        aggregate, "qwen2.5:7b", language=language)


def test_only_high_branch_present_even_if_llm_omits_it(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, _aggregate())
    items = out["analysis"]["priority_hypotheses"]
    assert [(i["rule_id"], i["branch_id"], i["severity"]) for i in items] == \
        [("5503", "B0_service_account_su", "high")]
    item = items[0]
    assert item["status"] == "unverified"
    assert item["samples_matched"] == item["samples_evaluated"] == 1
    assert item["first_seen"] and item["last_seen"]
    assert "S_local_su_sudo" in item["signals_yes"] and "S_service_actor" in item["signals_yes"]
    assert out["provenance"]["priority_hypotheses_count"] == 1
    assert out["analysis"]["summary"] == "Không nhắc gì đến su"
    assert out["analysis"]["severity"] == "medium" and out["analysis"]["key_findings"] == ["x"]
    blob = str(out["analysis"]["priority_hypotheses"])
    assert FAKE_PASS not in blob and "lab_nouser" not in blob and "ruser=" not in blob
    assert "5503" in item["text"] and "B0_service_account_su (high)" in item["text"]
    assert item["text"].startswith("Giả thuyết ưu tiên (chưa xác minh)")


def test_english_text_and_empty_when_no_high(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, _aggregate(), language="en")
    assert out["analysis"]["priority_hypotheses"][0]["text"].startswith("Priority hypothesis (unverified)")
    out = _run(monkeypatch, tmp_path, analysis_service.aggregate_alerts([_hit("999999", "x")]))
    assert "priority_hypotheses" not in out["analysis"]
    assert out["provenance"]["priority_hypotheses_count"] == 0


def _finding(rule, severity, branch="B1_x", group_key="k"):
    return {"rule_id": rule, "title": "T", "group_key": group_key, "group_count": 3, "branch_id": branch,
            "branch_severity": severity, "samples_evaluated": 3, "samples_matched": 2, "signals": {}}


def test_ordering_critical_first_and_cap():
    findings = [_finding(str(i), "high") for i in range(12)] + [_finding("c", "critical"),
                                                                  _finding("m", "medium"),
                                                                  _finding("u", "unknown", "B_unknown")]
    items = analysis_service.priority_hypotheses(findings, {}, "vi")
    assert len(items) == 10 and items[0]["rule_id"] == "c" and items[0]["severity"] == "critical"
    assert all(i["severity"] in ("critical", "high") for i in items)


def test_sensitive_playbook_drops_path():
    aggregate = {"groups": [{"group_key": "k", "syscheck_path": "/secret/path"}]}
    finding = _finding("5710", "high")
    items = analysis_service.priority_hypotheses(
        [finding], aggregate, "vi", lambda rid: {"signals": [{"sensitive_value": True}]})
    assert items[0]["syscheck_path"] == ""
    items = analysis_service.priority_hypotheses([finding], aggregate, "vi", lambda rid: {"signals": []})
    assert items[0]["syscheck_path"] == "/secret/path"


def _result(out):
    return out["analysis"]


def test_persisted_and_returned_by_job_detail(tmp_path, monkeypatch):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job("manual_window", "2026-11-25T10:00:00.000Z", "2026-11-25T11:00:00.000Z",
                              "qwen2.5:7b", "manual-v1", language="vi", delivery_channel="none")
    service = analysis_service.AnalysisService(_cfg(tmp_path))
    monkeypatch.setattr(analysis_service, "analyze_window", lambda prompt, **kw: (
        {"summary": "s", "severity": "medium", "key_findings": ["x"], "mitre": [], "next_steps": []},
        {"output_origin": "ollama_model"}))
    runtime = dashboard_worker.DashboardRuntime(store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, service)
    monkeypatch.setattr(dashboard_worker, "fetch_alerts_range", lambda *a, **k: {
        "analysis_mode": "full", "total": 2, "timeline": [],
        "alerts": [_hit("5503", PAM_WWW), _hit("550", SUDOERS_LOG, syscheck={"path": "/etc/sudoers.d/99-lab"})]})
    runtime._run_job(store.claim_next_job())
    detail = store.get_job_detail(job_id)
    result = detail["results"][0]["result"]
    assert [i["rule_id"] for i in result["priority_hypotheses"]] == ["5503"]
    assert result["playbooks"]
    report = dashboard_reports._job_report(detail, "v2")
    assert report["analysis"]["priority_hypotheses"][0]["branch_id"] == "B0_service_account_su"


def _job(language="vi", hypotheses=True):
    result = {"severity": "medium", "confidence": 0.5, "summary": "AI summary", "key_findings": ["kf"],
              "mitre": [], "next_steps": ["n"]}
    if hypotheses:
        result["priority_hypotheses"] = [
            {"text": "Giả thuyết ưu tiên (chưa xác minh): rule 5503 <b>&</b> *x*", "rule_id": "5503"},
            "not-a-dict",
        ]
    return {"id": 7, "status": "succeeded", "window_start": "a", "window_end": "b", "model": "m",
            "language": language, "metrics": {"total_alerts": 1}, "timeline": [], "groups": [],
            "results": [{"scope": "window", "result": result, "warnings": []}]}


def test_gmail_and_telegram_report_sections():
    plain, html_body, _ = render_gmail_report(_job())
    assert VI_TITLE in plain and plain.index(VI_TITLE) < plain.index("Summary: AI summary")
    assert "&lt;b&gt;&amp;&lt;/b&gt;" in html_body and "<b>&</b>" not in html_body
    assert html_body.index(VI_TITLE) < html_body.index(">Summary<")
    plain_en, html_en, _ = render_gmail_report(_job("en"))
    assert EN_TITLE in plain_en and EN_TITLE in html_en
    text, _ = render_report(_job())
    assert VI_TITLE in text
    summary, _ = render_summary_report(_job())
    assert VI_TITLE in summary and summary.index(VI_TITLE) < summary.index("Summary: AI summary")
    for body in (render_gmail_report(_job(hypotheses=False))[0], render_gmail_report(_job(hypotheses=False))[1],
                 render_report(_job(hypotheses=False))[0], render_summary_report(_job(hypotheses=False))[0]):
        assert VI_TITLE not in body and EN_TITLE not in body


def test_pdf_view_section_first_and_omitted_when_empty():
    view = build_pdf_view(_job())
    assert view["sections"][0][0] == VI_TITLE and "5503" in view["sections"][0][1][0]
    assert build_pdf_view(_job("en"))["sections"][0][0] == EN_TITLE
    assert all(title not in (VI_TITLE, EN_TITLE) for title, _ in build_pdf_view(_job(hypotheses=False))["sections"])
