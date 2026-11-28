"""Hồi quy lấy từ lab 2026-11-25 (docs/lab-run-2026-11-25.md): tín hiệu 550, 5710, 100121.

Giá trị full_log/syscheck.diff chép từ alert thật trên lab; IP thay bằng dải tài liệu (RFC 5737).
"""
import analysis_service
import playbooks

AGENT_ID = "001"
ATTACKER = "203.0.113.30"


def _answers(rule_id, extracted, model=None):
    entry = playbooks.get_playbook(rule_id)
    answers = playbooks.normalize_signals(model or {}, entry, extracted)
    return entry, answers, playbooks.select_branch(entry, answers)


def _fim(path, full_log, diff=None):
    extracted = {"agent.id": AGENT_ID, "syscheck.path": path, "full_log": full_log}
    if diff is not None:
        extracted["syscheck.diff"] = diff
    return extracted


# ---- 550 ----------------------------------------------------------------------------------------

CUPS_LOG = ("File '/etc/cups/subscriptions.conf' modified\nMode: realtime\n"
            "Changed attributes: inode,mtime,md5,sha1,sha256\n")


def test_550_cups_periodic_rewrite_is_negative():
    _, answers, branch = _answers("550", _fim("/etc/cups/subscriptions.conf", CUPS_LOG))
    assert answers["S_critical_path"]["rule_answer"] == "no"
    assert answers["S_suid_sgid_added"]["rule_answer"] == "no"
    assert answers["S_suspicious_diff_content"]["rule_answer"] is None   # không có diff → không kết luận
    assert branch == "B_unknown"


def test_550_sudoers_nopasswd_added_line_selects_b2():
    log = ("File '/etc/sudoers.d/99-lab' modified\nMode: realtime\n"
           "Changed attributes: size,mtime,md5,sha1,sha256\nSize changed from '17' to '52'\n")
    diff = "1a2\n> lab_nouser ALL=(ALL) NOPASSWD: ALL"
    _, answers, branch = _answers("550", _fim("/etc/sudoers.d/99-lab", log, diff))
    assert answers["S_critical_path"]["rule_answer"] == "yes"
    assert answers["S_suspicious_diff_content"]["rule_answer"] == "yes"
    assert branch == "B2_unverified_config_modification"


def test_550_reverse_shell_added_to_service_matches_only_the_added_line():
    diff = ('2c2\n< ExecStart=/bin/true\n---\n'
            '> ExecStart=/bin/bash -c "bash -i >& /dev/tcp/127.0.0.1/9 0>&1"')
    _, answers, _ = _answers("550", _fim("/etc/systemd/system/lab.service", "x", diff))
    assert answers["S_suspicious_diff_content"]["rule_answer"] == "yes"


def test_550_removing_a_backdoor_line_is_not_flagged_by_diff_signal():
    # Admin gỡ dòng reverse shell: dòng độc nằm ở '<' (đã xóa) → tín hiệu diff phải là "không".
    diff = ('2c2\n< ExecStart=/bin/bash -c "bash -i >& /dev/tcp/127.0.0.1/9 0>&1"\n---\n'
            '> ExecStart=/bin/true')
    _, answers, branch = _answers("550", _fim("/opt/app/run.conf", "x", diff))
    assert answers["S_suspicious_diff_content"]["rule_answer"] == "no"
    assert branch == "B_unknown"


def test_550_suid_turned_on_selects_b2():
    log = ("File '/usr/bin/lab-ls' modified\nMode: realtime\nChanged attributes: permission\n"
           "Permissions changed from 'rwxr-xr-x' to 'rwsr-xr-x'\n")
    _, answers, branch = _answers("550", _fim("/usr/bin/lab-ls", log))
    assert answers["S_suid_sgid_added"]["rule_answer"] == "yes"
    assert branch == "B2_unverified_config_modification"


def test_550_touch_on_binary_that_already_has_suid_is_not_flagged():
    # perm_after vẫn là rwsr-xr-x nhưng quyền không đổi: regex cũ trên perm_after báo nhầm.
    log = ("File '/usr/bin/passwd' modified\nMode: realtime\nChanged attributes: mtime\n"
           "Old modification time was: '1707224063', now it is '1795610616'\n")
    _, answers, branch = _answers("550", _fim("/usr/bin/passwd", log))
    assert answers["S_suid_sgid_added"]["rule_answer"] == "no"
    assert branch == "B_unknown"


# ---- 5710 ---------------------------------------------------------------------------------------

def test_5710_password_like_username_is_redacted_everywhere():
    extracted = {"agent.id": AGENT_ID, "data.srcip": ATTACKER, "data.srcuser": "Fake@Pass2026"}
    entry, answers, branch = _answers(
        "5710", extracted, {"S_password_in_username": {"answer": "yes", "value": "Fake@Pass2026"}})
    assert branch == "B4_password_in_username"
    assert answers["S_password_in_username"]["value"] == playbooks.REDACTED_VALUE
    text = " ".join(playbooks.render_signal_next_steps(entry, extracted, answers, branch))
    assert "Fake@Pass2026" not in text
    assert f'data.srcip:"{ATTACKER}"' in text


def test_5710_typo_without_model_answer_stays_unknown():
    # Không có regex cho "trông giống mật khẩu": dashboard (không gọi LLM) không bao giờ chọn B4.
    _, answers, branch = _answers("5710", {"agent.id": AGENT_ID, "data.srcuser": "trnguy"})
    assert answers["S_password_in_username"]["rule_answer"] is None
    assert branch == "B_unknown"


# ---- 100121 -------------------------------------------------------------------------------------

def _access(ua):
    return (f'{ATTACKER} - - [25/Nov/2026:19:47:35 +0700] "POST /DVWA/login.php HTTP/1.1" '
            f'302 888 "-" "{ua}"')


def test_100121_scripted_client_selects_automated_guessing():
    for ua in ("curl/8.18.0", "python-requests/2.31", "Mozilla/4.0 (Hydra)"):
        _, _, branch = _answers("100121", {"agent.id": AGENT_ID, "full_log": _access(ua)})
        assert branch == "B2_automated_guessing", ua


def test_100121_browser_user_agent_stays_unknown():
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
    _, answers, branch = _answers("100121", {"agent.id": AGENT_ID, "full_log": _access(ua)})
    assert answers["S_scripted_client"]["rule_answer"] == "no"
    assert branch == "B_unknown"


# ---- dashboard: syscheck.diff đi theo mẫu nhóm ---------------------------------------------------

def _fim_hit(path, diff, full_log="File modified\nMode: realtime\n"):
    return {"_index": "wazuh-alerts", "_id": "fim-1", "_source": {
        "timestamp": "2026-11-25T19:33:13.671+0700",
        "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed."},
        "agent": {"id": AGENT_ID, "name": "victim"},
        "syscheck": {"path": path, "diff": diff}, "full_log": full_log,
    }}


def test_dashboard_group_carries_syscheck_diff_to_signals_but_not_prompt():
    diff = "1a2\n> lab_nouser ALL=(ALL) NOPASSWD: ALL"
    aggregate = analysis_service.aggregate_alerts([_fim_hit("/opt/app/conf", diff)])
    finding = playbooks.window_playbook_findings(aggregate, playbooks.get_playbook)[0]
    assert finding["branch_id"] == "B2_unverified_config_modification"   # chỉ nhờ diff (path không trọng yếu)
    prompt = analysis_service.format_window_for_llm(aggregate)
    assert "NOPASSWD" not in prompt


def test_dashboard_truncated_diff_is_treated_as_missing():
    diff = "1a2\n" + "> # padding\n" * 400 + "> lab_nouser ALL=(ALL) NOPASSWD: ALL"
    assert len(diff) > analysis_service.MAX_PLAYBOOK_DIFF_CHARS
    aggregate = analysis_service.aggregate_alerts([_fim_hit("/opt/app/conf", diff)])
    finding = playbooks.window_playbook_findings(aggregate, playbooks.get_playbook)[0]
    assert finding["branch_id"] == "B_unknown"
