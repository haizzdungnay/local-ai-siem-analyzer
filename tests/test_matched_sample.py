"""matched_sample: con trỏ tới alert mẫu đầu tiên khớp nhánh đã chọn (không lộ đối số lệnh)."""
import string

import pytest

import analysis_service
import playbooks

SECRET = "Secret123"


def _sudo_log(letter, command):
    return (f"sudo: tester{letter} : TTY=pts/0 ; PWD=/home/tester ; USER=root ; COMMAND={command}")


def _hit(rule_id, full_log, timestamp, command=None, syscheck=None, **data):
    if command is not None:
        data["command"] = command
    source = {"timestamp": timestamp,
              "rule": {"id": rule_id, "level": 3, "description": f"rule {rule_id}"},
              "agent": {"id": "001", "name": "victim"}, "data": data, "full_log": full_log}
    if syscheck:
        source["syscheck"] = syscheck
    return {"_index": "wazuh-alerts", "_id": f"{rule_id}-{timestamp}", "_source": source}


def _sudo_aggregate(special_command="/bin/bash", special_index=7, other="/usr/bin/cat /var/log/syslog"):
    hits = []
    for i, letter in enumerate(string.ascii_lowercase[:20]):
        command = special_command if i == special_index else other
        hits.append(_hit("5402", _sudo_log(letter, command), f"2026-11-28T10:{i:02d}:00.000+0700",
                         command=command, srcuser=f"tester{letter}"))
    return analysis_service.aggregate_alerts(hits)


def _findings(aggregate):
    return analysis_service.window_playbook_findings(aggregate, playbooks.get_playbook, "en")


def test_5402_matched_sample_points_to_the_one_bash_sample():
    aggregate = _sudo_aggregate()
    assert len(aggregate["groups"][0]["playbook_samples"]) == 20
    finding = _findings(aggregate)[0]
    assert finding["rule_id"] == "5402" and finding["branch_id"] != playbooks.UNKNOWN_BRANCH
    assert finding["samples_matched"] == 1 and finding["samples_evaluated"] == 20
    assert finding["matched_sample"] == {"timestamp": "2026-11-28T10:07:00.000+0700",
                                         "command": "/bin/bash (0 args)"}


def test_matched_sample_tie_on_yes_count_keeps_the_earliest():
    # `cat /etc/sudoers.d/x` (S_security_change) và `/bin/bash` (S_root_shell) đều 1 tín hiệu "yes",
    # cùng nhánh B2: hòa thì giữ mẫu đến trước (mẫu 0).
    finding = _findings(_sudo_aggregate(other="/usr/bin/cat /etc/sudoers.d/x"))[0]
    assert finding["samples_matched"] == 20
    assert finding["matched_sample"] == {"timestamp": "2026-11-28T10:00:00.000+0700",
                                         "command": "/usr/bin/cat (1 args)"}


def test_matched_sample_prefers_sample_with_most_yes_signals():
    # `/bin/bash /etc/shadow` khớp cả S_root_shell và S_security_change (2 "yes") nên thắng mẫu đến trước.
    finding = _findings(_sudo_aggregate(special_command="/bin/bash /etc/shadow",
                                        other="/usr/bin/cat /etc/sudoers.d/x"))[0]
    assert finding["matched_sample"] == {"timestamp": "2026-11-28T10:07:00.000+0700",
                                         "command": "/bin/bash (1 args)"}


def test_matched_sample_is_the_first_of_several_matches():
    hits = [_hit("5402", _sudo_log(letter, "/bin/bash"), f"2026-11-28T10:0{i}:00.000+0700",
                 command="/bin/bash") for i, letter in enumerate("abc")]
    finding = _findings(analysis_service.aggregate_alerts(hits))[0]
    assert finding["samples_matched"] == 3
    assert finding["matched_sample"]["timestamp"] == "2026-11-28T10:00:00.000+0700"


def test_secret_args_absent_from_finding_prompt_and_priority_item():
    secret_command = f"/usr/bin/mysql -p{SECRET}"
    # full_log là sudo gọi bash (nhánh được chọn); data.command là lệnh có mật khẩu.
    hits = [_hit("5402", _sudo_log("a", "/bin/bash"), "2026-11-28T10:00:00.000+0700", command=secret_command)]
    aggregate = analysis_service.aggregate_alerts(hits)
    findings = _findings(aggregate)
    finding = next(f for f in findings if f["rule_id"] == "5402")
    assert finding["matched_sample"]["command"] == "/usr/bin/mysql (1 args)"
    finding = {**finding, "branch_id": "B1_x", "branch_severity": "high"}   # ép nhánh high cho block/priority
    block = analysis_service.format_playbook_branches_for_llm([finding], aggregate, playbooks.get_playbook)
    items = analysis_service.priority_hypotheses([finding], aggregate, "en", playbooks.get_playbook)
    assert SECRET not in repr(finding) and SECRET not in block and SECRET not in repr(items)
    assert "matched_at=2026-11-28T10:00:00.000_0700" in block   # _prompt_token đổi '+' thành '_'
    assert "mysql" not in block and "command" not in block
    assert items[0]["matched_sample"] == {"timestamp": "2026-11-28T10:00:00.000+0700",
                                          "command": "/usr/bin/mysql (1 args)"}


@pytest.mark.parametrize("raw,expected", [
    ("/bin/bash", "/bin/bash (0 args)"),
    ("/usr/bin/cat /etc/sudoers.d/x", "/usr/bin/cat (1 args)"),
    ("/usr/bin/mysql -pSecret123", "/usr/bin/mysql (1 args)"),
    ("PASS=hunter2 /bin/ls", "<unparsed> (1 args)"),
    ("", ""),
])
def test_summarize_command(raw, expected):
    assert playbooks.summarize_command(raw) == expected


def test_sensitive_playbook_5710_has_no_matched_sample():
    hit = _hit("5710", "sshd[1]: Failed password for invalid user Fake@Pass2026 from 203.0.113.9 port 1 ssh2",
               "2026-11-28T10:00:00.000+0700", srcip="203.0.113.9", srcuser="Fake@Pass2026")
    findings = _findings(analysis_service.aggregate_alerts([hit]))
    finding = next(f for f in findings if f["rule_id"] == "5710")
    assert "matched_sample" not in finding
    assert "Fake@Pass2026" not in repr(findings)


def test_unknown_branch_has_no_matched_sample():
    hit = _hit("5402", _sudo_log("a", "/usr/bin/cat /etc/hostname"), "2026-11-28T10:00:00.000+0700",
               command="/usr/bin/cat /etc/hostname")
    finding = _findings(analysis_service.aggregate_alerts([hit]))[0]
    assert finding["branch_id"] == playbooks.UNKNOWN_BRANCH
    assert "matched_sample" not in finding


def test_fim_group_matched_sample_has_path_and_timestamp_not_diff():
    diff = "1a2\n> lab_nouser ALL=(ALL) NOPASSWD: ALL"
    hit = _hit("550", "File '/etc/sudoers.d/99-lab' modified", "2026-11-28T11:00:00.000+0700",
               syscheck={"path": "/etc/sudoers.d/99-lab", "diff": diff})
    finding = _findings(analysis_service.aggregate_alerts([hit]))[0]
    assert finding["matched_sample"] == {"timestamp": "2026-11-28T11:00:00.000+0700",
                                         "syscheck_path": "/etc/sudoers.d/99-lab"}
    assert "NOPASSWD" not in repr(finding["matched_sample"])


def test_command_not_persisted_in_group_rows():
    import dashboard_store
    assert "command" in dashboard_store._GROUP_RAW_KEYS
