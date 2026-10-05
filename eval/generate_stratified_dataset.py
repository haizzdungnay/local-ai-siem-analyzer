"""eval/generate_stratified_dataset.py — Khung sinh bộ dữ liệu đánh giá phân tầng (F-07).

Sinh tập dữ liệu alert giả lập (synthetic stratified dataset) quy mô ~370 ca
phục vụ kiểm định thống kê McNemar (power >= 0.8) mà không cần kết nối Wazuh live.
Không ghi đè eval/cases/ và eval/expected/ hiện có.
"""

import argparse
import json
import random
from pathlib import Path


SEVERITY_TEMPLATES = {
    "critical": [
        {
            "scenario": "ransomware_encryption",
            "rule": {"id": "100201", "level": 15, "description": "Ransomware file encryption activity detected."},
            "data": {"file": "C:\\Users\\victim\\Documents\\report.docx.locked", "process": "vssadmin.exe"},
            "mitre": {"id": ["T1486"], "tactics": ["Impact"]},
            "log_tmpl": "Mass file modification with encrypted extension (.locked) and shadow copies deletion attempt by PID {pid}.",
            "summary": "Ransomware đang mã hóa dữ liệu hàng loạt và cố gắng xóa shadow copies.",
            "root_cause": "Mã độc ransomware thực thi lệnh mã hóa và gọi vssadmin xóa bản sao lưu phục hồi.",
            "facts": ["Ransomware file encryption activity detected.", "shadow copies deletion attempt"],
            "steps": ["Cô lập ngay lập tức máy trạm khỏi mạng", "Bảo toàn bộ nhớ RAM phục vụ điều tra số"]
        },
        {
            "scenario": "credential_dumping_mimikatz",
            "rule": {"id": "100202", "level": 14, "description": "LSASS memory access indicating credential dumping."},
            "data": {"target_process": "lsass.exe", "source_process": "mimikatz.exe", "access_mask": "0x1010"},
            "mitre": {"id": ["T1003.001"], "tactics": ["Credential Access"]},
            "log_tmpl": "Process 'mimikatz.exe' granted PROCESS_VM_READ access to 'lsass.exe' under user NT AUTHORITY\\SYSTEM.",
            "summary": "Phát hiện hành vi trích xuất thông tin xác thực từ tiến trình LSASS.",
            "root_cause": "Công cụ trích xuất bộ nhớ (Mimikatz) truy cập trái phép bộ nhớ của Local Security Authority.",
            "facts": ["LSASS memory access indicating credential dumping.", "PROCESS_VM_READ access to 'lsass.exe'"],
            "steps": ["Thu hồi toàn bộ tài khoản quản trị đăng nhập trên máy", "Cô lập thiết bị và rà quét lateral movement"]
        },
        {
            "scenario": "c2_reverse_shell_active",
            "rule": {"id": "100203", "level": 14, "description": "Active reverse shell communication to external C2."},
            "data": {"dst_ip": "203.0.113.88", "dst_port": 4444, "process": "/bin/bash"},
            "mitre": {"id": ["T1059.004", "T1071"], "tactics": ["Execution", "Command and Control"]},
            "log_tmpl": "Interactive Bash session established outbound connection to external IP 203.0.113.88:4444 without TTY.",
            "summary": "Phát hiện reverse shell tương tác ra máy chủ C2 bên ngoài.",
            "root_cause": "Tiến trình bash được khởi tạo từ web application hoặc reverse shell payload.",
            "facts": ["Active reverse shell communication to external C2.", "Interactive Bash session established outbound connection"],
            "steps": ["Chặn IP đích trên tường lửa biên", "Terminate tiến trình reverse shell và cô lập endpoint"]
        }
    ],
    "high": [
        {
            "scenario": "rootcheck_trojan_binary",
            "rule": {"id": "510", "level": 12, "description": "Host-based anomaly detection event (rootcheck)."},
            "data": {"file": "/usr/bin/diff", "title": "Trojaned version of file detected."},
            "mitre": {"id": ["T1574.006"], "tactics": ["Persistence"]},
            "log_tmpl": "Trojaned version of file '{file}' detected by signature match in rootcheck audit.",
            "summary": "Rootcheck phát hiện nghi vấn file hệ thống bị trojan hóa.",
            "root_cause": "Chữ ký rootcheck khớp với binary hệ thống; cần xác thực tính toàn vẹn gói.",
            "facts": ["Host-based anomaly detection event (rootcheck).", "Trojaned version of file detected."],
            "steps": ["Xác minh checksum với package manager gốc", "So sánh hash binary trước khi cô lập"]
        },
        {
            "scenario": "brute_force_threshold_exceeded",
            "rule": {"id": "5712", "level": 12, "description": "sshd: brute force trying to get access to the system."},
            "data": {"srcip": "10.0.0.50", "dstuser": "root"},
            "mitre": {"id": ["T1110.001"], "tactics": ["Credential Access"]},
            "log_tmpl": "Multiple failed SSH logins (count: {count}) within 60s from source IP 10.0.0.50.",
            "summary": "Tấn công dò quét mật khẩu SSH brute-force vượt ngưỡng cảnh báo.",
            "root_cause": "Nguồn IP cố gắng đăng nhập lặp đi lặp lại nhiều lần vào tài khoản đặc quyền.",
            "facts": ["sshd: brute force trying to get access to the system.", "Multiple failed SSH logins"],
            "steps": ["Chặn địa chỉ IP nguồn trên firewall", "Kiểm tra xem có lần đăng nhập thành công nào sau đó không"]
        },
        {
            "scenario": "weaponized_cve_exploit",
            "rule": {"id": "100204", "level": 13, "description": "Web vulnerability exploitation attempt matching CVE signature."},
            "data": {"uri": "/cgi-bin/test.cgi?cmd=id", "status": 200},
            "mitre": {"id": ["T1190"], "tactics": ["Initial Access"]},
            "log_tmpl": "HTTP request matching known RCE exploit pattern targeting Apache HTTP server.",
            "summary": "Nỗ lực khai thác lỗ hổng Web RCE có chữ ký CVE đã biết.",
            "root_cause": "Yêu cầu HTTP chứa payload chèn lệnh hệ thống vào script CGI.",
            "facts": ["Web vulnerability exploitation attempt matching CVE signature."],
            "steps": ["Kiểm tra response code và access log để xác định khai thác thành công hay thất bại", "Cập nhật bản vá web server"]
        }
    ],
    "medium": [
        {
            "scenario": "agent_stoppage",
            "rule": {"id": "506", "level": 8, "description": "Wazuh agent stopped or disconnected."},
            "data": {"status": "disconnected"},
            "mitre": {"id": ["T1562.001"], "tactics": ["Defense Evasion"]},
            "log_tmpl": "Wazuh agent daemon on endpoint '{agent}' stopped unexpectedly.",
            "summary": "Agent giám sát bảo mật bị dừng hoặc ngắt kết nối bất thường.",
            "root_cause": "Tiến trình giám sát endpoint bị tắt do bảo trì hoặc can thiệp dịch vụ.",
            "facts": ["Wazuh agent stopped or disconnected."],
            "steps": ["Kiểm tra trạng thái kết nối mạng của agent", "Xác nhận lịch bảo trì với quản trị viên endpoint"]
        },
        {
            "scenario": "single_root_ssh_failure",
            "rule": {"id": "5760", "level": 5, "description": "sshd: Failed attempt to login using root account."},
            "data": {"srcip": "10.0.0.60", "dstuser": "root"},
            "mitre": {"id": ["T1078.003"], "tactics": ["Initial Access"]},
            "log_tmpl": "Failed password for root from 10.0.0.60 port {port} ssh2.",
            "summary": "Một lần thử đăng nhập thất bại vào tài khoản root qua SSH.",
            "root_cause": "Người dùng hoặc tiến trình thử mật khẩu sai cho tài khoản root.",
            "facts": ["Failed attempt to login using root account."],
            "steps": ["Kiểm tra xem có chuỗi thử tiếp diễn không", "Đảm bảo PermitRootLogin đã được vô hiệu hóa"]
        },
        {
            "scenario": "suspicious_powershell_download",
            "rule": {"id": "91540", "level": 8, "description": "PowerShell command execution with encoded or download syntax."},
            "data": {"command": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass"},
            "mitre": {"id": ["T1059.001"], "tactics": ["Execution"]},
            "log_tmpl": "PowerShell spawned with hidden window and execution policy bypass flags.",
            "summary": "Thực thi PowerShell với cờ ẩn cửa sổ và vượt qua chính sách thực thi.",
            "root_cause": "Script hoặc người dùng gọi PowerShell với tham số thường dùng bởi công cụ tấn công.",
            "facts": ["PowerShell command execution with encoded or download syntax."],
            "steps": ["Kiểm tra tiến trình cha đã gọi PowerShell", "Xem xét nội dung script đầy đủ trong ScriptBlock log"]
        }
    ],
    "low": [
        {
            "scenario": "solved_cve_package_update",
            "rule": {"id": "23502", "level": 3, "description": "Vulnerability solved in package update."},
            "data": {"package": "openssl", "cve": "CVE-2024-0001"},
            "mitre": {"id": [], "tactics": []},
            "log_tmpl": "Vulnerability CVE-2024-0001 in package {package} has been marked as solved following system update.",
            "summary": "Thông báo lỗ hổng CVE đã được giải quyết qua bản cập nhật gói hệ thống.",
            "root_cause": "Hệ thống quản lý lỗ hổng ghi nhận gói phần mềm đã được nâng cấp bản vá.",
            "facts": ["Vulnerability solved in package update."],
            "steps": ["Không yêu cầu hành động xử lý sự cố; tiếp tục theo dõi thường quy"]
        },
        {
            "scenario": "normal_user_login",
            "rule": {"id": "5501", "level": 3, "description": "Login session opened for local user."},
            "data": {"user": "analyst"},
            "mitre": {"id": [], "tactics": []},
            "log_tmpl": "PAM session opened for user analyst by (uid=0).",
            "summary": "Phiên làm việc người dùng cục bộ được mở thành công.",
            "root_cause": "Người dùng đăng nhập bình thường vào hệ thống.",
            "facts": ["Login session opened for local user."],
            "steps": ["Hoạt động vận hành thông thường, không cần hành động can thiệp"]
        },
        {
            "scenario": "routine_cron_job",
            "rule": {"id": "5402", "level": 3, "description": "Successful sudo or cron task execution."},
            "data": {"command": "/usr/sbin/logrotate"},
            "mitre": {"id": [], "tactics": []},
            "log_tmpl": "Cron task /usr/sbin/logrotate executed successfully by root.",
            "summary": "Tác vụ định kỳ hệ thống (cron) thực thi thành công.",
            "root_cause": "Tiến trình cron định kỳ kích hoạt lệnh quản trị định kỳ.",
            "facts": ["Successful sudo or cron task execution."],
            "steps": ["Hoạt động quản trị định kỳ thông thường"]
        }
    ]
}


def generate_case(case_idx: int, severity: str, rng: random.Random) -> tuple[dict, dict]:
    tmpl = rng.choice(SEVERITY_TEMPLATES[severity])
    scenario = tmpl["scenario"]
    case_id = f"synth-{severity}-{scenario[:10]}-{case_idx:03d}"

    pid = rng.randint(1000, 65000)
    port = rng.randint(20000, 60000)
    count = rng.randint(8, 50)
    agent_id = f"{rng.randint(1, 10):03d}"
    agent_name = "victim-ubuntu" if rng.random() > 0.3 else "victim-win10"

    full_log = tmpl["log_tmpl"].format(
        pid=pid, port=port, count=count,
        file=tmpl["data"].get("file", "/bin/test"),
        agent=agent_name,
        package=tmpl["data"].get("package", "libssl")
    )

    alert_case = {
        "agent": {
            "id": agent_id,
            "name": agent_name,
            "ip": f"10.0.0.{rng.randint(20, 45)}"
        },
        "data": dict(tmpl["data"]),
        "rule": dict(tmpl["rule"]),
        "full_log": full_log,
        "timestamp": "2026-10-05T08:00:00.000+0000"
    }

    expected_doc = {
        "case_id": case_id,
        "provenance": "synthetic-stratified",
        "scenario": scenario,
        "rule_id": str(tmpl["rule"]["id"]),
        "disposition": "malicious" if severity in ("critical", "high") else ("suspicious" if severity == "medium" else "benign"),
        "severity": severity,
        "mitre_ids": list(tmpl["mitre"]["id"]),
        "mitre_tactics": list(tmpl["mitre"]["tactics"]),
        "summary_reference": tmpl["summary"],
        "root_cause_reference": tmpl["root_cause"],
        "required_facts": list(tmpl["facts"]),
        "forbidden_claims": [
            "Không suy đoán tác động vượt ngoài phạm vi chứng cứ có trong nhật ký.",
            "Không đưa ra khuyến nghị can thiệp phá hủy hệ thống mà không có xác minh sơ bộ."
        ],
        "next_steps_reference": list(tmpl["steps"]),
        "review_status": "draft-single-reviewer"
    }

    return alert_case, expected_doc


def generate_dataset(
    output_dir: Path,
    total: int = 370,
    min_critical: int = 35,
    min_high: int = 35,
    seed: int = 42
) -> dict:
    """Sinh tập dữ liệu phân tầng cân bằng vào thư mục chỉ định."""
    rng = random.Random(seed)

    cases_dir = output_dir / "cases"
    expected_dir = output_dir / "expected"
    cases_dir.mkdir(parents=True, exist_ok=True)
    expected_dir.mkdir(parents=True, exist_ok=True)

    # Phân bổ tầng lớp: đảm bảo tối thiểu số ca critical và high theo F-07
    num_critical = max(min_critical, int(total * 0.10))
    num_high = max(min_high, int(total * 0.15))
    remaining = total - (num_critical + num_high)
    num_medium = remaining // 2
    num_low = remaining - num_medium

    strata_counts = {
        "critical": num_critical,
        "high": num_high,
        "medium": num_medium,
        "low": num_low
    }

    manifest_items = []
    case_counter = 1

    for severity, count in strata_counts.items():
        for _ in range(count):
            case_data, expected_data = generate_case(case_counter, severity, rng)
            case_id = expected_data["case_id"]

            with open(cases_dir / f"{case_id}.json", "w", encoding="utf-8") as f:
                json.dump(case_data, f, ensure_ascii=False, indent=2)

            with open(expected_dir / f"{case_id}.json", "w", encoding="utf-8") as f:
                json.dump(expected_data, f, ensure_ascii=False, indent=2)

            manifest_items.append({
                "case_id": case_id,
                "severity": severity,
                "rule_id": str(case_data["rule"]["id"]),
                "scenario": expected_data["scenario"]
            })
            case_counter += 1

    manifest = {
        "version": "local-ai-siem-stratified/v1",
        "total_cases": len(manifest_items),
        "seed": seed,
        "strata_counts": strata_counts,
        "cases": manifest_items
    }

    with open(output_dir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    return manifest


def main():
    parser = argparse.ArgumentParser(description="Sinh tập dữ liệu phân tầng F-07 cho SIEM evaluation.")
    parser.add_argument("--output-dir", type=Path, default=Path("eval/stratified_370"), help="Thư mục xuất kết quả")
    parser.add_argument("--total", type=int, default=370, help="Tổng số ca sinh (mặc định: 370)")
    parser.add_argument("--min-critical", type=int, default=35, help="Số ca Critical tối thiểu (mặc định: 35)")
    parser.add_argument("--min-high", type=int, default=35, help="Số ca High tối thiểu (mặc định: 35)")
    parser.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên (mặc định: 42)")

    args = parser.parse_args()
    manifest = generate_dataset(
        output_dir=args.output_dir,
        total=args.total,
        min_critical=args.min_critical,
        min_high=args.min_high,
        seed=args.seed
    )
    print(f"Hoàn tất sinh {manifest['total_cases']} ca phân tầng tại: {args.output_dir}")
    print(f"Phân phối các lớp: {manifest['strata_counts']}")


if __name__ == "__main__":
    main()
