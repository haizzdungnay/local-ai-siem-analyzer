import json
import re
import sys
import requests
import urllib3
from collections import defaultdict
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, "ai_module")
from reader import load_config

urllib3.disable_warnings()
cases_dir = Path("eval/cases")
expected_dir = Path("eval/expected")
cfg = load_config("ai_module/config.yaml")["wazuh_indexer"]
url = f"{cfg.get('protocol', 'https')}://{cfg['host']}:{cfg['port']}/wazuh-alerts-*/_search"
response = requests.post(
    url,
    json={"size": 500, "sort": [{"timestamp": {"order": "desc"}}], "track_total_hits": False},
    auth=(cfg["user"], cfg["password"]),
    verify=cfg.get("ca_bundle", cfg.get("verify_ssl", True)),
    timeout=cfg.get("timeout", 30),
)
response.raise_for_status()
alerts = [
    hit["_source"] for hit in response.json()["hits"]["hits"]
    if isinstance(hit, dict) and isinstance(hit.get("_source"), dict)
]

AGENT_NAME = "victim-ubuntu"
AGENT_IP = "10.0.0.20"
SRC_MAP = {"192.168.100.30": "10.0.0.30", "192.168.100.1": "10.0.0.1"}
USER_MAP = {"trnguyn": "analyst", "tplab": "invalid-user-a", "duong": "invalid-user-b"}
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/=]+")
PID_RE = re.compile(r"(?<=\[)\d+(?=\])")
PORT_RE = re.compile(r"(?<= port )\d+")
DATE_RE = re.compile(r"^(?:Jul\s+28\s+)?(?:14|20|21):\d{2}:\d{2}\s+")


def replace_text(value):
    if not isinstance(value, str):
        return value
    value = value.replace("trnguyn-virtual-machine", AGENT_NAME)
    value = value.replace("99-claude-lab", "99-eval-lab")
    for old, new in SRC_MAP.items():
        value = value.replace(old, new)
    for old, new in USER_MAP.items():
        value = re.sub(rf"\b{re.escape(old)}\b", new, value)
    value = FINGERPRINT_RE.sub("SHA256:[REDACTED]", value)
    value = PID_RE.sub("1000", value)
    value = PORT_RE.sub("40000", value)
    return DATE_RE.sub("", value)


def sanitize(value):
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    return replace_text(value)


def sanitize_alert(alert):
    result = sanitize(deepcopy(alert))
    for key in ("timestamp", "@timestamp", "id", "manager", "decoder", "input", "location", "predecoder", "previous_output", "firedtimes", "cluster"):
        result.pop(key, None)
    rule = result.get("rule")
    if isinstance(rule, dict):
        rule.pop("firedtimes", None)
        rule.pop("mail", None)
        rule.pop("groups", None)
        rule.pop("pci_dss", None)
        rule.pop("hipaa", None)
        rule.pop("tsc", None)
        rule.pop("nist_800_53", None)
        rule.pop("gdpr", None)
        rule.pop("gpg13", None)
        rule.pop("id", None)
        rule.pop("level", None)
        rule.pop("description", None)
        rule.pop("mitre", None)
        rule.pop("decoder", None)
        rule.pop("mail", None)
        rule["id"] = str((alert.get("rule") or {}).get("id", ""))
        original_rule = alert.get("rule") or {}
        for field in ("level", "description", "mitre"):
            if field in original_rule:
                rule[field] = sanitize(deepcopy(original_rule[field]))
    agent = result.get("agent")
    if isinstance(agent, dict):
        agent.update({"id": "001", "name": AGENT_NAME, "ip": AGENT_IP})
    data = result.get("data")
    if isinstance(data, dict):
        data.pop("srcport", None)
    return result


def rule_id(alert):
    return str((alert.get("rule") or {}).get("id", ""))


by_rule = defaultdict(list)
for raw in alerts:
    by_rule[rule_id(raw)].append(raw)

selectors = [
    ("ssh", "5503", 5), ("ssh", "5760", 5), ("ssh", "5710", 2),
    ("ssh", "2502", 1), ("ssh", "5712", 1), ("ssh", "40112", 2),
    ("fim", "554", 2), ("fim", "553", 1),
    ("web", "31101", 1), ("web", "31151", 1), ("web", "31105", 1),
    ("benign", "5715", 1), ("benign", "5501", 2), ("benign", "5502", 2),
    ("benign", "5402", 1), ("benign", "503", 1), ("benign", "23502", 6),
    ("ambiguous", "506", 1), ("ambiguous", "510", 1),
]
selected = []
seen = set()
for category, rid, limit in selectors:
    for raw in by_rule[rid]:
        alert = sanitize_alert(raw)
        fingerprint = json.dumps(alert, ensure_ascii=False, sort_keys=True)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        selected.append((category, alert))
        if sum(1 for c, a in selected if c == category and rule_id(a) == rid) >= limit:
            break

if not 30 <= len(selected) <= 50:
    counts = defaultdict(int)
    for category, alert in selected:
        counts[(category, rule_id(alert))] += 1
    raise SystemExit(f"expected 30..50 cases, got {len(selected)}: {dict(counts)}")

severity = {
    "5503": "medium", "5760": "medium", "5710": "medium", "2502": "high",
    "5712": "high", "40112": "high", "554": "medium", "553": "high",
    "31101": "medium", "31151": "high", "31105": "medium",
    "5715": "low", "5501": "low", "5502": "low", "5402": "low", "503": "low", "23502": "low",
    "506": "medium", "510": "high",
}
disposition = {
    "5503": "suspicious", "5760": "suspicious", "5710": "suspicious", "2502": "malicious",
    "5712": "malicious", "40112": "ambiguous", "554": "ambiguous", "553": "ambiguous",
    "31101": "suspicious", "31151": "malicious", "31105": "suspicious",
    "5715": "benign", "5501": "benign", "5502": "benign", "5402": "benign", "503": "benign", "23502": "benign",
    "506": "ambiguous", "510": "ambiguous",
}
summary = {
    "5503": "Một lần xác thực PAM/SSH thất bại từ IP nguồn trong lab.",
    "5760": "Đăng nhập SSH vào tài khoản đích đã thất bại.",
    "5710": "Có lần đăng nhập SSH dùng tài khoản không tồn tại.",
    "2502": "Nhiều lần xác thực SSH thất bại được PAM tổng hợp.",
    "5712": "Wazuh phát hiện chuỗi brute-force SSH vào tài khoản không tồn tại.",
    "40112": "Nhiều lần xác thực thất bại được theo sau bởi đăng nhập thành công; cần xác minh phiên thành công.",
    "554": "Một file mới xuất hiện trong thư mục FIM được giám sát.",
    "553": "Một file trong thư mục FIM được giám sát đã bị xóa.",
    "31101": "Web server trả HTTP 404 cho request truy cập path đáng ngờ `/etc/passwd`.",
    "31151": "Nhiều request web lỗi từ cùng IP được Wazuh tương quan thành hoạt động quét.",
    "31105": "Một request chứa payload XSS được gửi tới web server và nhận HTTP 404.",
    "5715": "Đăng nhập SSH bằng public key đã thành công.",
    "5501": "Một phiên PAM đã được mở.",
    "5502": "Một phiên PAM đã đóng.",
    "5402": "Người dùng lab chạy lệnh sudo được ghi trong log.",
    "503": "Wazuh agent đã khởi động.",
    "506": "Wazuh agent đã dừng; cần xác minh đây là bảo trì hay hành vi né tránh.",
    "510": "Rootcheck báo nghi ngờ file hệ thống bị trojan hóa; cần xác minh để loại false positive.",
    "23502": "Wazuh ghi nhận bản cập nhật đã giải quyết CVE trên package của agent.",
}
root_cause = {
    "5503": "Mật khẩu hoặc thông tin xác thực SSH không hợp lệ; một alert đơn lẻ chưa chứng minh brute-force hay compromise.",
    "5760": "sshd từ chối thông tin xác thực của tài khoản đích; log cho thấy cùng thông báo lặp lại bốn lần.",
    "5710": "Client SSH thử username không tồn tại; alert không đủ evidence để kết luận password guessing.",
    "2502": "PAM ghi nhận nhiều lần xác thực thất bại trong cùng chuỗi kết nối.",
    "5712": "Nhiều lần thử SSH bằng tài khoản không tồn tại kích hoạt rule tương quan brute-force.",
    "40112": "Rule tương quan phát hiện thất bại xác thực trước một lần thành công; cần xác minh tính hợp lệ của phiên thành công.",
    "554": "Một file mới xuất hiện trong path FIM; nguyên nhân không có trong alert và cần đối chiếu change record.",
    "553": "Một file FIM đã bị xóa; nguyên nhân không có trong alert và cần xác minh actor hoặc tiến trình thực hiện.",
    "31101": "Request từ IP nguồn chứa path nhạy cảm nhưng server trả 404; alert chưa chứng minh đọc file thành công.",
    "31151": "Nhiều HTTP 404 liên tiếp từ cùng nguồn khớp hành vi vulnerability scanning và kích hoạt correlation rule.",
    "31105": "URL chứa chuỗi `<script>` khớp chữ ký XSS nhưng response 404; alert chưa chứng minh JavaScript đã thực thi.",
    "5715": "Public key của analyst được chấp nhận; cần đối chiếu source và fingerprint để xác nhận phiên được phép.",
    "5501": "PAM mở một phiên; alert không đủ evidence để xác nhận tính hợp lệ của hoạt động.",
    "5502": "PAM đóng một phiên; alert không cho biết nguyên nhân đóng.",
    "5402": "Analyst dùng sudo cho lệnh được ghi rõ trong full_log; cần đối chiếu change record để xác nhận được phép.",
    "503": "Wazuh agent đã khởi động; nguyên nhân không có trong alert, cần đối chiếu change record.",
    "506": "Wazuh agent đã dừng; nguyên nhân không có trong alert. Đối chiếu change record trước khi quy kết defense evasion.",
    "510": "Rootcheck khớp chữ ký generic trên binary diff; alert cần kiểm chứng hash hoặc package trước khi kết luận trojan.",
    "23502": "Vulnerability Detector ghi nhận CVE đã được giải quyết do package hoặc feed được cập nhật.",
}
next_steps = {
    "5503": ["Đếm các thất bại cùng IP và tài khoản trong cửa sổ thời gian ngắn", "Kiểm tra IP nguồn có thuộc lab hoặc danh sách tin cậy không"],
    "5760": ["Đối chiếu các alert 5503 hoặc 2502 cùng IP và thời điểm", "Chặn hoặc rate-limit nguồn nếu thất bại tiếp diễn"],
    "5710": ["Kiểm tra số username không tồn tại được thử từ cùng IP", "Theo dõi rule tương quan 5712 hoặc đăng nhập thành công sau đó"],
    "2502": ["Điều tra toàn bộ chuỗi SSH cùng IP nguồn", "Kiểm tra có phiên thành công sau các lần thất bại không"],
    "5712": ["Chặn hoặc cô lập IP nguồn nếu không được phép", "Rà soát tài khoản và các phiên thành công cùng thời điểm"],
    "40112": ["Xác minh chủ sở hữu IP, phương thức xác thực và phiên đăng nhập thành công", "Thu hồi credential và cô lập máy nếu phiên không được phép"],
    "554": ["Xác minh path, owner và hash của file mới", "Đối chiếu với script hoặc change record trước khi xóa hoặc cách ly"],
    "553": ["Xác minh file bị xóa và tiến trình hoặc người dùng thực hiện", "Khôi phục từ backup nếu đây không phải cleanup được phép"],
    "31101": ["Rà các request cùng IP và thời điểm", "Xác minh server không trả nội dung file nhạy cảm"],
    "31151": ["Xác định phạm vi URL và dịch vụ bị quét", "Chặn hoặc rate-limit nguồn nếu hoạt động không được phép"],
    "31105": ["Kiểm tra response và application log để xác nhận payload không thực thi", "Rà input validation và output encoding của ứng dụng"],
    "5715": ["Xác minh IP nguồn và fingerprint public key thuộc analyst", "Không chặn phiên nếu khớp hoạt động quản trị dự kiến"],
    "5501": ["Đối chiếu phiên với lệnh sudo hoặc phiên SSH liên quan", "Chỉ nâng mức nếu tài khoản, nguồn hoặc thời gian bất thường"],
    "5502": ["Đối chiếu với phiên mở tương ứng", "Không cần xử lý thêm nếu phiên hợp lệ"],
    "5402": ["Đọc chính xác COMMAND trong log và đối chiếu change record", "Điều tra thêm chỉ khi lệnh hoặc người dùng không được phép"],
    "503": ["Xác nhận agent active và đang gửi heartbeat", "Đối chiếu với thay đổi cấu hình dự kiến"],
    "506": ["Kiểm tra agent có tự khởi động lại và kết nối Manager không", "Điều tra service logs nếu không có bảo trì được phép"],
    "510": ["Xác minh package owner và checksum của binary", "So sánh với binary sạch trước khi cô lập hoặc thay thế"],
    "23502": ["Xác minh package đã ở bản vá và trạng thái CVE là Solved", "Theo dõi lần scan tiếp theo để bảo đảm finding không xuất hiện lại"],
}


def reference_text(mapping, rid, alert):
    if rid == "5760" and "message repeated 4 times" in str(alert.get("full_log", "")):
        return "Các lần đăng nhập SSH vào tài khoản đích đều thất bại; log ghi thông báo lặp lại bốn lần."
    return mapping[rid]


def expected_mitre(alert, rid):
    full_log = str(alert.get("full_log", ""))
    if rid in {"5715", "5501", "5402", "23502", "31101", "31105"}:
        return [], []
    if rid == "5710" and "Failed password" not in full_log:
        return [], []
    mitre = ((alert.get("rule") or {}).get("mitre") or {})
    return mitre.get("id", []), mitre.get("tactic", [])


for output_dir in (cases_dir, expected_dir):
    for output_file in output_dir.glob("*.json"):
        output_file.unlink()

manifest = []
ordinals = defaultdict(int)
for category, alert in selected:
    rid = rule_id(alert)
    ordinals[rid] += 1
    case_id = f"{category}-{rid}-{ordinals[rid]:02d}"
    case_file = cases_dir / f"{case_id}.json"
    expected_file = expected_dir / f"{case_id}.json"
    case_file.write_text(json.dumps(alert, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    mitre_ids, mitre_tactics = expected_mitre(alert, rid)
    description = str((alert.get("rule") or {}).get("description", ""))
    full_log = str(alert.get("full_log") or "").splitlines()
    required_facts = [description] + full_log[:1]
    expected = {
        "case_id": case_id, "provenance": "sanitized-live", "scenario": category,
        "rule_id": rid, "disposition": disposition[rid], "severity": severity[rid],
        "mitre_ids": mitre_ids, "mitre_tactics": mitre_tactics,
        "summary_reference": reference_text(summary, rid, alert),
        "root_cause_reference": reference_text(root_cause, rid, alert),
        "required_facts": required_facts,
        "forbidden_claims": ["Không khẳng định compromise thành công nếu alert không có bằng chứng đó.", "Không tự động chặn, xóa file hoặc cô lập máy trước khi xác minh context."],
        "next_steps_reference": next_steps[rid], "review_status": "draft-single-reviewer",
    }
    expected_file.write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest.append({"case_id": case_id, "case_file": case_file.as_posix(), "expected_file": expected_file.as_posix(), "provenance": "sanitized-live", "scenario": category, "rule_id": rid, "review_status": "draft-single-reviewer"})

Path("eval/manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"wrote {len(manifest)} cases and expected files")
