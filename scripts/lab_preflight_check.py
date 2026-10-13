"""scripts/lab_preflight_check.py

Kiểm tra tiền trạm (preflight check) cho môi trường lab SOC:
- Wazuh Indexer :9200 (OpenSearch cluster health, lưu trữ alert thật)
- Wazuh Manager API :55000 (quản trị, JWT authentication, quản lý agent)
- Ollama :11434 (LLM tags, qwen2.5:7b, qwen2.5:3b, nomic-embed-text)
- Victim agents (.20 Ubuntu, .40 Windows — ghi nhận trạng thái Active / Sysmon chưa xác nhận)
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_module"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


RECOMMENDED_MODELS = ("qwen2.5:7b", "qwen2.5:3b", "nomic-embed-text")


def load_lab_config(path: Path | str) -> dict[str, Any]:
    """Tải và parse file cấu hình YAML của lab."""
    target_path = Path(path)
    if not target_path.exists():
        fallback = ROOT / "ai_module" / "config.example.yaml"
        if fallback.exists():
            with open(fallback, encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle)
                return loaded if isinstance(loaded, dict) else {}
        return {}

    with open(target_path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
        return data if isinstance(data, dict) else {}


def check_tcp_port(host: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    """Kiểm tra kết nối TCP socket cơ bản tới host và port."""
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "reachable": False,
        "error": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["reachable"] = True
    except OSError as exc:
        result["error"] = str(exc)
    return result


def check_ollama(base_url: str, timeout: float = 5.0) -> dict[str, Any]:
    """Kiểm tra dịch vụ Ollama và các model được khuyến nghị."""
    parsed = urlsplit(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 11434)

    tcp_info = check_tcp_port(host, port, timeout=min(timeout, 2.0))
    if not tcp_info["reachable"]:
        return {
            "service": "Ollama LLM",
            "endpoint": base_url,
            "status": "FAIL",
            "models_found": [],
            "missing_recommended": list(RECOMMENDED_MODELS),
            "details": f"TCP unreachable at {host}:{port} ({tcp_info['error']})",
        }

    try:
        url = f"{base_url.rstrip('/')}/api/tags"
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        body = resp.json()
        models = [m.get("name", "") for m in body.get("models", []) if isinstance(m, dict)]
        missing = [req for req in RECOMMENDED_MODELS if not any(req in m for m in models)]
        status = "PASS" if not missing else ("WARN" if models else "FAIL")
        return {
            "service": "Ollama LLM",
            "endpoint": base_url,
            "status": status,
            "models_found": models,
            "missing_recommended": missing,
            "details": f"Tìm thấy {len(models)} model" if not missing else f"Thiếu: {', '.join(missing)}",
        }
    except Exception as exc:
        return {
            "service": "Ollama LLM",
            "endpoint": base_url,
            "status": "FAIL",
            "models_found": [],
            "missing_recommended": list(RECOMMENDED_MODELS),
            "details": f"Lỗi HTTP/JSON: {exc}",
        }


def check_wazuh_indexer(idx_cfg: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """Kiểm tra Wazuh Indexer (OpenSearch :9200) — nơi lưu alert thật."""
    host = idx_cfg.get("host", "192.168.100.10")
    port = int(idx_cfg.get("port", 9200))
    protocol = idx_cfg.get("protocol", "https")
    user = idx_cfg.get("user", "admin")
    password = idx_cfg.get("password", "")
    verify = idx_cfg.get("verify_ssl", False)
    ca_bundle = idx_cfg.get("ca_bundle")
    verify_val: Any = ca_bundle if ca_bundle else verify

    tcp_info = check_tcp_port(host, port, timeout=min(timeout, 2.0))
    if not tcp_info["reachable"]:
        return {
            "service": "Wazuh Indexer (:9200)",
            "role": "Lưu trữ cảnh báo thật (Alert Store)",
            "status": "FAIL",
            "details": f"TCP unreachable tại {host}:{port} ({tcp_info['error']})",
        }

    if password == "CHANGE_ME" or not password:
        return {
            "service": "Wazuh Indexer (:9200)",
            "role": "Lưu trữ cảnh báo thật (Alert Store)",
            "status": "WARN",
            "details": f"TCP {host}:{port} mở nhưng credential là CHANGE_ME (chưa đổi mật khẩu)",
        }

    try:
        url = f"{protocol}://{host}:{port}/_cluster/health"
        resp = requests.get(url, auth=(user, password), verify=verify_val, timeout=timeout)
        resp.raise_for_status()
        health = resp.json()
        cluster_status = health.get("status", "unknown")
        nodes = health.get("number_of_nodes", 0)
        return {
            "service": "Wazuh Indexer (:9200)",
            "role": "Lưu trữ cảnh báo thật (Alert Store)",
            "status": "PASS" if cluster_status in {"green", "yellow"} else "WARN",
            "cluster_status": cluster_status,
            "number_of_nodes": nodes,
            "details": f"Cluster: {health.get('cluster_name', '')} ({cluster_status}, {nodes} node)",
        }
    except requests.exceptions.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else 0
        return {
            "service": "Wazuh Indexer (:9200)",
            "role": "Lưu trữ cảnh báo thật (Alert Store)",
            "status": "FAIL",
            "details": f"HTTP {status_code} ({'Sai thông tin đăng nhập admin' if status_code == 401 else exc})",
        }
    except Exception as exc:
        return {
            "service": "Wazuh Indexer (:9200)",
            "role": "Lưu trữ cảnh báo thật (Alert Store)",
            "status": "FAIL",
            "details": f"Lỗi kết nối: {exc}",
        }


def check_wazuh_manager(mgr_cfg: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """Kiểm tra Wazuh Manager API (:55000) — quản trị, JWT auth, không lưu alert."""
    host = mgr_cfg.get("host", "192.168.100.10")
    port = int(mgr_cfg.get("port", 55000))
    protocol = mgr_cfg.get("protocol", "https")
    user = mgr_cfg.get("user", "wazuh-wui")
    password = mgr_cfg.get("password", "")
    verify = mgr_cfg.get("verify_ssl", False)
    ca_bundle = mgr_cfg.get("ca_bundle")
    verify_val: Any = ca_bundle if ca_bundle else verify

    tcp_info = check_tcp_port(host, port, timeout=min(timeout, 2.0))
    if not tcp_info["reachable"]:
        return {
            "service": "Wazuh Manager API (:55000)",
            "role": "Quản trị Agent & Rule (KHÔNG lưu alert)",
            "status": "FAIL",
            "token": None,
            "details": f"TCP unreachable tại {host}:{port} ({tcp_info['error']})",
        }

    if password == "CHANGE_ME" or not password:
        return {
            "service": "Wazuh Manager API (:55000)",
            "role": "Quản trị Agent & Rule (KHÔNG lưu alert)",
            "status": "WARN",
            "token": None,
            "details": f"TCP {host}:{port} mở nhưng credential là CHANGE_ME (chưa cấu hình mật khẩu)",
        }

    try:
        url = f"{protocol}://{host}:{port}/security/user/authenticate"
        resp = requests.post(url, auth=(user, password), verify=verify_val, timeout=timeout)
        resp.raise_for_status()
        token = resp.json().get("data", {}).get("token")
        return {
            "service": "Wazuh Manager API (:55000)",
            "role": "Quản trị Agent & Rule (KHÔNG lưu alert)",
            "status": "PASS" if token else "FAIL",
            "token": token,
            "details": "Xác thực JWT thành công" if token else "Không trích xuất được token",
        }
    except requests.exceptions.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else 0
        return {
            "service": "Wazuh Manager API (:55000)",
            "role": "Quản trị Agent & Rule (KHÔNG lưu alert)",
            "status": "FAIL",
            "token": None,
            "details": f"HTTP {status_code} ({'Sai thông tin xác thực' if status_code == 401 else exc})",
        }
    except Exception as exc:
        return {
            "service": "Wazuh Manager API (:55000)",
            "role": "Quản trị Agent & Rule (KHÔNG lưu alert)",
            "status": "FAIL",
            "token": None,
            "details": f"Lỗi xác thực: {exc}",
        }


def check_wazuh_agents(
    mgr_cfg: dict[str, Any],
    token: str | None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Truy vấn danh sách Agent qua Manager API để kiểm tra endpoint victim."""
    if not token:
        return {
            "service": "Wazuh Agents",
            "status": "SKIP",
            "agents": [],
            "details": "Bỏ qua do chưa có JWT token từ Manager API",
        }

    host = mgr_cfg.get("host", "192.168.100.10")
    port = int(mgr_cfg.get("port", 55000))
    protocol = mgr_cfg.get("protocol", "https")
    verify_val = mgr_cfg.get("ca_bundle") or mgr_cfg.get("verify_ssl", False)

    try:
        url = f"{protocol}://{host}:{port}/agents?select=id,name,ip,status,os.name"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, verify=verify_val, timeout=timeout)
        resp.raise_for_status()
        items = resp.json().get("data", {}).get("affected_items", [])

        ubuntu_status = "Not Found"
        windows_status = "Not Found"
        for item in items:
            ip = item.get("ip", "")
            name = item.get("name", "").lower()
            status = item.get("status", "unknown")
            if "192.168.100.20" in ip or "ubuntu" in name:
                ubuntu_status = status
            if "192.168.100.40" in ip or "windows" in name:
                windows_status = f"{status} (Sysmon: Chưa xác nhận)"

        return {
            "service": "Wazuh Agents",
            "status": "PASS" if items else "WARN",
            "total_agents": len(items),
            "ubuntu_victim_20": ubuntu_status,
            "windows_victim_40": windows_status,
            "details": f"{len(items)} agents đăng ký (Ubuntu: {ubuntu_status}; Windows: {windows_status})",
        }
    except Exception as exc:
        return {
            "service": "Wazuh Agents",
            "status": "WARN",
            "agents": [],
            "details": f"Không thể lấy danh sách agent: {exc}",
        }


def run_preflight(config_path: Path | str, timeout: float = 5.0) -> dict[str, Any]:
    """Chạy toàn bộ các bước kiểm tra tiền trạm môi trường lab."""
    cfg = load_lab_config(config_path)
    ollama_cfg = cfg.get("ollama", {})
    base_url = ollama_cfg.get("base_url", "http://localhost:11434")

    ollama_res = check_ollama(base_url, timeout=timeout)
    indexer_res = check_wazuh_indexer(cfg.get("wazuh_indexer", {}), timeout=timeout)
    manager_res = check_wazuh_manager(cfg.get("wazuh", {}), timeout=timeout)
    agents_res = check_wazuh_agents(cfg.get("wazuh", {}), manager_res.get("token"), timeout=timeout)

    # Loại bỏ raw token khỏi kết quả báo cáo
    clean_manager_res = {k: v for k, v in manager_res.items() if k != "token"}

    statuses = [ollama_res["status"], indexer_res["status"], clean_manager_res["status"]]
    if "FAIL" in statuses:
        overall = "FAIL"
    elif "WARN" in statuses:
        overall = "WARN"
    else:
        overall = "PASS"

    return {
        "overall_status": overall,
        "config_file": str(config_path),
        "checks": {
            "ollama": ollama_res,
            "wazuh_indexer": indexer_res,
            "wazuh_manager": clean_manager_res,
            "wazuh_agents": agents_res,
        },
    }


def format_report_text(report: dict[str, Any]) -> str:
    """Tạo báo cáo định dạng Markdown / bảng kiểm tra."""
    lines = [
        "=" * 78,
        f"KẾT QUẢ LAB PREFLIGHT CHECK: [{report['overall_status']}]",
        f"Cấu hình: {report['config_file']}",
        "=" * 78,
    ]
    for key, item in report["checks"].items():
        status = item.get("status", "UNKNOWN")
        service = item.get("service", key)
        role = f" ({item['role']})" if "role" in item else ""
        details = item.get("details", "")
        lines.append(f"[{status:<4}] {service}{role}")
        lines.append(f"       -> {details}")
    lines.append("-" * 78)
    lines.append("Lưu ý vận hành:")
    lines.append("- Alert production được đọc từ Wazuh Indexer :9200, KHÔNG từ Manager :55000.")
    lines.append("- Windows victim .40 có agent Active, nhưng Sysmon chưa xác nhận trong lab.")
    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab Preflight Diagnostic Checker")
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "ai_module" / "config.yaml",
        help="Đường dẫn file cấu hình YAML",
    )
    parser.add_argument("--json", action="store_true", help="Xuất kết quả JSON")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout kết nối mạng (giây)")
    args = parser.parse_args()

    report = run_preflight(args.config, timeout=args.timeout)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_report_text(report))

    return 0 if report["overall_status"] in {"PASS", "WARN"} else 1


if __name__ == "__main__":
    sys.exit(main())
