"""reader.py — Đọc alert từ Wazuh (API hoặc tail alerts.json).

Stub: cấu trúc sẵn, chưa chạy thật. Implement ở GĐ3.
"""
import json
import requests
import yaml
from pathlib import Path
from typing import Iterator


def load_config(path: str = "config.yaml") -> dict:
    """Load YAML config."""
    with open(path) as f:
        return yaml.safe_load(f)


def get_wazuh_token(cfg: dict) -> str:
    """Xác thực Wazuh API, trả về JWT token."""
    url = f"{cfg['wazuh']['protocol']}://{cfg['wazuh']['host']}:{cfg['wazuh']['port']}/security/user/authenticate"
    r = requests.post(url, auth=(cfg["wazuh"]["user"], cfg["wazuh"]["password"]),
                      verify=cfg["wazuh"].get("verify_ssl", False))
    r.raise_for_status()
    return r.json()["data"]["token"]


def fetch_alerts_api(cfg: dict, limit: int = 10) -> list[dict]:
    """Lấy N alert mới nhất qua Wazuh API."""
    # TODO: implement query OpenSearch/Indexer thay vì manager API
    # ponytail: API manager chỉ có alert gần đây. Dùng OpenSearch query khi cần lịch sử dài.
    token = get_wazuh_token(cfg)
    url = f"{cfg['wazuh']['protocol']}://{cfg['wazuh']['host']}:{cfg['wazuh']['port']}/alerts"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, params={"limit": limit},
                     verify=cfg["wazuh"].get("verify_ssl", False))
    r.raise_for_status()
    return r.json().get("data", {}).get("affected_items", [])


def tail_alerts_json(path: str = "/var/ossec/logs/alerts/alerts.json") -> Iterator[dict]:
    """Tail file alerts.json (chạy trên SIEM hoặc mount NFS). Generator."""
    # TODO: implement tail -f dạng streaming
    raise NotImplementedError("tail_alerts_json chưa implement — dùng fetch_alerts_api trước")


def load_sample_alerts(path: str = "../eval/samples") -> list[dict]:
    """Load alert mẫu từ thư mục eval/samples/ (dùng khi --demo)."""
    alerts = []
    for f in sorted(Path(path).glob("*.json")):
        alerts.append(json.loads(f.read_text()))
    return alerts
