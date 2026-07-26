"""reader.py — Đọc alert từ Wazuh (Indexer/OpenSearch, hoặc tail alerts.json)."""
import json
import requests
import yaml
from pathlib import Path
from typing import Iterator


def load_config(path: str = "config.yaml") -> dict:
    """Load YAML config."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_wazuh_token(cfg: dict) -> str:
    """Xác thực Wazuh Manager API, trả về JWT token. (Không dùng để lấy alert)"""
    url = f"{cfg['wazuh']['protocol']}://{cfg['wazuh']['host']}:{cfg['wazuh']['port']}/security/user/authenticate"
    r = requests.post(url, auth=(cfg["wazuh"]["user"], cfg["wazuh"]["password"]),
                      verify=cfg["wazuh"].get("verify_ssl", False))
    r.raise_for_status()
    return r.json()["data"]["token"]


def fetch_alerts_api(cfg: dict, limit: int = 10) -> list[dict]:
    """Lấy N alert mới nhất — query thẳng Wazuh Indexer (OpenSearch), không phải Manager API."""
    idx_cfg = cfg["wazuh_indexer"]
    url = (f"{cfg['wazuh']['protocol']}://{idx_cfg['host']}:{idx_cfg['port']}"
           f"/wazuh-alerts-*/_search")

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    r = requests.post(
        url,
        json=query,
        auth=(idx_cfg["user"], idx_cfg["password"]),
        verify=idx_cfg.get("verify_ssl", False),
    )
    r.raise_for_status()

    hits = r.json().get("hits", {}).get("hits", [])
    return [hit["_source"] for hit in hits]


def tail_alerts_json(path: str = "/var/ossec/logs/alerts/alerts.json") -> Iterator[dict]:
    """Tail file alerts.json (chạy trên SIEM hoặc mount NFS). Generator."""
    raise NotImplementedError("tail_alerts_json chưa implement — dùng fetch_alerts_api trước")


def load_sample_alerts(path: str = "../eval/samples") -> list[dict]:
    """Load alert mẫu từ thư mục eval/samples/ (dùng khi --demo)."""
    alerts = []
    for f in sorted(Path(path).glob("*.json")):
        alerts.append(json.loads(f.read_text(encoding="utf-8")))
    return alerts