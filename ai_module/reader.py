"""reader.py — Đọc alert từ Wazuh (Indexer/OpenSearch, hoặc tail alerts.json)."""
import json
import requests
import yaml
from pathlib import Path
from typing import Iterator


MODULE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = MODULE_DIR.parent / "eval" / "samples"


def load_config(path: str | Path = MODULE_DIR / "config.yaml") -> dict:
    """Load and minimally validate YAML config."""
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ValueError("Config YAML phải là object")
    for section in ("ollama", "wazuh_indexer", "extractor"):
        if not isinstance(cfg.get(section), dict):
            raise ValueError(f"Thiếu hoặc sai config section: {section}")
    if not isinstance(cfg["extractor"].get("fields"), list):
        raise ValueError("extractor.fields phải là list")
    return cfg


def get_wazuh_token(cfg: dict) -> str:
    """Xác thực Wazuh Manager API, trả về JWT token. (Không dùng để lấy alert)"""
    wazuh_cfg = cfg["wazuh"]
    url = f"{wazuh_cfg['protocol']}://{wazuh_cfg['host']}:{wazuh_cfg['port']}/security/user/authenticate"
    r = requests.post(
        url,
        auth=(wazuh_cfg["user"], wazuh_cfg["password"]),
        verify=wazuh_cfg.get("verify_ssl", False),
        timeout=wazuh_cfg.get("timeout", 30),
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def fetch_alerts_api(cfg: dict, limit: int = 10) -> list[dict]:
    """Lấy N alert mới nhất — query thẳng Wazuh Indexer (OpenSearch), không phải Manager API."""
    if not 1 <= limit <= 50:
        raise ValueError("limit phải nằm trong khoảng 1..50")

    idx_cfg = cfg["wazuh_indexer"]
    protocol = idx_cfg.get("protocol", "https")
    url = (f"{protocol}://{idx_cfg['host']}:{idx_cfg['port']}"
           f"/wazuh-alerts-*/_search")

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "track_total_hits": False,
    }

    r = requests.post(
        url,
        json=query,
        auth=(idx_cfg["user"], idx_cfg["password"]),
        verify=idx_cfg.get("ca_bundle", idx_cfg.get("verify_ssl", True)),
        timeout=idx_cfg.get("timeout", 30),
    )
    r.raise_for_status()

    body = r.json()
    if not isinstance(body, dict):
        raise ValueError("Indexer trả JSON không phải object")
    hits_object = body.get("hits")
    if not isinstance(hits_object, dict):
        raise ValueError("Indexer response thiếu hits object")
    hits = hits_object.get("hits")
    if not isinstance(hits, list):
        raise ValueError("Indexer response thiếu hits.hits list")

    alerts = []
    for index, hit in enumerate(hits):
        if not isinstance(hit, dict):
            raise ValueError(f"Indexer hits.hits[{index}] phải là object")
        source = hit.get("_source")
        if not isinstance(source, dict):
            raise ValueError(f"Indexer hits.hits[{index}]._source phải là object")
        alerts.append(source)
    return alerts


def tail_alerts_json(path: str = "/var/ossec/logs/alerts/alerts.json") -> Iterator[dict]:
    """Tail file alerts.json (chạy trên SIEM hoặc mount NFS). Generator."""
    raise NotImplementedError("tail_alerts_json chưa implement — dùng fetch_alerts_api trước")


def load_sample_alerts(path: str | Path = SAMPLES_DIR) -> list[dict]:
    """Load alert mẫu từ thư mục eval/samples/ (dùng khi --demo)."""
    alerts = []
    for f in sorted(Path(path).glob("*.json")):
        alerts.append(json.loads(f.read_text(encoding="utf-8")))
    return alerts
