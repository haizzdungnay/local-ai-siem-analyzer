"""extractor.py — Trích ~10 trường chính từ alert JSON.

KHÔNG ném raw JSON vào LLM — giảm token, tăng chính xác.
Stub: cấu trúc sẵn, chưa chạy thật. Implement ở GĐ3.
"""
import yaml


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def extract_fields(alert: dict, fields: list[str] | None = None) -> dict:
    """Trích các trường quan trọng từ alert JSON.

    Args:
        alert: raw alert dict từ Wazuh
        fields: danh sách dotted key (vd "rule.id"). Nếu None, dùng config.

    Returns:
        dict chỉ chứa trường đã trích — sẵn sàng format cho LLM.
    """
    if fields is None:
        cfg = load_config()
        fields = cfg["extractor"]["fields"]

    extracted = {}
    for field in fields:
        value = _get_nested(alert, field)
        if value is not None:
            extracted[field] = value
    return extracted


def _get_nested(d: dict, dotted_key: str):
    """Truy cập nested dict bằng dotted key (vd 'rule.mitre.id')."""
    keys = dotted_key.split(".")
    current = d
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return None
    return current


def format_for_llm(extracted: dict) -> str:
    """Format extracted fields thành text ngắn gọn cho LLM context.

    Ví dụ output:
        Rule: 5712 (level 10) — SSHD brute-force
        MITRE: T1110 / Credential Access
        Agent: victim-ubuntu (192.168.100.20)
        Source IP: 192.168.100.30
        Log: Failed password for root from 192.168.100.30 port 22 ssh2
    """
    # TODO: implement formatting — bám danh sách trường trong config
    lines = []
    for key, val in extracted.items():
        lines.append(f"{key}: {val}")
    return "\n".join(lines)
