"""extractor.py — Trích ~10 trường chính từ alert JSON.

KHÔNG ném raw JSON vào LLM — giảm token, tăng chính xác.
"""
import yaml


def load_config(path: str = "config.yaml") -> dict:
    with open(path, encoding="utf-8") as f:
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


# Nhãn hiển thị đẹp cho từng field — thay vì in thẳng "rule.id: 5712",
# in "Rule: 5712" cho LLM (và người đọc log) dễ hiểu hơn.
_LABELS = {
    "rule.id": "Rule",
    "rule.description": "Description",
    "rule.level": "Level",
    "rule.mitre.id": "MITRE ID",
    "rule.mitre.tactic": "MITRE Tactic",
    "rule.mitre.technique": "MITRE Technique",
    "agent.name": "Agent",
    "agent.ip": "Agent IP",
    "data.srcip": "Source IP",
    "full_log": "Log",
}


def format_for_llm(extracted: dict) -> str:
    """Format extracted fields thành text ngắn gọn cho LLM context.

    Ví dụ output:
        Rule: 5712 (level 10) — SSHD brute-force
        MITRE: T1110 / Credential Access
        Agent: victim-ubuntu (192.168.100.20)
        Source IP: 192.168.100.30
        Log: Failed password for root from 192.168.100.30 port 22 ssh2
    """
    lines = []

    rule_id = extracted.get("rule.id")
    level = extracted.get("rule.level")
    desc = extracted.get("rule.description")
    if rule_id is not None:
        header = f"Rule: {rule_id}"
        if level is not None:
            header += f" (level {level})"
        if desc:
            header += f" — {desc}"
        lines.append(header)

    mitre_id = extracted.get("rule.mitre.id")
    mitre_tactic = extracted.get("rule.mitre.tactic")
    mitre_technique = extracted.get("rule.mitre.technique")
    if mitre_id or mitre_tactic or mitre_technique:
        mitre_id_str = ", ".join(mitre_id) if isinstance(mitre_id, list) else str(mitre_id or "")
        mitre_tactic_str = ", ".join(mitre_tactic) if isinstance(mitre_tactic, list) else str(mitre_tactic or "")
        mitre_technique_str = (
            ", ".join(mitre_technique)
            if isinstance(mitre_technique, list)
            else str(mitre_technique or "")
        )
        mitre_parts = [
            part for part in (mitre_id_str, mitre_tactic_str, mitre_technique_str) if part
        ]
        lines.append(f"MITRE: {' / '.join(mitre_parts)}")

    agent_name = extracted.get("agent.name")
    agent_ip = extracted.get("agent.ip")
    if agent_name:
        agent_line = f"Agent: {agent_name}"
        if agent_ip:
            agent_line += f" ({agent_ip})"
        lines.append(agent_line)

    srcip = extracted.get("data.srcip")
    if srcip:
        lines.append(f"Source IP: {srcip}")

    full_log = extracted.get("full_log")
    if full_log:
        lines.append(f"Log: {full_log}")

    # Field nào chưa xử lý riêng ở trên (fallback) — tránh mất dữ liệu
    # nếu config.yaml sau này thêm field mới mà chưa cập nhật hàm này.
    handled = {"rule.id", "rule.level", "rule.description",
               "rule.mitre.id", "rule.mitre.tactic", "rule.mitre.technique",
               "agent.name", "agent.ip", "data.srcip", "full_log"}
    for key, val in extracted.items():
        if key not in handled:
            lines.append(f"{_LABELS.get(key, key)}: {val}")

    return "\n".join(lines)
