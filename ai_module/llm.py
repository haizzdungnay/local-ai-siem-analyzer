"""llm.py — Gọi Ollama LLM local, ép output JSON schema.

Output schema: {summary, root_cause, severity, mitre, next_steps[]}
Đúng theo kế hoạch GĐ3 trong KE_HOACH.md — phân tích từng alert đơn lẻ.
(Phần gom theo cụm hành vi sẽ làm sau, xem behavior_grouper.py)
"""
import json
import ollama as ollama_sdk


OUTPUT_SCHEMA = {
    "summary": "Tóm tắt cảnh báo 1-2 câu",
    "root_cause": "Nguyên nhân kích hoạt rule",
    "severity": "low | medium | high | critical",
    "mitre": "MITRE ATT&CK technique ID + tactic",
    "next_steps": ["Bước kiểm tra/xử lý 1", "Bước 2", "..."]
}

# Ví dụ đã điền sẵn (few-shot) — giúp model kém instruction-following (vd base
# model như Foundation-Sec-8B) không nhầm MÔ TẢ field trong OUTPUT_SCHEMA
# thành GIÁ TRỊ cần trả về. Dùng chung cho mọi model, không phân biệt.
EXAMPLE_INPUT = """Rule: 5503 (level 5) — PAM: User login failed
Agent: victim-ubuntu (192.168.100.20)
Source IP: 192.168.100.30
Log: Failed password for root from 192.168.100.30 port 22 ssh2"""

EXAMPLE_OUTPUT = {
    "summary": "Nhiều lần đăng nhập SSH thất bại vào tài khoản root từ một IP bên ngoài.",
    "root_cause": "Có khả năng đang bị dò mật khẩu (brute-force) qua SSH nhắm vào tài khoản root.",
    "severity": "medium",
    "mitre": "T1110 / Credential Access",
    "next_steps": [
        "Kiểm tra xem IP nguồn 192.168.100.30 có nằm trong danh sách tin cậy không",
        "Xem xét chặn IP hoặc bật rate-limit cho SSH nếu số lần thất bại tiếp tục tăng"
    ]
}

SYSTEM_PROMPT = """Bạn là chuyên gia phân tích an ninh mạng (SOC analyst).
Nhiệm vụ: đọc thông tin cảnh báo SIEM và giải thích bằng tiếng Việt, rõ ràng, ngắn gọn.

Luôn trả lời dạng JSON với đúng các trường sau (đây là MÔ TẢ Ý NGHĨA từng trường,
KHÔNG PHẢI giá trị mẫu để copy lại):
{schema}

Ví dụ 1 lượt hỏi-đáp đúng cách (chỉ để tham khảo cách điền, không liên quan tới
alert thực tế bên dưới):

Input mẫu:
{example_input}

Output mẫu (JSON hợp lệ, đã điền nội dung thực tế thay vì mô tả field):
{example_output}

Không thêm text ngoài JSON. Không copy nguyên văn mô tả field ở trên vào giá trị
trả về — hãy phân tích alert thực tế bên dưới và điền nội dung tương ứng.
Không bịa thông tin không có trong alert.""".format(
    schema=json.dumps(OUTPUT_SCHEMA, ensure_ascii=False, indent=2),
    example_input=EXAMPLE_INPUT,
    example_output=json.dumps(EXAMPLE_OUTPUT, ensure_ascii=False, indent=2),
)


def analyze_alert(alert_text: str, rag_context: str = "",
                   model: str = "qwen2.5:3b", base_url: str = "http://localhost:11434") -> dict:
    """Gửi alert đã trích + RAG context cho LLM, parse JSON output.

    Args:
        alert_text: output từ extractor.format_for_llm()
        rag_context: output từ rag.format_context()
        model: tên model Ollama
        base_url: Ollama endpoint

    Returns:
        dict theo OUTPUT_SCHEMA
    """
    user_msg = f"Thông tin cảnh báo:\n{alert_text}"
    if rag_context:
        user_msg += f"\n\nTham khảo thêm:\n{rag_context}"

    client = ollama_sdk.Client(host=base_url)
    response = client.chat(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        format="json",
    )
    return _parse_response(response["message"]["content"])


def _looks_like_echoed_schema(result: dict) -> bool:
    """Phát hiện trường hợp model 'trả lại đề bài' — copy nguyên văn mô tả
    field trong OUTPUT_SCHEMA thay vì điền nội dung phân tích thực tế.

    Dùng chung cho mọi model (không if-else riêng theo tên model). Coi là
    echoed nếu >= 2 field trùng khớp (không phân biệt hoa/thường, khoảng
    trắng thừa) với đúng mô tả gốc trong OUTPUT_SCHEMA.
    """
    echoed_count = 0
    for key, schema_value in OUTPUT_SCHEMA.items():
        result_value = result.get(key)
        if result_value is None:
            continue
        # So sánh dạng string hóa để áp dụng được cả cho next_steps (list)
        if str(result_value).strip().lower() == str(schema_value).strip().lower():
            echoed_count += 1
    return echoed_count >= 2


def _fallback_result(reason: str, raw_preview: str = "") -> dict:
    return {
        "summary": raw_preview[:200] if raw_preview else "",
        "root_cause": reason,
        "severity": "unknown",
        "mitre": "",
        "next_steps": ["Kiểm tra lại prompt / thử model khác"],
    }


def _parse_response(raw: str) -> dict:
    """Parse JSON từ LLM response. Fallback nếu LLM trả sai format hoặc
    'trả lại đề bài' thay vì phân tích thực tế."""
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return _fallback_result("[LLM không trả JSON hợp lệ]", raw)

    # Validate required keys
    for key in OUTPUT_SCHEMA:
        if key not in result:
            result[key] = f"[MISSING: {key}]"

    if _looks_like_echoed_schema(result):
        return _fallback_result(
            "[LLM trả lại mô tả schema thay vì phân tích thực tế — model có thể "
            "yếu về instruction-following, cân nhắc đổi model]",
            raw,
        )

    return result
