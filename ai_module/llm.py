"""llm.py — Gọi Ollama LLM local, ép output JSON schema.

Output schema: {summary, root_cause, severity, mitre, next_steps[]}
Stub: cấu trúc sẵn, chưa chạy thật. Implement ở GĐ3.
"""
import json
import ollama as ollama_sdk


# Schema ép LLM trả về
OUTPUT_SCHEMA = {
    "summary": "Tóm tắt cảnh báo 1-2 câu",
    "root_cause": "Nguyên nhân kích hoạt rule",
    "severity": "low | medium | high | critical",
    "mitre": "MITRE ATT&CK technique ID + tactic",
    "next_steps": ["Bước kiểm tra/xử lý 1", "Bước 2", "..."]
}

SYSTEM_PROMPT = """Bạn là chuyên gia phân tích an ninh mạng (SOC analyst).
Nhiệm vụ: đọc thông tin cảnh báo SIEM và giải thích bằng tiếng Việt, rõ ràng, ngắn gọn.

Luôn trả lời dạng JSON với đúng các trường sau:
{schema}

Không thêm text ngoài JSON. Không bịa thông tin không có trong alert.""".format(
    schema=json.dumps(OUTPUT_SCHEMA, ensure_ascii=False, indent=2)
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

    # TODO: implement actual Ollama call
    # client = ollama_sdk.Client(host=base_url)
    # response = client.chat(model=model, messages=[
    #     {"role": "system", "content": SYSTEM_PROMPT},
    #     {"role": "user", "content": user_msg},
    # ], format="json")
    # return _parse_response(response["message"]["content"])

    raise NotImplementedError("LLM call chưa implement — chạy main.py --demo để test pipeline")


def _parse_response(raw: str) -> dict:
    """Parse JSON từ LLM response. Fallback nếu LLM trả sai format."""
    try:
        result = json.loads(raw)
        # Validate required keys
        for key in OUTPUT_SCHEMA:
            if key not in result:
                result[key] = f"[MISSING: {key}]"
        return result
    except json.JSONDecodeError:
        return {
            "summary": raw[:200],
            "root_cause": "[LLM không trả JSON hợp lệ]",
            "severity": "unknown",
            "mitre": "",
            "next_steps": ["Kiểm tra lại prompt / thử model khác"]
        }
