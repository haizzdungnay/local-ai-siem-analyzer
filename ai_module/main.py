"""main.py — Entrypoint mô-đun AI phân tích alert Wazuh.

Đúng theo kế hoạch GĐ3 trong KE_HOACH.md:
Ollama, trích trường chính, RAG, ép JSON schema
{summary, root_cause, severity, mitre, next_steps}

Usage:
    python main.py                 # đọc alert mới từ Wazuh API
    python main.py --demo          # chạy với alert mẫu (eval/samples/)
    python main.py --model 7b      # dùng qwen2.5:7b thay vì 3b
"""
import argparse
import json
import sys

from reader import load_config, fetch_alerts_api, load_sample_alerts
from extractor import extract_fields, format_for_llm
from rag import RuleRAG
from llm import analyze_alert


def main():
    parser = argparse.ArgumentParser(description="AI local phân tích alert Wazuh")
    parser.add_argument("--demo", action="store_true", help="Chạy với alert mẫu thay vì API")
    parser.add_argument("--model", default=None, help="Override model (vd: qwen2.5:7b)")
    parser.add_argument("--config", default="config.yaml", help="Path config YAML")
    parser.add_argument("--limit", type=int, default=5, help="Số alert đọc từ API")
    args = parser.parse_args()

    # 1. Load config
    cfg = load_config(args.config)
    model = args.model or cfg["ollama"]["model"]

    # 2. Đọc alert
    if args.demo:
        print("[DEMO] Load alert mẫu từ eval/samples/")
        alerts = load_sample_alerts("../eval/samples")
        if not alerts:
            print("!! Chưa có alert mẫu. Tạo file JSON trong eval/samples/ trước.")
            print("   Xem eval/samples/sample-ssh-bruteforce.json.example")
            sys.exit(1)
    else:
        print(f"[*] Đọc {args.limit} alert từ Wazuh Indexer ({cfg['wazuh_indexer']['host']}:{cfg['wazuh_indexer']['port']})...")
        alerts = fetch_alerts_api(cfg, limit=args.limit)

    # 3. RAG init (nếu bật)
    rag = None
    if cfg.get("rag", {}).get("enabled"):
        try:
            rag = RuleRAG(
                data_dir=cfg["rag"]["data_dir"],
                embedding_model=cfg["rag"]["embedding_model"],
                base_url=cfg["ollama"]["base_url"],
            )
        except Exception as e:
            print(f"[!] Không khởi tạo được RAG, chạy tiếp không có RAG context: {e}")
            rag = None

    # 4. Pipeline: extract → RAG → LLM
    for i, alert in enumerate(alerts):
        print(f"\n{'='*60}")
        print(f"Alert {i+1}/{len(alerts)}")
        print(f"{'='*60}")

        # Trích trường chính
        extracted = extract_fields(alert, cfg["extractor"]["fields"])
        alert_text = format_for_llm(extracted)
        print(f"\n[Extracted]\n{alert_text}")

        # RAG tra cứu
        rag_context = ""
        if rag:
            rule_id = extracted.get("rule.id", "")
            desc = extracted.get("rule.description", "")
            try:
                results = rag.query(str(rule_id), str(desc))
                rag_context = rag.format_context(results)
            except Exception as e:
                rag_context = ""
                print(f"[!] RAG query lỗi (bỏ qua context): {e}")

        # LLM phân tích
        try:
            result = analyze_alert(
                alert_text=alert_text,
                rag_context=rag_context,
                model=model,
                base_url=cfg["ollama"]["base_url"]
            )
            print(f"\n[AI Analysis]\n{json.dumps(result, ensure_ascii=False, indent=2)}")
        except Exception as e:
            print(f"\n[!] Lỗi khi gọi LLM: {e}")
            print(f"    Model dự kiến: {model}")

    print(f"\n{'='*60}")
    print(f"Xong {len(alerts)} alert. Model: {model}")


if __name__ == "__main__":
    main()
