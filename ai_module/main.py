"""main.py — Entrypoint mô-đun AI phân tích alert Wazuh.

Usage:
    python main.py                 # đọc alert mới từ Wazuh API
    python main.py --demo          # chạy với alert mẫu (eval/samples/)
    python main.py --model 7b      # dùng qwen2.5:7b thay vì 3b

Stub: pipeline sẵn, chưa chạy thật. Implement ở GĐ3.
"""
import argparse
import json
import sys
from pathlib import Path

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
        print(f"[*] Đọc {args.limit} alert từ Wazuh API ({cfg['wazuh']['host']})...")
        alerts = fetch_alerts_api(cfg, limit=args.limit)

    # 3. RAG init (nếu bật)
    rag = None
    if cfg.get("rag", {}).get("enabled"):
        rag = RuleRAG(
            data_dir=cfg["rag"]["data_dir"],
            embedding_model=cfg["rag"]["embedding_model"]
        )
        # rag.index()  # chỉ chạy lần đầu hoặc khi update data

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
            except NotImplementedError:
                rag_context = "(RAG chưa implement)"

        # LLM phân tích
        try:
            result = analyze_alert(
                alert_text=alert_text,
                rag_context=rag_context,
                model=model,
                base_url=cfg["ollama"]["base_url"]
            )
            print(f"\n[AI Analysis]\n{json.dumps(result, ensure_ascii=False, indent=2)}")
        except NotImplementedError:
            print("\n[!] LLM chưa implement. Pipeline stub chạy đến đây.")
            print(f"    Model dự kiến: {model}")
            print(f"    RAG context: {rag_context[:100]}...")

    print(f"\n{'='*60}")
    print(f"Xong {len(alerts)} alert. Model: {model}")


if __name__ == "__main__":
    main()
