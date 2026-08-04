"""main.py — Entrypoint mô-đun AI phân tích alert Wazuh.

Usage:
    python ai_module/main.py                 # đọc alert mới từ Wazuh Indexer
    python ai_module/main.py --demo          # chạy với alert mẫu
    python ai_module/main.py --model qwen2.5:7b
    python ai_module/main.py --demo --language en
"""
import argparse
import json
import sys

from extractor import extract_fields, format_for_llm
from llm import analyze_alert
from rag import RuleRAG
from reader import MODULE_DIR, fetch_alerts_api, load_config, load_sample_alerts, resolve_config_paths


PROJECT_DIR = MODULE_DIR.parent
SAMPLES_DIR = PROJECT_DIR / "eval" / "samples"


def _configure_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def _positive_limit(value: str) -> int:
    limit = int(value)
    if not 1 <= limit <= 50:
        raise argparse.ArgumentTypeError("limit phải nằm trong khoảng 1..50")
    return limit


def main():
    _configure_console_encoding()
    parser = argparse.ArgumentParser(description="AI local phân tích alert Wazuh")
    parser.add_argument("--demo", action="store_true", help="Chạy với alert mẫu thay vì API")
    parser.add_argument("--model", default=None, help="Override model (vd: qwen2.5:7b)")
    parser.add_argument(
        "--language", choices=("vi", "en"), default=None,
        help="Ngon ngu phan tich: vi hoac en (mac dinh theo dashboard.default_language)",
    )
    parser.add_argument("--config", default=str(MODULE_DIR / "config.yaml"), help="Path config YAML")
    parser.add_argument("--limit", type=_positive_limit, default=5, help="Số alert đọc từ API (1-50)")
    args = parser.parse_args()

    cfg = resolve_config_paths(load_config(args.config))
    model = args.model or cfg["ollama"]["model"]
    ollama_timeout = cfg["ollama"].get("timeout", 120)
    language = args.language or cfg.get("dashboard", {}).get("default_language", "vi")

    if args.demo:
        print("[DEMO] Load alert mẫu từ eval/samples/")
        alerts = load_sample_alerts(str(SAMPLES_DIR))
        if not alerts:
            print("!! Chưa có alert mẫu. Tạo file JSON trong eval/samples/ trước.")
            sys.exit(1)
    else:
        idx_cfg = cfg["wazuh_indexer"]
        print(f"[*] Đọc {args.limit} alert từ Wazuh Indexer ({idx_cfg['host']}:{idx_cfg['port']})...")
        alerts = fetch_alerts_api(cfg, limit=args.limit)

    rag = None
    if cfg.get("rag", {}).get("enabled"):
        try:
            rag = RuleRAG(
                data_dir=cfg["rag"]["data_dir"],
                embedding_model=cfg["rag"]["embedding_model"],
                base_url=cfg["ollama"]["base_url"],
                timeout=ollama_timeout,
            )
            indexed_count = rag.ensure_indexed()
            if indexed_count:
                print(f"[*] Đã index {indexed_count} tài liệu RAG.")
        except Exception as e:
            print(f"[!] Không khởi tạo được RAG, chạy tiếp không có RAG context: {e}")
            rag = None

    for i, alert in enumerate(alerts):
        print(f"\n{'='*60}")
        print(f"Alert {i+1}/{len(alerts)}")
        print(f"{'='*60}")

        extracted = extract_fields(alert, cfg["extractor"]["fields"])
        alert_text = format_for_llm(extracted)
        print(f"\n[Extracted]\n{alert_text}")

        rag_context = ""
        if rag:
            try:
                results = rag.query(
                    str(extracted.get("rule.id", "")),
                    str(extracted.get("rule.description", "")),
                )
                rag_context = rag.format_context(results)
            except Exception as e:
                print(f"[!] RAG query lỗi (bỏ qua context): {e}")

        try:
            analysis, provenance = analyze_alert(
                alert_text=alert_text,
                rag_context=rag_context,
                model=model,
                base_url=cfg["ollama"]["base_url"],
                timeout=ollama_timeout,
                language=language,
                include_provenance=True,
                allow_remote=cfg["ollama"].get("allow_remote", False),
            )
            result = {"analysis": analysis, "provenance": provenance}
            print(f"\n[AI Analysis]\n{json.dumps(result, ensure_ascii=False, indent=2)}")
        except Exception as e:
            print(f"\n[!] Lỗi khi gọi LLM: {e}")
            print(f"    Model dự kiến: {model}")

    print(f"\n{'='*60}")
    print(f"Xong {len(alerts)} alert. Model: {model}. Language: {language}")


if __name__ == "__main__":
    main()
