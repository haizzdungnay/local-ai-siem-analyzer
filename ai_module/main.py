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

_CONSOLE_METADATA_FIELDS = (
    "rule.id", "rule.description", "rule.level", "rule.mitre.id",
    "rule.mitre.tactic", "rule.mitre.technique", "agent.name", "agent.ip", "data.srcip",
)
_CONSOLE_UNSAFE_KEYS = {
    "full_log", "raw_log", "sample_log", "raw_prompt", "system_prompt", "user_prompt",
    "raw_response", "token", "access_token", "api_key", "password", "secret",
}


def _configure_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def _positive_limit(value: str) -> int:
    limit = int(value)
    if not 1 <= limit <= 50:
        raise argparse.ArgumentTypeError("limit phải nằm trong khoảng 1..50")
    return limit


def _safe_console_alert_text(extracted: dict) -> str:
    """Render only allow-listed alert metadata; raw event logs stay off the console."""
    safe_fields = {
        field: extracted[field]
        for field in _CONSOLE_METADATA_FIELDS
        if field in extracted
    }
    return format_for_llm(safe_fields) or "(no approved alert metadata available)"


def _hidden_alert_values(extracted: dict) -> list[str]:
    """Collect non-display fields so model echoes cannot disclose custom raw log fields."""
    values = []

    def collect(value):
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    for field, value in extracted.items():
        if field not in _CONSOLE_METADATA_FIELDS:
            collect(value)
    return values


def _redact_console_value(value, raw_values):
    """Do not let a model echo an input log or raw diagnostic field to the terminal."""
    if isinstance(value, dict):
        return {
            str(key): _redact_console_value(item, raw_values)
            for key, item in value.items()
            if str(key).lower() not in _CONSOLE_UNSAFE_KEYS
        }
    if isinstance(value, list):
        return [_redact_console_value(item, raw_values) for item in value]
    if isinstance(value, str):
        for raw_value in raw_values:
            if isinstance(raw_value, str) and raw_value:
                value = value.replace(raw_value, "[redacted raw alert]")
    return value


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
    parser.add_argument(
        "--unsafe-show-raw-alert", action="store_true",
        help="UNSAFE: print raw alert logs that may contain credentials or personal data",
    )
    args = parser.parse_args()

    cfg = resolve_config_paths(load_config(args.config))
    model = args.model or cfg["ollama"]["model"]
    ollama_timeout = cfg["ollama"].get("timeout", 120)
    language = args.language or cfg.get("dashboard", {}).get("default_language", "vi")

    if args.unsafe_show_raw_alert:
        print(
            "[!] WARNING: raw alert output can contain credentials and personal data.",
            file=sys.stderr,
        )

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
    rag_runtime = {
        "configured": bool(cfg.get("rag", {}).get("enabled")),
        "state": "disabled",
        "fallback": "rag_disabled",
    }
    if cfg.get("rag", {}).get("enabled"):
        try:
            rag = RuleRAG(
                data_dir=cfg["rag"]["data_dir"],
                embedding_model=cfg["rag"]["embedding_model"],
                base_url=cfg["ollama"]["base_url"],
                timeout=ollama_timeout,
            )
            indexed_count = rag.ensure_indexed()
            rag_runtime = {
                "configured": True,
                "state": "ready",
                "indexed_now": indexed_count,
            }
            if indexed_count:
                print(f"[*] Đã index {indexed_count} tài liệu RAG.")
        except Exception as e:
            e = type(e).__name__
            print(f"[!] Không khởi tạo được RAG, chạy tiếp không có RAG context: {e}")
            rag_runtime = {
                "configured": True,
                "state": "unavailable",
                "fallback": "initialization_failed",
                "error_type": e,
            }
            rag = None

    for i, alert in enumerate(alerts):
        print(f"\n{'='*60}")
        print(f"Alert {i+1}/{len(alerts)}")
        print(f"{'='*60}")

        extracted = extract_fields(alert, cfg["extractor"]["fields"])
        alert_text = format_for_llm(extracted)
        if args.unsafe_show_raw_alert:
            print(f"\n[Raw extracted alert]\n{alert_text}")
        else:
            print(f"\n[Alert metadata]\n{_safe_console_alert_text(extracted)}")

        rag_context = ""
        alert_rag_provenance = dict(rag_runtime)
        if rag:
            try:
                results = rag.query(
                    str(extracted.get("rule.id", "")),
                    str(extracted.get("rule.description", "")),
                )
                rag_context = rag.format_context(results)
                alert_rag_provenance.update({
                    "state": "context_used" if rag_context else "no_matching_context",
                    "result_count": len(results),
                })
                if not rag_context:
                    alert_rag_provenance["fallback"] = "no_matching_context"
            except Exception as e:
                e = type(e).__name__
                alert_rag_provenance.update({
                    "state": "query_failed",
                    "fallback": "query_failed",
                    "error_type": e,
                })
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
            safe_provenance = dict(provenance) if isinstance(provenance, dict) else {}
            safe_provenance["rag"] = alert_rag_provenance
            result = {"analysis": analysis, "provenance": safe_provenance}
            console_result = _redact_console_value(
                result, _hidden_alert_values(extracted),
            )
            print(f"\n[AI Analysis]\n{json.dumps(console_result, ensure_ascii=False, indent=2)}")
        except Exception as e:
            e = type(e).__name__
            print(f"\n[!] Lỗi khi gọi LLM: {e}")
            print(f"    Model dự kiến: {model}")

    print(f"\n{'='*60}")
    print(f"Xong {len(alerts)} alert. Model: {model}. Language: {language}")


if __name__ == "__main__":
    main()
