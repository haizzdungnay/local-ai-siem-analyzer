"""
eval/playbook_ab_smoke.py — phép thử A/B nhanh cho playbook Tầng 3 (chưa phải đánh giá).

Cùng một alert mẫu, gọi LLM hai lần với cấu hình giống hệt nhau:
  A: không có playbook (giống pipeline hiện tại khi RAG không trả về gì)
  B: thêm playbook của rule.id vào khối context (exact lookup theo rule.id)
rồi in next_steps cạnh nhau. N=1, chỉ để kiểm tra playbook có được model dùng hay không;
kết luận định lượng phải chờ ablation trên tập test khóa.

Chạy từ thư mục gốc repo (cần Ollama):
    python eval/playbook_ab_smoke.py
    python eval/playbook_ab_smoke.py --alert eval/samples/alert-ssh-bruteforce.json --model qwen2.5:7b
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_module"))

import yaml  # noqa: E402

from extractor import extract_fields, format_for_llm  # noqa: E402
from llm import analyze_alert  # noqa: E402
from reader import load_config, resolve_config_paths  # noqa: E402

PLAYBOOK_PATH = ROOT / "ai_module" / "rag_data" / "playbooks.yaml"


def load_playbook(rule_id: str, path: Path = PLAYBOOK_PATH) -> dict | None:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for entry in data.get("playbooks") or []:
        if str(entry.get("rule_id")) == str(rule_id):
            return entry
    return None


def playbook_context(entry: dict) -> str:
    """Khối PLAYBOOK đưa vào context: chỉ các trường dùng cho điều tra, bỏ trường quản trị."""
    keep = {k: entry[k] for k in ("rule_id", "title", "mitre", "trigger", "facts", "verify",
                                  "branches", "fp_conditions", "do_not") if entry.get(k)}
    body = yaml.safe_dump(keep, allow_unicode=True, sort_keys=False, width=1000)
    return (
        f"[PLAYBOOK rule={entry.get('rule_id')} status={entry.get('status', 'draft')}]\n"
        "Hướng dẫn điều tra cho rule này. Dùng để viết next_steps: bước xác minh trước, "
        "containment sau; điền giá trị thật từ ALERT (srcip, agent, user); "
        "không dùng giá trị không có trong ALERT.\n" + body
    )


def run(alert_text: str, context: str, cfg: dict, model: str, language: str) -> dict:
    analysis, provenance = analyze_alert(
        alert_text=alert_text,
        rag_context=context,
        model=model,
        base_url=cfg["ollama"]["base_url"],
        timeout=cfg["ollama"].get("timeout", 120),
        language=language,
        include_provenance=True,
        allow_remote=cfg["ollama"].get("allow_remote", False),
    )
    return {"analysis": analysis, "latency_s": (provenance or {}).get("total_duration", 0) / 1e9,
            "output_origin": (provenance or {}).get("output_origin")}


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="A/B playbook smoke test (N=1)")
    ap.add_argument("--alert", default=str(ROOT / "eval" / "samples" / "alert-ssh-bruteforce.json"))
    ap.add_argument("--model", default=None)
    ap.add_argument("--language", default="vi", choices=("vi", "en"))
    ap.add_argument("--out", default=str(ROOT / "eval" / "raw_exports" / "smoke" / "playbook-ab.json"))
    args = ap.parse_args()

    cfg = resolve_config_paths(load_config())
    model = args.model or cfg["ollama"]["model"]
    alert = json.loads(Path(args.alert).read_text(encoding="utf-8"))
    extracted = extract_fields(alert, cfg["extractor"]["fields"])
    alert_text = format_for_llm(extracted)
    rule_id = str(extracted.get("rule.id", ""))

    entry = load_playbook(rule_id)
    if entry is None:
        sys.exit(f"!! Không có playbook cho rule {rule_id} trong {PLAYBOOK_PATH}")
    context_b = playbook_context(entry)

    print(f"Alert: {args.alert} | rule {rule_id} | model {model}")
    a = run(alert_text, "", cfg, model, args.language)
    b = run(alert_text, context_b, cfg, model, args.language)

    for label, res in (("A — KHÔNG playbook", a), ("B — CÓ playbook", b)):
        an = res["analysis"]
        print("\n" + "=" * 78)
        print(f"{label}   (severity={an.get('severity')}, origin={res['output_origin']}, {res['latency_s']:.1f}s)")
        print("=" * 78)
        for i, step in enumerate(an.get("next_steps") or [], 1):
            print(f"  {i}. {step}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"alert": args.alert, "rule_id": rule_id, "model": model,
                               "playbook_context": context_b, "A_no_playbook": a, "B_playbook": b},
                              ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"\nĐã ghi: {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
