"""
eval/playbook_ab_smoke.py — phép thử A/B nhanh cho playbook Tầng 3 (chưa phải đánh giá).

Cùng một alert mẫu, gọi LLM ba lần với cấu hình giống hệt nhau:
  A: không có playbook (giống pipeline hiện tại khi RAG không trả về gì)
  B: playbook đi qua rag_context → bị bọc UNTRUSTED_RAG_CONTEXT (cách cũ)
  C: playbook TRUSTED; model chỉ chọn nhánh (enum), next_steps do code dựng (block v5)
Cả B và C dùng cùng playbook tra chính xác theo rule.id; khác nhau chỉ ở chỗ đặt và nhãn
tin cậy. In next_steps cạnh nhau kèm số bước có rule ID (check_next_steps). N=1, chỉ để kiểm tra playbook có được model dùng hay không;
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

from extractor import extract_fields, format_for_llm  # noqa: E402
from llm import analyze_alert  # noqa: E402
from playbooks import PLAYBOOK_PATH, check_next_steps, get_playbook, playbook_body  # noqa: E402
from reader import load_config, resolve_config_paths  # noqa: E402

def playbook_context(entry: dict) -> str:
    """Cách B (cũ): playbook dạng văn bản đưa qua rag_context."""
    return (
        f"[PLAYBOOK rule={entry.get('rule_id')} status={entry.get('status', 'draft')}]\n"
        "Hướng dẫn điều tra cho rule này. Dùng để viết next_steps: bước xác minh trước, "
        "containment sau; điền giá trị thật từ ALERT (srcip, agent, user); "
        "không dùng giá trị không có trong ALERT.\n" + playbook_body(entry)
    )


def run(alert_text: str, context: str, cfg: dict, model: str, language: str,
        playbook: dict | None = None, extracted: dict | None = None) -> dict:
    analysis, provenance = analyze_alert(
        alert_text=alert_text,
        rag_context=context,
        playbook=playbook,
        extracted=extracted,
        model=model,
        base_url=cfg["ollama"]["base_url"],
        timeout=cfg["ollama"].get("timeout", 120),
        language=language,
        include_provenance=True,
        allow_remote=cfg["ollama"].get("allow_remote", False),
    )
    return {"analysis": analysis, "latency_s": (provenance or {}).get("total_duration", 0) / 1e9,
            "output_origin": (provenance or {}).get("output_origin"),
            "playbook": (provenance or {}).get("playbook")}


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

    entry = get_playbook(rule_id)
    if entry is None:
        sys.exit(f"!! Không có playbook cho rule {rule_id} trong {PLAYBOOK_PATH}")
    context_b = playbook_context(entry)

    print(f"Alert: {args.alert} | rule {rule_id} | model {model}")
    arms = {
        "A_no_playbook": ("A — KHÔNG playbook", run(alert_text, "", cfg, model, args.language)),
        "B_playbook": ("B — playbook qua rag_context (UNTRUSTED)",
                       run(alert_text, context_b, cfg, model, args.language)),
        "C_trusted_playbook": ("C — TRUSTED_PLAYBOOK trong system prompt",
                               run(alert_text, "", cfg, model, args.language, playbook=entry,
                                   extracted=extracted)),
    }
    for key, (label, res) in arms.items():
        an = res["analysis"]
        res["check"] = check_next_steps(an.get("next_steps"), entry)
        chk = res["check"]
        print("\n" + "=" * 78)
        print(f"{label}   (severity={an.get('severity')}, origin={res['output_origin']}, {res['latency_s']:.1f}s)")
        print(f"  bước có rule ID: {chk['steps_with_rule_id']}/{chk['steps_total']} | "
              f"verify được nêu: {','.join(chk['verify_cited']) or '-'} / {chk['verify_total']}")
        pb = res.get("playbook") or {}
        if pb.get("mode") == "signals":
            for sid, item in (pb.get("signals") or {}).items():
                print(f"  tín hiệu {sid}: {item['answer']}  (model: {item.get('model_answer')}, "
                      f"regex: {item.get('rule_answer')})  [{item['value']}]")
            print(f"  nhánh CODE chọn: {pb['branch_id']} | severity theo: {pb.get('severity_source')} "
                  f"(model nói: {pb.get('model_severity', an.get('severity'))})")
        elif pb.get("branch_id"):
            print(f"  nhánh model chọn: {pb['branch_id']} (hợp lệ: {pb.get('branch_valid')}) | "
                  f"severity theo: {pb.get('severity_source')} (model nói: {pb.get('model_severity', an.get('severity'))})")
            print(f"  căn cứ: {pb.get('branch_evidence')}")
        print("=" * 78)
        for i, step in enumerate(an.get("next_steps") or [], 1):
            print(f"  {i}. {step}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"alert": args.alert, "rule_id": rule_id, "model": model,
                               "playbook_context": context_b,
                               **{key: res for key, (_, res) in arms.items()}},
                              ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"\nĐã ghi: {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
