"""
research/training/build_sft_jsonl.py — candidates ĐÃ REVIEW -> SFT JSONL (chat format) cho QLoRA.

Input (JSONL, mỗi dòng một cửa sổ alert đã gom):
  {
    "sample_id": "splunk-T1548.003-linux_auditd_sudo_su-w01",
    "split_group_id": "splunk:T1548.003/linux_auditd_sudo_su",   # mọi mẫu cùng kịch bản chung 1 nhóm
    "source": {"dataset": "...", "upstream_commit": "...", "sha256": "..."},
    "window_text": "<đầu ra format_window_for_llm(aggregate)>",
    "language": "vi",
    "target": { ...đúng WINDOW_OUTPUT_SCHEMA: summary, severity, key_findings, mitre,
                next_steps, response_language, confidence, assessment_basis... },
    "target_origin": "human" | "distilled",
    "review_status": "reviewed",
    "reviewed_by": ["Nguyen", "Duong"]
  }

Bảo đảm:
  - prompt giống production từng ký tự: system = build_effective_system_prompt("window", lang),
    user = _untrusted_message("WINDOW_DATA", ...) + nhắc ngôn ngữ — y như llm.analyze_window();
  - target phải parse được bằng llm._parse_window_payload (không rơi vào fallback);
  - từ chối mẫu chưa review, và mẫu có source.sha256 thuộc tập test đã khóa;
  - chia train/val theo split_group_id (không bao giờ cùng một kịch bản ở hai tập).

    python research/training/build_sft_jsonl.py --input candidates.reviewed.jsonl \
        --out-dir research/training/outputs/sft-v1 --val-ratio 0.15 --seed 42
"""
import argparse
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ai_module"))
sys.path.insert(0, str(ROOT / "eval"))

import llm  # noqa: E402
from verify_test_lock import forbidden_hashes, load_lock  # noqa: E402

REQUIRED = ("sample_id", "split_group_id", "window_text", "target", "review_status")


def build_messages(window_text: str, target: dict, language: str = "vi") -> list[dict]:
    system = llm.build_effective_system_prompt("window", language)
    user = "\n\n".join([llm._untrusted_message("WINDOW_DATA", window_text),
                        llm._trusted_language_reminder(language)])
    assistant = json.dumps(target, ensure_ascii=False, separators=(",", ":"))
    return [{"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant}]


def validate(sample: dict, forbidden: set[str]) -> str | None:
    missing = [k for k in REQUIRED if not sample.get(k)]
    if missing:
        return f"thiếu trường {missing}"
    if sample["review_status"] != "reviewed" or not sample.get("reviewed_by"):
        return "chưa review (review_status != reviewed hoặc thiếu reviewed_by)"
    if (sample.get("source") or {}).get("sha256") in forbidden:
        return "nguồn thuộc tập test đã khóa"
    language = sample.get("language", "vi")
    # Cùng bộ kiểm tra production dùng cho output model: target sai schema -> "local_fallback".
    _, origin = llm._parse_window_payload(json.dumps(sample["target"], ensure_ascii=False), language)
    if origin == "local_fallback":
        return "target không hợp lệ theo WINDOW_OUTPUT_SCHEMA"
    if sample["target"].get("response_language") != language:
        return "target.response_language khác language của mẫu"
    return None


def split_groups(groups: list[str], val_ratio: float, seed: int) -> set[str]:
    ordered = sorted(set(groups))
    random.Random(seed).shuffle(ordered)
    n_val = max(1, round(len(ordered) * val_ratio)) if len(ordered) > 1 else 0
    return set(ordered[:n_val])


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--input", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--val-ratio", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    forbidden = forbidden_hashes(load_lock())
    samples, rejected = [], Counter()
    for line_no, line in enumerate(Path(args.input).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        sample = json.loads(line)
        reason = validate(sample, forbidden)
        if reason:
            rejected[reason] += 1
            print(f"  bỏ dòng {line_no} ({sample.get('sample_id')}): {reason}", file=sys.stderr)
            continue
        samples.append(sample)
    if not samples:
        raise SystemExit("Không còn mẫu hợp lệ.")

    val_groups = split_groups([s["split_group_id"] for s in samples], args.val_ratio, args.seed)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    with (out / "train.jsonl").open("w", encoding="utf-8", newline="\n") as tr, \
         (out / "val.jsonl").open("w", encoding="utf-8", newline="\n") as va:
        for s in samples:
            split = "val" if s["split_group_id"] in val_groups else "train"
            row = {"sample_id": s["sample_id"], "split_group_id": s["split_group_id"],
                   "target_origin": s.get("target_origin", "unknown"),
                   "messages": build_messages(s["window_text"], s["target"], s.get("language", "vi"))}
            (va if split == "val" else tr).write(json.dumps(row, ensure_ascii=False) + "\n")
            counts[split] += 1
    manifest = {
        "input": str(args.input), "input_sha256": hashlib.sha256(Path(args.input).read_bytes()).hexdigest(),
        "seed": args.seed, "val_ratio": args.val_ratio, "counts": dict(counts),
        "val_groups": sorted(val_groups), "rejected": dict(rejected),
        "prompt_version": llm.SOC_PROMPT_VERSION,
        "target_origin": dict(Counter(s.get("target_origin", "unknown") for s in samples)),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                                       encoding="utf-8", newline="\n")
    print(f"[OK] train={counts['train']} val={counts['val']} rejected={sum(rejected.values())} -> {out}")


if __name__ == "__main__":
    main()
