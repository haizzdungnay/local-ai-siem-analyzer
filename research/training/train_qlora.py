"""
research/training/train_qlora.py — QLoRA SFT (HF transformers + PEFT + bitsandbytes) cho Qwen2.5.

Chạy được trên Windows native (không cần WSL2). Loss chỉ tính trên token của assistant
(JSON output), prompt hệ thống + WINDOW_DATA bị mask (-100).

    # 1) kiểm tra môi trường CUDA/VRAM bằng vài mẫu giả, model nhỏ:
    python research/training/train_qlora.py --config research/training/configs/qwen2.5-3b-qlora.yaml --smoke
    # 2) train thật:
    python research/training/train_qlora.py --config research/training/configs/qwen2.5-7b-qlora.yaml

Output (gitignored): research/training/outputs/<run_name>/ gồm adapter LoRA, run_manifest.json.
"""
import argparse
import hashlib
import inspect
import json
import math
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_config(path: Path) -> dict:
    import yaml
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def tokenize_example(messages: list[dict], tokenizer, max_len: int,
                     template_kwargs: dict | None = None, assistant_suffix: str | None = None,
                     debug: dict | None = None) -> dict | None:
    """input_ids = prompt (y như lúc suy luận) + câu trả lời; labels = -100 cho phần prompt.

    prompt_text = chat template của system+user với add_generation_prompt=True (và template_kwargs,
    vd {"enable_thinking": False} cho Qwen3/3.5 — khớp Ollama think=False). Phần trả lời lấy từ
    template của cả hội thoại nếu nó bắt đầu bằng prompt_text; nếu không (Qwen3.5 render lượt
    assistant khác lúc sinh), dùng nội dung assistant + assistant_suffix (mặc định eos_token).
    Prompt và trả lời được tokenize riêng nên ranh giới label luôn chính xác.
    """
    kw = template_kwargs or {}
    prompt_text = tokenizer.apply_chat_template(messages[:-1], tokenize=False,
                                                add_generation_prompt=True, **kw)
    full_text = tokenizer.apply_chat_template(messages, tokenize=False,
                                              add_generation_prompt=False, **kw)
    answer = messages[-1]["content"]
    if full_text.startswith(prompt_text) and answer in full_text[len(prompt_text):]:
        completion, mode = full_text[len(prompt_text):], "template"
    else:
        completion, mode = answer + (assistant_suffix if assistant_suffix is not None
                                     else (tokenizer.eos_token or "")), "generation_prompt+suffix"
    prompt_ids = tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
    completion_ids = tokenizer(completion, add_special_tokens=False)["input_ids"]
    if debug is not None and not debug:
        debug.update({"mode": mode, "prompt_tail": prompt_text[-160:], "completion_head": completion[:120],
                      "completion_tail": completion[-40:]})
    ids = prompt_ids + completion_ids
    if len(ids) > max_len:
        return None  # bỏ mẫu quá dài thay vì cắt mất JSON đích
    return {"input_ids": ids, "attention_mask": [1] * len(ids),
            "labels": [-100] * len(prompt_ids) + completion_ids}


def smoke_samples(n: int = 8, filler_lines: int = 0) -> list[dict]:
    target = {"summary": "Mẫu smoke test.", "severity": "low", "key_findings": ["smoke"],
              "mitre": [], "next_steps": ["Không có hành động — dữ liệu giả."],
              "response_language": "vi", "confidence": 50,
              "assessment_basis": {"observed_facts": ["smoke"], "inferences": [],
                                   "uncertainties": [], "limitations": ["dữ liệu giả"]}}
    return [{"messages": [{"role": "system", "content": "Bạn là SOC analyst."},
                          {"role": "user", "content": f"WINDOW_DATA smoke {i}\n" + FILLER_LINE * filler_lines},
                          {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)}]}
            for i in range(n)]


# Một dòng giả gần giống WINDOW_DATA (rule/level/agent/đếm) để đo tốc độ và VRAM ở độ dài thật.
FILLER_LINE = ("- rule 5710 level 5 sshd: Attempt to login using a non-existent user | agent lab-01 | "
               "srcip 10.0.0.30 | count 16 | first 2026-01-01T00:00:00Z | last 2026-01-01T00:01:00Z\n")


def filler_lines_for(tokenizer, target_tokens: int, template_kwargs: dict | None = None) -> int:
    """Số dòng FILLER_LINE để cả mẫu smoke (prompt + trả lời) dài xấp xỉ target_tokens token."""
    if target_tokens <= 0:
        return 0
    base = tokenize_example(smoke_samples(1)[0]["messages"], tokenizer, 10 ** 9, template_kwargs)
    per_line = len(tokenizer(FILLER_LINE, add_special_tokens=False)["input_ids"])
    return max(0, (target_tokens - len(base["input_ids"])) // max(1, per_line))


class Collator:
    def __init__(self, pad_id: int):
        self.pad_id = pad_id

    def __call__(self, batch):
        import torch
        width = max(len(x["input_ids"]) for x in batch)
        out = {"input_ids": [], "attention_mask": [], "labels": []}
        for x in batch:
            pad = width - len(x["input_ids"])
            out["input_ids"].append(x["input_ids"] + [self.pad_id] * pad)
            out["attention_mask"].append(x["attention_mask"] + [0] * pad)
            out["labels"].append(x["labels"] + [-100] * pad)
        return {k: torch.tensor(v) for k, v in out.items()}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_adapter(init: dict) -> Path:
    """Tải snapshot thư mục adapter về cache local (khóa revision) và trả về đường dẫn thư mục.

    Không để PEFT tự dò file trên Hub: với subfolder + revision, bước dò của PEFT có thể báo
    'không có safetensors' rồi thử adapter_model.bin (404) dù file có thật.
    """
    from huggingface_hub import snapshot_download
    sub = (init.get("subfolder") or "").strip("/")
    root = snapshot_download(repo_id=init["repo"], revision=init.get("revision") or None,
                             allow_patterns=[f"{sub}/*"] if sub else None)
    path = Path(root) / sub if sub else Path(root)
    if not (path / "adapter_config.json").exists() or not list(path.glob("adapter_model.*")):
        raise SystemExit(f"!! Snapshot thiếu adapter_config.json / adapter_model.*: {path}")
    return path


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--smoke", action="store_true", help="8 mẫu giả, 5 step: chỉ kiểm tra môi trường")
    ap.add_argument("--smoke-len", type=int, default=0,
                    help="với --smoke: độ dài mẫu giả tính bằng token (xấp xỉ), vd 2000 để đo như dữ liệu thật")
    ap.add_argument("--list-modules", action="store_true",
                    help="nạp model 4-bit, in tên các lớp Linear (chọn lora.target_modules) rồi thoát")
    args = ap.parse_args()
    cfg = load_config(Path(args.config))

    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig,
                              Trainer, TrainingArguments)
    from transformers import __version__ as transformers_version

    if not torch.cuda.is_available():
        raise SystemExit("!! Không thấy CUDA. Cài PyTorch bản CUDA 12.8+ cho RTX 50xx (xem research/training/README.md).")
    gpu = torch.cuda.get_device_name(0)
    print(f"[*] GPU: {gpu} | torch {torch.__version__} | CUDA {torch.version.cuda}")

    run_name = cfg["run_name"] + ("-smoke" if args.smoke else "")
    out_dir = ROOT / "research" / "training" / "outputs" / run_name
    out_dir.mkdir(parents=True, exist_ok=True)

    remote = bool(cfg.get("trust_remote_code", False))
    template_kwargs = cfg.get("chat_template_kwargs") or {}
    tokenizer = AutoTokenizer.from_pretrained(cfg["base_model"], trust_remote_code=remote)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    max_len = int(cfg.get("max_seq_len", 2048))

    if args.smoke or args.list_modules:
        lines = filler_lines_for(tokenizer, min(args.smoke_len, max_len - 8), template_kwargs)
        train_rows, val_rows = smoke_samples(8, lines), smoke_samples(2, lines)
        data_files = {}
    else:
        data_dir = ROOT / cfg["data_dir"]
        train_rows, val_rows = read_jsonl(data_dir / "train.jsonl"), read_jsonl(data_dir / "val.jsonl")
        data_files = {name: sha256(data_dir / name) for name in ("train.jsonl", "val.jsonl", "manifest.json")
                      if (data_dir / name).exists()}

    def encode(rows):
        encoded = [tokenize_example(r["messages"], tokenizer, max_len, template_kwargs,
                                    cfg.get("assistant_suffix"), debug) for r in rows]
        kept = [e for e in encoded if e is not None]
        return kept, len(encoded) - len(kept)

    debug = {}
    train_ds, dropped_train = encode(train_rows)
    print(f"[*] chat template mode: {debug.get('mode')}")
    print(f"    ...cuối prompt : {debug.get('prompt_tail')!r}")
    print(f"    đầu trả lời... : {debug.get('completion_head')!r}")
    print(f"    ...cuối trả lời: {debug.get('completion_tail')!r}")
    val_ds, dropped_val = encode(val_rows)
    print(f"[*] train={len(train_ds)} (bỏ {dropped_train} quá dài) val={len(val_ds)} (bỏ {dropped_val})")
    if not train_ds:
        raise SystemExit(f"!! Không còn mẫu train nào sau khi lọc độ dài (max_seq_len={max_len}). "
                         "Tăng max_seq_len trong config hoặc giảm độ dài mẫu.")
    if train_ds:
        lengths = sorted(len(x["input_ids"]) for x in train_ds)
        print(f"[*] độ dài token: min {lengths[0]}, median {lengths[len(lengths) // 2]}, max {lengths[-1]}")

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(cfg["base_model"], quantization_config=bnb,
                                                 dtype=torch.bfloat16, device_map={"": 0},
                                                 trust_remote_code=remote)
    if args.list_modules:
        names = sorted({name.rsplit(".", 1)[-1] for name, mod in model.named_modules()
                        if mod.__class__.__name__ in ("Linear", "Linear4bit")})
        print(f"[*] {model.config.model_type}: lớp Linear -> {names}")
        print(f"[*] VRAM sau khi nạp 4-bit: {torch.cuda.memory_allocated() / 1024 ** 3:.1f} GB")
        return
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    init = cfg.get("init_adapter")
    init_adapter_files = {}
    if init:
        # Train TIẾP một adapter có sẵn (vd adapter pentest của bên thứ ba): r/alpha/target_modules
        # lấy từ adapter_config.json của adapter đó, khối `lora` trong config bị bỏ qua.
        from peft import PeftModel
        adapter_dir = resolve_adapter(init)
        model = PeftModel.from_pretrained(model, str(adapter_dir), is_trainable=True)
        init_adapter_files = {f.name: sha256(f) for f in sorted(adapter_dir.iterdir())
                              if f.suffix in (".safetensors", ".json")}
        print(f"[*] Train tiếp adapter {init['repo']}/{init.get('subfolder', '')} @ {init.get('revision')}"
              f" -> {adapter_dir}")
    else:
        lora = LoraConfig(r=cfg["lora"]["r"], lora_alpha=cfg["lora"]["alpha"],
                          lora_dropout=cfg["lora"]["dropout"], bias="none", task_type="CAUSAL_LM",
                          target_modules=cfg["lora"]["target_modules"])  # list tên lớp hoặc "all-linear"
        model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    t = cfg["train"]
    epochs = 1 if args.smoke else t["epochs"]
    grad_accum = 1 if args.smoke else t["grad_accum"]
    total_steps = 5 if args.smoke else max(1, math.ceil(len(train_ds) / grad_accum) * epochs)
    warmup_steps = max(1, int(total_steps * t.get("warmup_ratio", 0.05)))
    wanted = dict(
        output_dir=str(out_dir), run_name=run_name, seed=int(cfg.get("seed", 42)),
        num_train_epochs=epochs, max_steps=5 if args.smoke else -1,
        per_device_train_batch_size=1, per_device_eval_batch_size=1,
        gradient_accumulation_steps=grad_accum,
        learning_rate=t["lr"], lr_scheduler_type="cosine", warmup_steps=warmup_steps,
        bf16=True, logging_steps=1 if args.smoke else 5,
        eval_strategy="no" if args.smoke else "epoch", save_strategy="no" if args.smoke else "epoch",
        save_total_limit=2, report_to=[], gradient_checkpointing=True,
        optim="paged_adamw_8bit", dataloader_num_workers=0,
    )
    # transformers 5.x đổi/bỏ một số tham số (vd warmup_ratio): chỉ truyền tham số bản đang cài nhận.
    accepted = set(inspect.signature(TrainingArguments.__init__).parameters)
    dropped = sorted(k for k in wanted if k not in accepted)
    if dropped:
        print(f"[!] transformers {transformers_version} không nhận {dropped} — bỏ qua")
    targs = TrainingArguments(**{k: v for k, v in wanted.items() if k in accepted})
    print(f"[*] tổng step {total_steps}, warmup {warmup_steps}, grad_accum {grad_accum}, epochs {epochs}")
    trainer = Trainer(model=model, args=targs, train_dataset=train_ds,
                      eval_dataset=None if args.smoke else val_ds,
                      data_collator=Collator(tokenizer.pad_token_id))
    torch.cuda.reset_peak_memory_stats()
    started = time.time()
    result = trainer.train()
    elapsed = time.time() - started
    peak_gb = torch.cuda.max_memory_allocated() / 1024 ** 3

    model.save_pretrained(out_dir / "adapter")
    tokenizer.save_pretrained(out_dir / "adapter")
    metrics = {"train_loss": result.training_loss}
    if not args.smoke and val_ds:
        metrics.update(trainer.evaluate())
    manifest = {"run_name": run_name, "smoke": args.smoke, "config": cfg, "config_sha256": sha256(Path(args.config)),
                "data_files_sha256": data_files, "init_adapter_files_sha256": init_adapter_files, "train_examples": len(train_ds), "val_examples": len(val_ds),
                "dropped_too_long": {"train": dropped_train, "val": dropped_val},
                "metrics": metrics, "wall_seconds": round(elapsed, 1), "peak_vram_gb": round(peak_gb, 2),
                "gpu": gpu, "torch": torch.__version__, "cuda": torch.version.cuda,
                "transformers": transformers_version, "dropped_training_args": dropped,
                "total_steps": total_steps, "warmup_steps": warmup_steps,
                "platform": platform.platform(), "log_history": trainer.state.log_history}
    (out_dir / "run_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, default=str) + "\n",
                                               encoding="utf-8", newline="\n")
    tokens = sum(len(x["input_ids"]) for x in train_ds[: targs.max_steps]) if args.smoke else None
    print(f"[OK] {elapsed/60:.1f} phút, VRAM đỉnh {peak_gb:.1f} GB, loss {result.training_loss:.4f} -> {out_dir}")
    if tokens:
        print(f"[*] thông lượng ≈ {tokens / elapsed:.0f} token/giây (gồm cả step đầu khởi động)")


if __name__ == "__main__":
    main()
