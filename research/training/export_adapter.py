"""
research/training/export_adapter.py — gộp adapter LoRA vào model gốc (fp16) để chuyển sang GGUF/Ollama.

    python research/training/export_adapter.py --config research/training/configs/qwen2.5-7b-qlora.yaml
    # -> research/training/outputs/<run_name>/merged/   (safetensors fp16, ~15 GB cho 7B)

Sau đó (llama.cpp, xem README.md):
    python llama.cpp/convert_hf_to_gguf.py <merged> --outtype f16 --outfile <run>.f16.gguf
    llama.cpp/llama-quantize <run>.f16.gguf <run>.Q4_K_M.gguf Q4_K_M
    ollama create soc-qwen2.5-7b-qlora-v1 -f research/training/Modelfile
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    import torch
    import yaml
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    run_dir = ROOT / "research" / "training" / "outputs" / cfg["run_name"]
    adapter = run_dir / "adapter"
    if not adapter.exists():
        raise SystemExit(f"!! Không thấy adapter: {adapter}")
    # Gộp trên trọng số fp16 (không phải 4-bit) để model xuất ra không mang sai số lượng tử hoá kép.
    remote = bool(cfg.get("trust_remote_code", False))
    base = AutoModelForCausalLM.from_pretrained(cfg["base_model"], dtype=torch.float16,
                                                device_map="cpu", low_cpu_mem_usage=True,
                                                trust_remote_code=remote)
    merged = PeftModel.from_pretrained(base, str(adapter)).merge_and_unload()
    out = run_dir / "merged"
    merged.save_pretrained(out, safe_serialization=True)
    AutoTokenizer.from_pretrained(str(adapter), trust_remote_code=remote).save_pretrained(out)
    print(f"[OK] merged -> {out}")


if __name__ == "__main__":
    main()
