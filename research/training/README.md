# QLoRA SFT — nhánh so sánh B3/B4

Trạng thái: **pipeline đã viết, chưa có dữ liệu train đã review, chưa train**. Mọi số liệu thời gian/VRAM dưới đây là ước lượng cho tới khi có `run_manifest.json` thật.

## Ràng buộc (không vi phạm)
1. Tập test khóa ở `eval/test_set_lock.json` (2026-11-05). Chạy `python eval/verify_test_lock.py` trước mọi thí nghiệm. `build_sft_jsonl.py` từ chối nguồn có hash thuộc tập khóa.
2. Dữ liệu train lấy từ kịch bản **mới** (Splunk Attack Data replay qua Wazuh, kịch bản lab mới) — không từ `eval/raw_exports/`, `eval/cases/`, `eval/stratified_370/`.
3. Chỉ mẫu `review_status: reviewed` có `reviewed_by` vào SFT. Target do model lớn sinh nháp ghi `target_origin: distilled` và phải khai báo trong báo cáo.
4. Chia train/val theo `split_group_id` (kịch bản), không theo dòng.
5. So B3 với B1 trên **cùng** base (`qwen2.5:7b` ↔ `Qwen/Qwen2.5-7B-Instruct`), cùng prompt `soc-contract-v2`, cùng tập test; báo cáo cả prediction thô và sau `apply_severity_floor()`.

## Môi trường (Windows native, RTX 5070 Ti 16 GB)
```powershell
python -m venv .venv-train
.\.venv-train\Scripts\Activate.ps1
pip install torch --index-url https://download.pytorch.org/whl/cu128
pip install -r research/training/requirements-train.txt
pip freeze > research/training/requirements-train.lock.txt
python -c "import torch;print(torch.cuda.get_device_name(0), torch.version.cuda)"
```

## Luồng
```
candidates.reviewed.jsonl ──build_sft_jsonl.py──► outputs/sft-v1/{train,val}.jsonl + manifest.json
        └─ cùng system prompt + WINDOW_DATA + nhắc ngôn ngữ như llm.analyze_window()
train_qlora.py --smoke      # 8 mẫu giả, 5 step, model 3B: kiểm tra CUDA/bitsandbytes/VRAM
train_qlora.py (3B → 7B)    # outputs/<run>/adapter + run_manifest.json (loss, VRAM đỉnh, thời gian, hash dữ liệu)
export_adapter.py           # merge fp16 → outputs/<run>/merged
llama.cpp convert + quantize Q4_K_M → ollama create   # rồi chạy eval với model mới
```

## Ước lượng (chưa đo)
| Mẫu (~2.5k token, 3 epoch) | HF PEFT 7B |
|---|---|
| 300 | ~25–50 phút |
| 1.000 | ~1,5–2,5 giờ |
| 3.000 | ~4–8 giờ |
VRAM 7B 4-bit + gradient checkpointing, seq 2048: ước ~9–12 GB. Merge + GGUF: ~20–40 phút, cần ~40 GB đĩa trống.

## Ollama
`Modelfile` (tạo khi có GGUF):
```
FROM ./qwen2.5-7b-soc-qlora-v1.Q4_K_M.gguf
```
Giữ template chat của Qwen2.5: nếu `ollama show qwen2.5:7b --modelfile` có `TEMPLATE`, chép nguyên khối đó vào Modelfile.

## Thí nghiệm mở rộng: Qwen3.5-9B-Pentest-V5 (`configs/qwen35-9b-pentest-qlora.yaml`)
Vai trò: **external comparator**, không thuộc ablation chính. So trong nội bộ cặp (pentest-9B gốc ↔ pentest-9B + QLoRA nhóm) trên cùng tập test khóa.

Điều kiện trước khi train (chưa xác minh):
1. Repo Hugging Face có `*.safetensors` + `config.json`. Bản Ollama `hf.co/HRB25/qwen35-9b-pentest-v5` là GGUF Q4_K_M — QLoRA không train được trên GGUF.
2. Ghi license, base model và mô tả dữ liệu fine-tune của tác giả. Model đã được bên thứ ba fine-tune trên dữ liệu không rõ nguồn → không loại trừ được nhiễm tập test; nêu trong phần giới hạn.
3. Kiến trúc qwen35 (lai SSM) được `transformers`/PEFT/bitsandbytes hỗ trợ trên Windows:
   ```powershell
   python research/training/train_qlora.py --config research/training/configs/qwen35-9b-pentest-qlora.yaml --list-modules
   python research/training/train_qlora.py --config research/training/configs/qwen35-9b-pentest-qlora.yaml --smoke
   ```
`chat_template_kwargs.enable_thinking: false` giữ định dạng giống production (Ollama `think=False`, output JSON trực tiếp). Ước lượng VRAM 4-bit seq 2048: ~10–13 GB; thời gian ~1,3× bản 7B.
