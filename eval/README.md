# GĐ4 — Bộ đánh giá phân tích alert

Corpus hiện có 33 case `sanitized-live` lấy từ Wazuh lab ngày 2026-07-28–29. Mỗi case có input đóng băng trong `cases/` và ground truth nháp trong `expected/`; `manifest.json` nối hai phần bằng `case_id`.

## Thành phần

- `cases/*.json`: alert đã bỏ timestamp/ID sự kiện, IP/hostname/user/fingerprint thật.
- `expected/*.json`: disposition, severity, MITRE, facts bắt buộc, claims cấm và bước xử lý tham chiếu.
- `rubric.md`: cách hai reviewer chấm độc lập.
- `results.csv`: output baseline, latency, schema validity và cột điểm reviewer.
- `export_confusion_matrix.py`: dựng ma trận nhầm lẫn severity trực tiếp từ manifest, nhãn tham chiếu nháp trong `expected/` và hai CSV baseline; không gọi Ollama.
- `run_eval.py`: runner dùng đúng extractor, RAG và `analyze_alert()` của pipeline.
- `build_dataset.py`: script maintainer tái tạo snapshot từ Indexer; cần `ai_module/config.yaml`, có xóa rồi ghi lại `cases/` và `expected/`.
- `summarize_results.py`: tổng hợp latency, schema/error rate, severity exact-match, human scores đã điền và AI judgments riêng.
- `judge_results.py`: AI-only rubric judge; không thay human review.
- Hướng dẫn kiểm thử và human timing đầy đủ: [`../docs/manual-test.md`](../docs/manual-test.md).

Ground truth đã qua một vòng review độc lập nhưng vẫn giữ `review_status: draft-single-reviewer` vì chưa có reviewer người thứ hai. Vòng review đã giảm duplicate, hạ `40112` thành ambiguous/high và bỏ forced MITRE trên benign/weak-evidence case. Live capture mới bổ sung `31101`, `31151` và `31105`; không có synthetic case.

## Chạy baseline

Model baseline đã có trong lab:

```powershell
python eval/run_eval.py --model qwen2.5:7b --language vi
```

The SOC contract is versioned (`soc-contract-v1`). A new run writes a separate
CSV named `results-<prompt-version>-<language>.csv`; the historical
`eval/results.csv` is never overwritten. Use `--results <path>` for an
explicit output, and add `--overwrite` only when replacing a deliberately
chosen non-baseline file. Use `--language en` for an English run. The CSV keeps
the legacy five-field alert schema while adding prompt/language/provenance
columns for audit and reproducibility.

A/B RAG:

```powershell
python eval/run_eval.py --model qwen2.5:7b --language vi --results eval/results-soc-contract-v1-vi-rag.csv
python eval/run_eval.py --model qwen2.5:7b --language vi --no-rag --results eval/results-soc-contract-v1-vi-no-rag.csv
```

Smoke-test một case:

```powershell
python eval/run_eval.py --model qwen2.5:7b --language vi --limit 1 --results eval/results-soc-contract-v1-vi-smoke.csv
```

Runner ghi mới file CSV. Chạy cùng corpus, config extractor, prompt, RAG corpus và model tag; không sửa prompt giữa hai lượt so sánh.

Kết quả baseline đã ghi ở [`baseline.md`](baseline.md). Đây là kết quả model tự động trước human review, không phải điểm chất lượng cuối.

Tổng hợp kết quả hiện có:

```powershell
python eval/summarize_results.py eval/results.csv eval/results-no-rag.csv
```

Xuất ma trận nhầm lẫn cho baseline `qwen2.5:7b` (cả RAG và no-RAG):

```powershell
python eval/export_confusion_matrix.py
```

Lệnh trên kiểm tra coverage 33 case, xác nhận mọi nhãn trong `expected/*.json`
đều có `review_status: draft-single-reviewer`, rồi ghi report Markdown/CSV/PNG
vào `docs/` và `eval/`.
Prediction thiếu, JSON lỗi hoặc severity ngoài hợp đồng được giữ ở cột
`invalid`, không bị loại khỏi mẫu.

Human reviewer điền năm cột `*_score`, `reviewer`, `notes` trong bản copy của CSV. Không tự sinh điểm semantic từ model output hoặc expected data.

## Baseline phân tích tay

1. Reviewer chỉ mở `cases/*.json`; không xem `expected/` hoặc output AI.
2. Viết đủ 5 field `summary`, `root_cause`, `severity`, `mitre`, `next_steps` và đo thời gian từ lúc mở case đến lúc hoàn tất.
3. Reviewer khác chấm output tay và output AI theo `rubric.md`; ẩn tên nguồn output khi có thể.
4. Ghi thời gian tay vào file riêng hoặc cột notes; không ghi đè output model trong `results.csv`.
5. Báo median/p95 latency, schema-valid rate và điểm trung bình từng tiêu chí; không chỉ báo một điểm tổng.
6. Dùng `summarize_results.py` sau khi chấm; `scored_cases` phải bằng số case trước khi kết luận semantic.

`root_cause` phải phân biệt sự kiện quan sát được với suy đoán. Rule MITRE từ Wazuh có thể map rộng ngay cả trên hoạt động benign; reviewer chấm model dựa alert + ground truth, không buộc model kết luận attack chỉ vì rule có MITRE.
