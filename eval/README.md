# GĐ4 — Bộ đánh giá phân tích alert

Corpus hiện có 30 case `sanitized-live` lấy từ Wazuh lab ngày 2026-07-28–29. Mỗi case có input đóng băng trong `cases/` và ground truth nháp trong `expected/`; `manifest.json` nối hai phần bằng `case_id`.

## Thành phần

- `cases/*.json`: alert đã bỏ timestamp/ID sự kiện, IP/hostname/user/fingerprint thật.
- `expected/*.json`: disposition, severity, MITRE, facts bắt buộc, claims cấm và bước xử lý tham chiếu.
- `rubric.md`: cách hai reviewer chấm độc lập.
- `results.csv`: output baseline, latency, schema validity và cột điểm reviewer.
- `run_eval.py`: runner dùng đúng extractor, RAG và `analyze_alert()` của pipeline.
- `build_dataset.py`: script maintainer tái tạo snapshot từ Indexer; cần `ai_module/config.yaml`, có xóa rồi ghi lại `cases/` và `expected/`.

Ground truth đã qua một vòng review độc lập nhưng vẫn giữ `review_status: draft-single-reviewer` vì chưa có reviewer người thứ hai. Vòng review đã giảm duplicate, hạ `40112` thành ambiguous/high, bỏ forced MITRE trên benign/weak-evidence case và thêm benign rule `23502`. Snapshot Indexer hiện không có alert web `31101/31151`, nên corpus chưa chứa web case; không tạo synthetic case chỉ để đủ quota.

## Chạy baseline

Model baseline đã có trong lab:

```powershell
python eval/run_eval.py --model qwen2.5:7b
```

A/B RAG:

```powershell
python eval/run_eval.py --model qwen2.5:7b --results eval/results-rag.csv
python eval/run_eval.py --model qwen2.5:7b --no-rag --results eval/results-no-rag.csv
```

Smoke-test một case:

```powershell
python eval/run_eval.py --model qwen2.5:7b --limit 1 --results eval/results-smoke.csv
```

Runner ghi mới file CSV. Chạy cùng corpus, config extractor, prompt, RAG corpus và model tag; không sửa prompt giữa hai lượt so sánh.

Kết quả smoke baseline đã ghi ở [`baseline.md`](baseline.md). Đây là kết quả model tự động trước human review, không phải điểm chất lượng cuối.

## Baseline phân tích tay

1. Reviewer chỉ mở `cases/*.json`; không xem `expected/` hoặc output AI.
2. Viết đủ 5 field `summary`, `root_cause`, `severity`, `mitre`, `next_steps` và đo thời gian từ lúc mở case đến lúc hoàn tất.
3. Reviewer khác chấm output tay và output AI theo `rubric.md`; ẩn tên nguồn output khi có thể.
4. Ghi thời gian tay vào file riêng hoặc cột notes; không ghi đè output model trong `results.csv`.
5. Báo median/p95 latency, schema-valid rate và điểm trung bình từng tiêu chí; không chỉ báo một điểm tổng.

`root_cause` phải phân biệt sự kiện quan sát được với suy đoán. Rule MITRE từ Wazuh có thể map rộng ngay cả trên hoạt động benign; reviewer chấm model dựa alert + ground truth, không buộc model kết luận attack chỉ vì rule có MITRE.
