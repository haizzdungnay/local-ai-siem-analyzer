# Baseline GĐ4 — `qwen2.5:7b` RAG/no-RAG

Ngày chạy: 2026-07-29
Corpus: 30 case `sanitized-live` đã qua vòng review kỹ thuật
Model: `qwen2.5:7b`
RAG: `nomic-embed-text` + corpus hiện tại
Kết quả thô: `eval/results.csv`, `eval/results-no-rag.csv`

Hai lượt chạy tuần tự để tránh tranh chấp tài nguyên Ollama.

## Kết quả tự động

| Chỉ số | RAG | Không RAG |
|---|---:|---:|
| Case hoàn tất | 30/30 | 30/30 |
| Schema hợp lệ | 30/30 (100%) | 30/30 (100%) |
| Lỗi gọi model | 0 | 0 |
| Latency trung bình | 2.702 s | 2.399 s |
| Latency median | 2.563 s | 2.435 s |
| Latency p95 | 3.440 s | 2.925 s |
| Latency lớn nhất | 3.697 s | 3.042 s |
| Severity exact-match với ground truth nháp | 18/30 (60.0%) | 21/30 (70.0%) |

Phân bố severity lượt RAG: `low=16`, `medium=10`, `high=4`, `critical=0`. Lượt không RAG: `low=14`, `medium=14`, `high=2`, `critical=0`.

## Lệch severity

RAG lệch 12 case:

- Hạ mức: `ssh-5503-01`, `ssh-5503-03`, `ssh-2502-01`, `ssh-5712-01`, hai FIM `554`, FIM `553`, `ambiguous-510-01`.
- Nâng mức: `ssh-5760-02`, `benign-23502-01`, `benign-23502-06`, `ambiguous-506-01`.

Không RAG lệch 9 case:

- Hạ mức: `ssh-5760-01`, `ssh-2502-01`, `ssh-5712-01`, hai case `ssh-40112`, hai FIM `554`.
- Nâng mức: `benign-5501-02`, `benign-5402-01`.

## Diễn giải giới hạn

Exact-match chỉ là smoke metric, không phải điểm chất lượng tổng. Một lượt stochastic trên 30 case không đủ kết luận RAG làm giảm chất lượng; RAG corpus hiện chưa có nhiều rule mới như `23502`, và human scoring semantic chưa hoàn tất.

Ground truth đã qua một vòng review độc lập kỹ thuật nhưng vẫn mang `review_status: draft-single-reviewer`. Reviewer người thứ hai còn phải chấm summary, root cause, severity, MITRE và next steps theo `rubric.md`.

## Còn thiếu

- Reviewer người thứ hai xác nhận/adjudicate expected labels.
- Chấm semantic toàn bộ output trong hai CSV.
- Đo baseline phân tích tay trên cùng 30 case.
- Model đối chứng chỉ thêm nếu giữ nguyên prompt, corpus và extractor config.
