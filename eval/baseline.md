# Baseline GĐ4 — `qwen2.5:7b` RAG/no-RAG

Ngày chạy mới nhất: 2026-07-29
Corpus: 33 case `sanitized-live` đã qua một vòng review kỹ thuật
Model: `qwen2.5:7b`
RAG: `nomic-embed-text` + corpus hiện tại
Kết quả thô: `eval/results.csv`, `eval/results-no-rag.csv`

Hai lượt chạy tuần tự để tránh tranh chấp tài nguyên Ollama.

## Kết quả tự động

| Chỉ số | RAG | Không RAG |
|---|---:|---:|
| Case hoàn tất | 33/33 | 33/33 |
| Schema hợp lệ | 32/33 (97.0%) | 33/33 (100%) |
| Lỗi gọi model | 0 | 0 |
| Latency trung bình | 2.716 s | 2.428 s |
| Latency median | 2.704 s | 2.410 s |
| Latency p95 | 3.897 s | 3.304 s |
| Latency lớn nhất | 5.020 s | 3.934 s |
| Severity exact-match với ground truth nháp | 22/33 (66.7%) | 19/33 (57.6%) |

Một output RAG (`benign-23502-01`) dùng fallback `severity=unknown`, nên `schema_valid=false` theo protocol dù JSON vẫn đọc được. Không RAG có 33/33 schema-valid.

## Web cases mới

Live capture bổ sung ba case, không synthetic:

- `web-31101-01`: request path `/etc/passwd`, HTTP 404; không được khẳng định đọc file thành công.
- `web-31151-01`: nhiều HTTP 404 cùng nguồn, correlation vulnerability scanning `T1595.002`.
- `web-31105-01`: payload XSS nhận HTTP 404; không được khẳng định JavaScript đã thực thi.

## Diễn giải giới hạn

Exact-match severity chỉ là smoke metric, không phải điểm chất lượng tổng. Một lượt stochastic trên 33 case không đủ kết luận RAG tốt hơn hoặc kém hơn. Human scoring semantic chưa hoàn tất; `review_status` vẫn là `draft-single-reviewer`.

Output live gần nhất cũng cho thấy model có thể cưỡng ép MITRE trên benign PAM/sudo. Đây là finding cần chấm theo rubric, không sửa prompt giữa hai lượt baseline hiện tại.

## AI-only rubric scoring

Judge local độc lập với candidate: `CyberCrew/notmythos-8b`, prompt `ai-judge-v1`, temperature `0`, seed `20260729`.

| AI judge metric | RAG | Không RAG |
|---|---:|---:|
| Coverage/schema valid | 33/33 | 33/33 |
| Overall mean | 3.44/5 | 3.42/5 |
| Overall median | 3.60/5 | 3.60/5 |
| Summary mean | 3.94 | 3.94 |
| Root cause mean | 3.00 | 3.06 |
| Severity mean | 2.21 | 2.09 |
| MITRE mean | 4.21 | 4.36 |
| Next steps mean | 3.85 | 3.64 |

Paired comparison: RAG thắng 8 case, hòa 18, no-RAG thắng 7. Chênh lệch rất nhỏ; không đủ kết luận RAG tốt hơn. Đây là **AI-only rubric scoring**, không phải human review hoặc ground truth final. Raw judgments: `eval/ai-judgments-notmythos-8b.csv`.

## Còn thiếu

- Reviewer người thứ hai xác nhận/adjudicate 33 expected labels.
- Chấm semantic toàn bộ 66 output trong hai CSV.
- Đo baseline phân tích tay trên cùng 33 case.
- Model đối chứng chỉ thêm nếu giữ nguyên prompt, corpus và extractor config.

Tổng hợp lại sau khi điền điểm:

```powershell
python eval/summarize_results.py eval/results.csv eval/results-no-rag.csv
```
