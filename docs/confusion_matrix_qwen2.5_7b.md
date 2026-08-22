# Confusion matrix — qwen2.5:7b

- Dataset: `eval/manifest.json` (33 frozen `sanitized-live` cases).
- Reference labels: `eval/expected/*.json` (`review_status=draft-single-reviewer`).
- Rows are reference ground truth (draft, single reviewer); cells show count and row percentage. Columns: predicted severity.
- `invalid` includes missing/malformed JSON or a severity outside `low|medium|high`.
- The project contains `qwen2.5:7b`; no `qwen2.7:7b` result exists, so this is the project baseline requested.

**Hình 4.1. Ma trận nhầm lẫn mức nghiêm trọng — cấu hình A (có RAG) và B (không RAG)**


## Cấu hình A — có RAG

Accuracy: **22/33 (66.7%)**; macro-F1: **0.660**.

| Nhãn chuẩn \ Dự đoán | thấp | trung bình | cao | không hợp lệ | Tổng |
|---|---:|---:|---:|---:|---:|
| **thấp** | 10 | 2 | 0 | 1 | 13 |
| **trung bình** | 4 | 9 | 0 | 0 | 13 |
| **cao** | 1 | 3 | 3 | 0 | 7 |
| **Tổng dự đoán** | 15 | 14 | 3 | 1 | 33 |

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| low | 66.7% | 76.9% | 0.714 | 13 |
| medium | 64.3% | 69.2% | 0.667 | 13 |
| high | 100.0% | 42.9% | 0.600 | 7 |

### Misclassification details

| Case | Nhãn chuẩn | Dự đoán |
|---|---|---|
| `ssh-5710-02` | trung bình | thấp |
| `ssh-5712-01` | cao | trung bình |
| `fim-554-01` | trung bình | thấp |
| `fim-554-02` | trung bình | thấp |
| `fim-553-01` | cao | thấp |
| `benign-5501-02` | thấp | trung bình |
| `benign-23502-01` | thấp | không hợp lệ |
| `benign-23502-05` | thấp | trung bình |
| `ambiguous-510-01` | cao | trung bình |
| `web-31101-01` | trung bình | thấp |
| `web-31151-01` | cao | trung bình |

## Cấu hình B — không RAG

Accuracy: **19/33 (57.6%)**; macro-F1: **0.502**.

| Nhãn chuẩn \ Dự đoán | thấp | trung bình | cao | không hợp lệ | Tổng |
|---|---:|---:|---:|---:|---:|
| **thấp** | 9 | 4 | 0 | 0 | 13 |
| **trung bình** | 4 | 9 | 0 | 0 | 13 |
| **cao** | 0 | 6 | 1 | 0 | 7 |
| **Tổng dự đoán** | 13 | 19 | 1 | 0 | 33 |

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| low | 69.2% | 69.2% | 0.692 | 13 |
| medium | 47.4% | 69.2% | 0.562 | 13 |
| high | 100.0% | 14.3% | 0.250 | 7 |

### Misclassification details

| Case | Nhãn chuẩn | Dự đoán |
|---|---|---|
| `ssh-5760-03` | trung bình | thấp |
| `ssh-2502-01` | cao | trung bình |
| `ssh-5712-01` | cao | trung bình |
| `ssh-40112-01` | cao | trung bình |
| `ssh-40112-02` | cao | trung bình |
| `fim-554-01` | trung bình | thấp |
| `fim-554-02` | trung bình | thấp |
| `fim-553-01` | cao | trung bình |
| `benign-5501-01` | thấp | trung bình |
| `benign-5501-02` | thấp | trung bình |
| `benign-5402-01` | thấp | trung bình |
| `benign-23502-04` | thấp | trung bình |
| `ambiguous-506-01` | trung bình | thấp |
| `web-31151-01` | cao | trung bình |

## Interpretation

- RAG correctly classifies 22/33 cases; the one `invalid` output is `benign-23502-01`.
- Without RAG, 19/33 cases are correct and all outputs are schema-valid.
- In the `high` row, RAG predicts 3/7 correctly and under-calls 4/7; no-RAG predicts 1/7 correctly and under-calls 6/7.

