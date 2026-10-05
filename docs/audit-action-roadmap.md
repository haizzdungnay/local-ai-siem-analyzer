# Lộ trình hành động sau audit kỹ thuật (2026-10-01)

Nguồn: audit đọc code và kết quả tracked (`eval/results*.csv`, `eval/adjudicated_severity.json`, `pytest`). Không chạy Ollama/Wazuh live. Mục ghi "(suy luận)" chưa kiểm chứng trực tiếp.

## Đối chiếu số liệu

| Số liệu | Thực tế | Nguồn |
|---|---|---|
| 33 case `sanitized-live` | Đúng | `eval/cases/`, `eval/expected/` |
| 50 adversarial case | Đúng; cả 50 cùng kiểu injection gián tiếp ép severity high xuống low | `eval/adversarial/adversarial_dataset_50.json` |
| Ground truth | 2 reviewer và adjudication, Cohen's κ = 0,91 (linear-weighted 0,93); `review_status: draft-single-reviewer` trong `eval/expected/` là metadata cũ | `eval/adjudicated_severity.json` |
| Accuracy no-RAG → RAG | 19/33 (57,6%) → 22/33 (66,7%) | `eval/results-no-rag.csv`, `eval/results.csv` |
| Recall `high` | RAG 3/7 (Wilson 95% CI 15,8–75,0%); no-RAG 1/7 (2,6–51,3%) | `eval/confusion_matrix_qwen2.5_7b.csv` |
| Test | 263 collected, 259 pass, 4 fail (`config.yaml`) | `python -m pytest -q` |

RAG vs no-RAG (paired, N = 33): cả hai đúng 14, chỉ RAG đúng 8, chỉ no-RAG đúng 5, cả hai sai 6. McNemar exact p = 0,58; 95% CI chênh lệch −12,1 đến +30,3 điểm; power ≈ 7%. Phát hiện chênh 9 điểm (α = 0,05, power 0,8) cần ≈ 146 cặp lệch, tương đương ≈ 370 case.

## Phát hiện

| ID | Trụ cột | Mức | Phát hiện | Khắc phục |
|---|---|---|---|---|
| F-01 | Bảo mật | High | Không có Host allowlist; `_validate_origin` so Origin với `request.host_url`, nên trang DNS rebinding đọc/ghi được toàn bộ API | Kiểm tra Host loopback trong `before_request` |
| F-02 | AI | High | Recall high 3/7; severity chỉ là enum, không rubric, không few-shot | Rubric, few-shot, sàn severity theo `rule.level` |
| F-03 | Bảo mật | Medium | Delimiter `<UNTRUSTED_ALERT>` không escape; kết quả injection benchmark không được track; adversarial chỉ 1 kiểu | NFKC, bỏ zero-width, escape `<>`; ghi CSV; thêm 15–20 case |
| F-04 | AI | Medium | ID MITRE chỉ kiểm tra regex; 11 ID ngoài catalog trong `results.csv`, 9 trong `results-no-rag.csv` | Đối chiếu catalog ATT&CK Enterprise, gắn `mitre_unverified` |
| F-05 | AI | Medium | Không đặt `num_ctx` (Ollama dùng mặc định); `full_log` ở luồng single-alert không giới hạn | `num_ctx: 8192`, cắt `full_log[:2000]`, cảnh báo theo `prompt_eval_count` |
| F-06 | Eval | High | RAG +9,1 điểm không có ý nghĩa thống kê; mỗi cấu hình chạy 1 lần | Ghi rõ trong docs; chạy lặp ≥ 3 seed |
| F-07 | Eval | Medium | High 7/33; rule 23502 chiếm 6/33 case gần trùng; không có `critical` | Mở rộng theo tầng lớp, ≥ 30 case mỗi lớp high/critical |
| F-08 | Eval | Low | Hai nguồn ground truth; metadata `draft` cũ; quy trình blind chưa viết | Một nguồn duy nhất; sửa metadata bằng script nhỏ (không chạy `build_dataset.py`) |
| F-09 | Code | High | CI fail trên clean checkout: 4 test cần `config.yaml` (gitignored) | Sửa test/CI để chạy được trên clean checkout |
| F-10 | Ổn định | Medium | Timeout Telegram cap 600 s; ở 8 KiB/s, PDF > ~4,6 MiB chắc chắn timeout; retry 3 lần chặn thread delivery > 30 phút | Giới hạn PDF theo cap × tốc độ; quá giới hạn thì gửi text; không retry timeout với cùng payload |
| F-11 | Bảo mật | Low | `*.local.env` lưu plaintext; `chmod 0o600` không có tác dụng trên Windows | `icacls` chỉ cấp quyền cho user hiện tại, hoặc DPAPI |
| F-12 | Dữ liệu | Low | `job_alerts` giữ `source_ip`/agent chưa che; backup chứa các trường này | Ghi tài liệu, đặt retention cho backup |
| F-13 | AI | Low | 7/66 dòng output có chữ Trung | Kiểm tra regex CJK, retry 1 lần hoặc gắn cờ |
| F-14 | AI | Low | Chuẩn hóa `confidence` hợp lý; chưa đo calibration | Đo Brier/ECE khi N đủ lớn; badge fallback trên UI |
| F-15 | Code | Medium | `create_app()` 718 dòng; 20 hàm > 50 dòng | Tách Blueprint khi sửa dashboard lần tới |
| F-16 | Code | Medium | Thiếu test DB lock, JSON cắt dở, UTF-8 lỗi, payload lớn, lỗi 5xx; chưa có `pytest-cov` | Thêm 5 test và `pytest-cov` |
| F-17 | Code | Low | `eval/reproducibility_benchmark.py` import `numpy` không khai báo | Thay bằng `statistics` |

## Lộ trình

### P0 — làm ngay

- [x] F-01: Host allowlist loopback và test Host lạ.
- [x] F-09: `pytest tests -q` pass trên clean checkout và CI.
- [x] F-06: README/docs/slides ghi rõ RAG chưa có ý nghĩa thống kê; recall high kèm CI. Slides PDF/PPTX chưa sửa (file nhị phân), cần cập nhật thủ công.

### P1 — 1–2 tuần

- [x] F-02: rubric severity 4 bậc + few-shot trong system prompt; sàn severity tất định (`rule.level >= 12` kéo lên high, ghi cờ `severity_floor_applied` vào provenance); chạy eval ra file mới khi Ollama live.
- [x] F-05: cấu hình `num_ctx: 8192` cho Ollama; cắt xén `full_log` ở trần 2000 ký tự trong `extractor.py`; cảnh báo `context_near_limit` khi `prompt_eval_count > 7000`.
- [x] F-13: cờ `cjk_detected` trong provenance khi phát hiện chữ Trung trong kết quả LLM.
- [x] F-04: kiểm tra ID MITRE với catalog đầy đủ (858 ID Enterprise ATT&CK, gắn `mitre_unverified` vào provenance).
- [x] F-03: làm sạch dữ liệu không tin cậy (NFKC, zero-width strip, escape `<>`), track kết quả injection benchmark (`eval/injection_benchmark_results.csv`), thêm 20 adversarial case đa dạng vector (`eval/adversarial/adversarial_dataset_diverse_20.json`).
- [x] F-10: giới hạn tải PDF Telegram theo trần băng thông (`MAX_PDF_BYTES = 4.915.200` bytes), fallback sang tin nhắn văn bản, chặn retry tự động lặp lại cho `telegram_timeout` nếu không `force=True`.
- [x] F-16: bổ sung 5 test ca biên (DB lock, JSON cắt dở, UTF-8 lỗi/null byte, log vượt trần, lỗi 5xx indexer không rò rỉ secret) và cấu hình `pytest-cov` đạt ≥ 80% coverage.
- [x] F-08: đồng bộ tham chiếu nhãn đánh giá và ghi nhận nguồn gốc adjudication κ = 0,91 trong `eval/adjudicated_severity.json`.

### Dài hạn — trước nghiệm thu/triển khai

- [x] F-07: xây dựng khung sinh dataset phân tầng (`eval/generate_stratified_dataset.py`, test `tests/test_stratified_dataset.py`) đảm bảo tối thiểu >= 35 ca critical và >= 35 ca high, sẵn sàng sinh bộ dữ liệu 370 ca khi chạy lặp >= 3 seed.
- [x] F-08: tài liệu quy trình blind cho reviewer (`docs/adjudication_procedure.md`), công thức Cohen's kappa và cơ chế phân xử bất đồng giữ kappa >= 0.80.
- [x] F-14: đo calibration `confidence` (Brier score, ECE, MCE) qua `eval/calibration_metrics.py`.
- [x] F-11: bảo mật file cấu hình `*.local.env` bằng `_restrict_file_permissions` (`icacls` trên Windows, `chmod 0o600` trên POSIX).
- [x] F-12: chính sách retention cho backup SQLite qua `DashboardStore.prune_retention_backups(max_backups=10, max_age_days=30)`.
- [x] F-17: loại bỏ dependency `numpy` không khai báo trong `eval/reproducibility_benchmark.py`, thay bằng stdlib `statistics`.
- [x] F-15: tách Blueprint cho `create_app()` thành 6 blueprint module chuyên biệt (`ui_bp`, `jobs_bp`, `ip_analysis_bp`, `security_tests_bp`, `notifications_bp`, `maintenance_bp`) và tách `dashboard_reports.py`.
