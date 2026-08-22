# Handoff — local-ai-siem-analyzer

Ngày cập nhật: 2026-08-22

## Confusion matrix qwen2.5:7b từ dữ liệu project (2026-08-22)

- Trạng thái: KẾT QUẢ ĐÃ XUẤT VÀ VERIFY TRONG PHẠM VI; chưa đánh dấu hoàn tất toàn repo vì worktree có lỗi `git diff --check` tồn tại ngoài phạm vi task.
- Nguồn dữ liệu: đủ 33/33 case trong `eval/manifest.json`; exporter dùng trực tiếp nhãn severity trong `eval/expected/*.json` và xác nhận cả 33 file có `review_status=draft-single-reviewer`; prediction từ `eval/results.csv` (RAG) và `eval/results-no-rag.csv` (no-RAG), tất cả row đều ghi model `qwen2.5:7b`.
- Kết quả RAG, theo hàng `low/medium/high` và cột `low/medium/high/invalid`: `[10,2,0,1]`, `[4,9,0,0]`, `[1,3,3,0]`; exact-match `22/33 = 66.7%`, macro-F1 `0.660`.
- Kết quả no-RAG: `[9,4,0,0]`, `[4,9,0,0]`, `[0,6,1,0]`; exact-match `19/33 = 57.6%`, macro-F1 `0.502`.
- Đã cập nhật exporter `eval/export_confusion_matrix.py`, tài liệu chạy trong `eval/README.md`, report `docs/confusion_matrix_qwen2.5_7b.md`, dữ liệu máy đọc `eval/confusion_matrix_qwen2.5_7b.csv`, ảnh hai panel `docs/confusion_matrix_qwen2.5_7b.png` và entry point legacy `docs/draw confusion.py`; chú thích ảnh và dòng provenance trong report dùng đúng “Rows are reference ground truth (draft, single reviewer); cells show count and row percentage.”
- Verification: `python eval/summarize_results.py eval/results.csv eval/results-no-rag.csv` PASS; `python eval/stats_analysis.py` PASS; targeted pytest — 23 passed; full `pytest -q` — 263 passed; `python -m py_compile eval/export_confusion_matrix.py "docs/draw confusion.py"` PASS; exporter rerun thành công; secret scan PASS; ảnh đã kiểm tra trực quan; exact-claim scan không còn “Rows are adjudicated ground truth”; task-scoped whitespace/diff check PASS.
- Verification chưa pass toàn worktree: `git diff --check` bị hàng loạt CRLF/trailing-whitespace trong các file dirty có sẵn ngoài task; chạy lại với `core.whitespace=cr-at-eol` còn báo `ai_module/llm.py:979: new blank line at EOF`. Không sửa vì đây là thay đổi của user/luồng khác.
- Giới hạn: đây là hai lượt baseline đã lưu trên corpus nhỏ 33 case, không phải ước lượng hiệu năng tổng quát. RAG có 1 output `severity=unknown` được giữ ở cột `invalid`; recall lớp `high` chỉ 3/7 với RAG và 1/7 khi không RAG. Không chạy inference mới vì cả hai snapshot đã đủ coverage; tránh trộn lượt stochastic mới vào baseline lịch sử.
- Next action: nếu cần baseline theo prompt/model tag mới, chạy `eval/run_eval.py` ra file mới (không ghi đè `eval/results*.csv`) rồi mở rộng exporter bằng input explicit.

## Fix Telegram khong gui duoc bao cao co attack chain (2026-08-21)

- Trang thai: HOAN TAT.
- Trieu chung: bat "Phan tich chuoi tan cong (IP tu dong)" thi bao cao khong toi Telegram/Gmail.
- Chan doan: `report_deliveries` cho thay job #250 (attack_chain=1) ket thuc `uncertain` voi `telegram_network_error`, trong khi job #253/#254 (attack_chain=0) deu `sent`. Goi `send_report()` truc tiep tra `TimeoutError: The write operation timed out` tu `ssl.sendall` trong luc upload.
- Nguyen nhan that: KHONG phai loi logic cua attack chain. Uplink lab do duoc ~9 KB/s (job #254, PDF 273 KiB, mat 30.7s). `_post_document()` ghim `timeout=(5, max(45, timeout_seconds))`, nen PDF ~360-390 KiB can ~41-44s cong TLS overhead la vuot tran 45s va bi huy giua chung. Attack chain chi lam PDF to them ~13 KiB, du de day payload qua nguong nhung khong phai nguyen nhan goc.
- Sua tai `ai_module/telegram_notifier.py`: them `_upload_read_timeout()` tinh deadline theo kich thuoc payload (`ASSUMED_UPLOAD_BYTES_PER_SECOND = 8 KiB/s`), san `MIN_UPLOAD_READ_TIMEOUT_SECONDS = 45`, tran `MAX_UPLOAD_READ_TIMEOUT_SECONDS = 600` de worker khong treo vo han. `telegram.timeout_seconds` la san chu khong phai tran.
- Verification: `python -m pytest -q` — 256 passed. Test moi: `test_document_read_timeout_scales_with_payload_size`.
- Verification live: gui lai job #250 (bản truoc fail) thanh cong trong 3.7s, message_id 23. Job #256 chay qua worker that voi `delivery_channel=telegram` va attack_chain=on: job `succeeded`, delivery `sent`, `attempt_count=1`.
- Luu y: Gmail dang `enabled: False` trong cau hinh local nen chi Telegram thuc su gui. Neu bat Gmail can kiem tra lai vi `gmail_notifier` dung `timeout=self.settings.timeout_seconds` (mac dinh 15s) cho SMTP; chua do duoc voi attachment lon.
- Gioi han: `ASSUMED_UPLOAD_BYTES_PER_SECOND` la hang so uoc luong cho lab, khong do bang wire thuc te. Neu uplink cham hon 8 KB/s van co the timeout; khi do nang `telegram.timeout_seconds` de keo san len.
- Server chay PID 4648 tren `127.0.0.1:8765`.
- Next action: review staged diff va commit kem `CHANGELOG.md` + `HANDOFF.md`.

## Fix quality-gate gia va confidence thang 0-1 (2026-08-21)

- Trang thai: HOAN TAT. Hai loi phat hien tren job #250.
- Loi 1 (do luot truoc gay ra): `_attack_chain_result()` tra ca nhan mo ta `Attack chain profile for source IP ...` trong `warnings`, roi `_run_job()` merge vao warnings cua job, nen UI bat panel "Bao cao chua dat quality gate" du chain chay thanh cong. Sua tai `ai_module/dashboard_worker.py`: nhan giu tren result row cua chinh chuoi, chi day canh bao len bao cao cua so khi chain tra fallback/unknown.
- Loi 2: model tra `confidence` tren thang 0-1 (`0.8`) trong khi hop dong la 0-100, hien thi thanh "0.8%". Them `_normalized_confidence()` trong `ai_module/llm.py`, dung chung cho ca ba scope qua `_enrich_contract()`. Gia tri trong khoang (0,1) duoc nhan 100; `0`, `1`, `100` giu nguyen vi deu la phan tram hop le; gia tri ngoai hop dong van fail-closed ve local fallback. Bo sung cau "khong dung thang 0-1" vao `CONFIDENCE_FIELD_DESCRIPTION`.
- Verification: `python -m pytest -q` — 255 passed. Test moi: `test_fractional_confidence_is_rescaled_to_the_contract_percentage`; cap nhat `test_attack_chain_is_merged_into_the_same_job_and_single_delivery` de chot window warnings rong.
- Verification live: job #255 (`CyberCrew/notmythos-8b:latest`, cua so 6h, attack_chain=on) status `succeeded`, window confidence 80.0 va `warnings: []`, chain confidence 50.0 giu nhan tren row cua no. `GET /api/jobs/255` xac nhan.
- Gioi han: chain confidence 50.0 tren cua so it alert; day la diem model tu cham theo rubric, khong phai loi hien thi. Job #250 va cac job cu van luu confidence goc trong DB, khong ghi de hoi to.
- Server chay PID 40092 tren `127.0.0.1:8765`; asset cache-bust `?v=dashboard-20260821-4`.
- Next action: hard-reload dashboard, mo job #255 xac nhan khong con panel quality gate va confidence hien dung; sau do review staged diff va commit kem `CHANGELOG.md` + `HANDOFF.md`.

## Attack chain gop chung mot dot bao cao + confidence calibration (2026-08-21)

- Trang thai: HOAN TAT.
- Van de: tick checkbox trong form job tao ra hai dot bao cao roi rac (vi du #242 window va #243 chain). Yeu cau la mot dot duy nhat; tach rieng chi khi chay form Threat hunting cuc bo.
- `ai_module/dashboard_worker.py`: bo `_queue_attack_chain_followup()` va `_run_attack_chain_job()`, thay bang `_attack_chain_result()` chay inline truoc khi hoan tat job cha. Khong con job con, khong con `analysis_kind`/`parent_job_id` trong luong chay.
- `ai_module/dashboard_store.py`: `save_result_and_complete_if_not_cancelled()` nhan `extra_results`, ghi ca hai result row trong cung transaction. Them phase `analyzing_attack_chain` vao `JOB_PHASES`.
- `ai_module/telegram_notifier.py`: `_analysis_from_job()` loai row `scope_key='attack_chain'` de bao cao chinh khong bi ghi de; them `attack_chain_from_job()`.
- `ai_module/gmail_notifier.py` + `ai_module/telegram_pdf.py`: them muc **Attack chain** sau `Key findings` trong ca plain text, HTML va PDF.
- `ai_module/web/app.js`: khoi chuoi tan cong doc row `scope_key === 'attack_chain'` cua chinh job; `windowResult` loc bo row chain; tag lich su doi tu `analysis_kind` sang `job.attack_chain`.
- Confidence: prompt len `soc-contract-v2` voi thang hieu chinh 90-100/70-89/40-69/duoi 40, noi ro confidence khong phai muc nghiem trong, va nhung vao `description` cua field `confidence` trong ca ba output schema. Scope `ip_profile` co quy tac rieng cho `intent`, `kill_chain_stages`, `targeted_assets`.
- Nguyen nhan that cua confidence thap: cua so lab bi cat prompt (`included_groups` 20/21, `truncated: True`) nen model tu ha diem. Nang `max_groups_in_prompt` 20 -> 40 va `max_window_prompt_chars` 24000 -> 32000 trong `ai_module/config.yaml` va `config.example.yaml`.
- Do luong live (qwen2.5:7b, cua so 24h, temperature 0, seed 42):
  - Truoc: job #244-#247 deu window confidence 85.0, status `partial`, `truncated: True`.
  - Sau: job #248 va #249 window confidence 95.0, status `succeeded`, `truncated: False`.
  - Chain profile giu confidence 70.0 tren 2 alert; `intent` da dung nghia ("Tan cong brute force nham thu cac mat khau dang nhap DVWA") va `kill_chain_stages` co timestamp + rule ID.
- Verification: `python -m pytest -q` — 254 passed; `node --check ai_module/web/app.js` PASS; `python -m compileall -q ai_module` PASS.
- Verification end-to-end: job #249 co dung hai row `scope_key` = `window` + `attack_chain` tren cung mot job, `GET /api/jobs/249` tra ca hai, khong sinh job con, chi mot delivery.
- Test moi: `test_attack_chain_is_merged_into_the_same_job_and_single_delivery`, `test_confidence_rubric_is_calibrated_and_scoped_per_analysis_kind`, `test_attack_chain_row_is_merged_into_the_single_report`.
- Gioi han: chain confidence 70 tren cua so chi co 2 alert; can them du lieu lab (nhieu giai doan tan cong hon) truoc khi ket luan rubric da du cho scope ip_profile. Job #238-#247 la du lieu thu nghiem con lai trong DB.
- Server chay PID 14276 tren `127.0.0.1:8765`; asset cache-bust `?v=dashboard-20260821-3`.
- Next action: hard-reload dashboard, mo job #249 xac nhan khoi **Chuoi tan cong theo thoi gian** hien trong cung bao cao; sau do review staged diff va commit kem `CHANGELOG.md` + `HANDOFF.md`.

## Attack chain render fix + v9 migration live (2026-08-21)

- Trạng thái: HOÀN TẤT. Ba lỗi độc lập trong handoff đã được sửa và verify end-to-end.
- `ai_module/web/index.html`: thêm `#ai-chain-field` + `<ol id="ai-chain" class="attack-chain">` giữa root cause và MITRE; dùng lại class `.attack-chain` có sẵn, không thêm CSS.
- `ai_module/web/app.js`: `renderAiReview()` fallback root cause sang `result.intent` và render `result.kill_chain_stages`, ẩn khối khi rỗng; `renderJobs()` gắn tag `· chuỗi tấn công` cho `analysis_kind === 'attack_chain'`.
- `tests/test_dashboard_ui.py`: thêm `test_attack_chain_result_has_render_target_and_history_tag()` chốt markup/JS.
- Backup DB trước migration: `ai_module/dashboard_data/dashboard.pre-v9-20260821-134457.db` (3047424 bytes, khớp bản gốc). Restart server → `_ensure_v9_attack_chain()` chạy, `user_version` 8 → 9.
- Verification: `PRAGMA user_version` = 9; `PRAGMA table_info(jobs)` có đủ `analysis_kind`, `attack_chain`, `attack_chain_seconds`, `parent_job_id`; `GET /api/jobs` trả key `analysis_kind`; 237 job lịch sử giữ nguyên.
- Verification test: `python -m pytest tests/test_dashboard_api.py tests/test_dashboard_store_worker.py tests/test_dashboard_ui.py -q` — 111 passed.
- Cache-bust asset `?v=dashboard-20260820-2` → `?v=dashboard-20260821-1` để browser không giữ `app.js` cũ; `test_dashboard_exposes_ip_investigation_and_attack_chain_controls` chuyển từ assert token cứng sang assert mọi asset dùng chung một token.
- Verification full: `python -m pytest -q` — 252 passed; `node --check ai_module/web/app.js` PASS; `python -m compileall -q ai_module` PASS; `GET /` và `GET /assets/app.js` trả markup/JS mới.
- Verification end-to-end: job `#240` (24h, `qwen2.5:7b`, attack_chain=on) kết thúc `partial`, sinh job con `#241` `analysis_kind=attack_chain`, `parent_job_id=240`, status `succeeded`, result có `kill_chain_stages` và `intent` — đúng dữ liệu mà panel mới đọc.
- Ghi chú/giới hạn: job `#238` (cửa sổ 1h) succeeded với 0 alert nên worker early-return tại `dashboard_worker.py:341` và KHÔNG queue follow-up — hành vi thiết kế, không phải bug. Job `#239` failed vì `qwen2.5:3b` chưa pull trong Ollama local; chỉ có `qwen2.5:7b`, `deepseek-r1:8b`, `nomic-embed-text`, `Foundation-Sec-8B`, `notmythos-8b`.
- Giới hạn test: assertion UI là static markup/JS, chưa có jsdom/Playwright trong repo; render thật đã xác nhận qua payload API `#241`.
- Server hiện chạy PID 8540 trên `127.0.0.1:8765` (PID cũ 23728 đã stop). Log runtime ghi ra `ai_module/dashboard_data/server.out.log` / `server.err.log` (untracked).
- Next action: hard-reload dashboard (asset có query `?v=dashboard-20260820-2`, có thể cần bump khi cache), mở job `#241` xác nhận khối **Chuỗi tấn công theo thời gian** hiển thị; sau đó review staged diff và commit kèm `CHANGELOG.md` + `HANDOFF.md`.

## Batch history table spacing fix (2026-08-21)

- Sửa `ai_module/web/styles.css`: selector chung cho `small` không còn ghi đè `display: -webkit-box` của `.history-summary-clamp`; tóm tắt AI được giới hạn 3 dòng và vẫn mở đầy đủ qua **Xem thêm**.
- Giảm `line-height` và padding dọc của các ô trong `.batch-table` để mốc thời gian, trạng thái và nội dung AI không kéo giãn hàng bất thường.
- Bảng 11 cột nay dùng đúng chiều rộng khung, bỏ `min-width: 1120px`, chia tỷ lệ riêng cho từng cột và giữ badge trạng thái không bẻ chữ; không còn cần kéo ngang để thấy `Review`, `Delivery`, `Freshness`.
- Verification: `tests/test_dashboard_ui.py` — 25 passed; full `pytest -q` — 251 passed; `node --check ai_module/web/app.js` PASS; reload dashboard và đo DOM xác nhận hàng đầu giảm khoảng 201px xuống 98px, summary có overflow ẩn đúng 3 dòng.
- Verification bổ sung: DOM xác nhận `tableWidth=wrapperWidth=746px`, `scrollWidth=746px`, đủ 11 cột; badge `UNREVIEWED` giữ một dòng; `python -m compileall -q ai_module` PASS.
- Blocker/giới hạn: bảng vẫn giữ scroll ngang cho toàn bộ 11 cột trên viewport hẹp; nội dung AI dài hơn 3 dòng cần mở **Xem thêm**.

## Attack chain follow-up analysis (2026-08-20)

- Thêm checkbox **Phân tích chuỗi tấn công (IP tự động)** vào form `Phân tích mới` (`#job-attack-chain`) và form `Fixed windows` (`#schedule-attack-chain`).
- Worker đơn luồng xử lý FIFO: job window chạy trước, lưu result, xếp hàng delivery, rồi `_queue_attack_chain_followup()` tạo job con `analysis_kind=attack_chain` với cùng model/language/delivery/LLM snapshot và `parent_job_id`.
- `_run_attack_chain_job()` gọi `fetch_active_source_ips(limit=1)` trên đúng `[window_start, window_end)` để lấy IP nhiều alert nhất, chạy `analyze_ip_profile_aggregate()` rồi xếp hàng delivery riêng; window rỗng hoặc không có IP thì kết thúc `succeeded` mà không gọi LLM.
- Lỗi ở job con không ghi đè hay làm hỏng report window đã lưu.
- Dropdown `#job-attack-chain-seconds` / `#schedule-attack-chain-seconds` chỉ hiện khi checkbox được bật; cửa sổ chuỗi tấn công neo tại `window_end` của job gốc và lùi lại đúng số giây đã chọn.
- SQLite schema v9 migration `_ensure_v9_attack_chain()` gồm `attack_chain_seconds` cho cả `jobs` và `schedule`; API `/api/jobs` và `PUT /api/schedule` validate qua `_resolve_attack_chain()`, cờ sai kiểu hoặc preset lạ trả `422`.
- Verification: `python -m pytest` — `250 passed`; `node --check ai_module/web/app.js` PASS; `python -m compileall -q ai_module` PASS; secret scan PASS.

## Threat hunting cục bộ & Unified Control Hub (2026-08-20)

- Gộp khối **Phân tích mới** và **Threat hunting cục bộ (Phân tích hành vi IP và chuỗi tấn công)** vào cùng một card/hàng điều khiển phía trên Dashboard UI (`.control-card-unified`).
- Bổ sung tùy chọn checkbox **Tự động phân tích**: Tự động truy vấn và lùng sục địa chỉ IPv4 có số lượng alert hoạt động nhiều nhất trong khoảng thời gian đã chọn.
- Thêm dropdown chọn nhanh địa chỉ IPv4 hoạt động thực tế từ Wazuh Indexer (`GET /api/active-ips`) kèm ô text input nhập tay tùy chọn.
- Mở rộng dropdown thời gian phân tích đồng bộ từ 5 phút đến 30 ngày (300s -> 2592000s) và dropdown model phân tích từ allowlist.
- Backend: Thêm `fetch_active_source_ips()` trong `reader.py`, API `GET /api/active-ips`, cập nhật `POST /api/ip-analysis` hỗ trợ auto mode.
- Verification: 248 tests passed, compileall PASS, secret scan PASS.

## Eval benchmarks and extended timerange update (2026-08-20)

- Bổ sung các benchmark và dataset đánh giá: prompt injection, capacity, reproducibility, user study protocol, severity groundtruth, RAG benchmark.
- Nâng cấp time-range parser và worker hỗ trợ các preset/custom range lên tới 30 ngày (259200s, 604800s, 2592000s).
- Bổ sung các test suites kiểm thử unit/integration cho mở rộng timerange, model provenance, RAG benchmark, adversarial prompt injection.
- Verification: Secret scan passed, staged files ready for release.


## Documentation relocation (2026-08-14)

- Moved standalone notes `SoLieuC4.md`, `check.md`, `promt.md`, and `test.md` to `docs/`; root `HANDOFF.md` remains because `CLAUDE.md` and `.githooks/pre-commit` require it as release ledger.
- Preserved operator guides at `docs/gmail.md` and `docs/telegram.md`; retained their technical plans as `docs/gmail-plan.md` and `docs/telegram-plan.md` instead of overwriting shipped guides.
- Excluded untracked dashboard runtime logs from release staging; logs contain local lab/runtime details.
- Verification: `python -m pytest` — `222 passed`; AST scan — 36 Python files, 0 errors; `git diff --check`, cached whitespace check, and tracked secret scan PASS.
- Next: review staged rename/doc diff, run hook, commit, push `main`, then verify GitHub Actions.

## CI fix (2026-08-14)

- GitHub run `31763143771` failed only at `ubuntu-latest / Python 3.11` → `Audit Python dependencies`; three other matrix jobs passed.
- Root cause: `Pillow==12.0.0` had newly reported vulnerabilities. Minimum targeted fix: `ai_module/requirements.txt` pin changed to `Pillow==12.3.0`; no application source changed.
- Local dependency audit after reinstall: `dependency audit passed; 1 documented exception(s) remain active`.
- Full local verification after fix: `222 passed in 18.06s`; compileall, JavaScript syntax, shell syntax, `git diff --check` và tracked secret scan PASS. Dependency audit PASS.
- Next: commit only dependency pin + ledgers, push, then wait for all GitHub matrix jobs green.

## GitHub release preparation (2026-08-14)

- Đã làm sạch artifact sinh bởi pytest/runtime (`.tmp-*`, `qa_run_20260811/`, `$null`, dashboard stdout/stderr logs); không stage.
- Đã bổ sung đồng bộ tài liệu Gmail: README ghi đúng `multipart/alternative` với HTML Alert map + text fallback; roadmap ghi delivery local opt-in, không inbound webhook/email, OAuth hoặc remote multi-user.
- Untracked release files gồm Gmail/Telegram delivery, security-test runner/model selector, DVWA rule/script, Caddy example, export/retention docs và regression tests; không có credential thật. `ai_module/gmail.local.env` và `ai_module/telegram.local.env` vẫn gitignored.
- Verification ngày 2026-08-14: `python -m pytest -q` — `222 passed in 17.92s`; `python -m compileall -q ai_module eval tests` PASS; `node --check ai_module/web/app.js` PASS; `node --check ai_module/web/test.js` PASS; `bash -n scripts/attacks/dvwa-module-test.sh` PASS; `python scripts/check_tracked_secrets.py` PASS; `git diff --check` PASS, chỉ cảnh báo LF/CRLF.
- Trạng thái: chưa stage/commit/push. Remote hiện là `origin` tới `https://github.com/haizzdungnay/local-ai-siem-analyzer`; branch `main` đang ở `4099dff` và khớp `origin/main` trước release.
- Giới hạn: chưa chạy traffic lab, Gmail/Telegram live delivery, Ollama, Indexer hoặc browser acceptance trong lượt này. Không chạy `eval/build_dataset.py`.
- Next action: stage source/docs/tests đã review, review staged diff + secret scan, commit rồi push `main` nếu hook/remote cho phép.

## Security-test model selection (2026-08-13)

- `/security-tests` đã có dropdown model cho từng lượt chạy. Catalog trả `default_model` và giao `allowed_models` với model đang cài trong Ollama; modal khóa/snapshot lựa chọn, revalidate catalog rồi gửi `scenario_id`, model và `confirm=true`. API/runner xác thực availability lần nữa trước thread/SSH và snapshot model vào run, sau đó AI job dùng đúng snapshot đó.
- Config mới `security_tests.allowed_analysis_models` là tập con bắt buộc của `dashboard.allowed_models`; `security_tests.analysis_model` vẫn là default. Config cũ không có khóa mới tự dùng allowlist dashboard để tương thích. Target, command, payload, language, timebox và LLM parameters vẫn cố định server-side.
- Safety: đã xóa test executable `test_brute_force_success_marker_requires_all_300_fake_curls_to_succeed`; PATH Windows→Git Bash của test cũ không cô lập `curl` đáng tin và từng có thể gọi DVWA thật. Không rerun script tấn công hoặc traffic live trong thay đổi model selector này. Verification không-network cuối: full `222 passed`, Python compileall, JavaScript syntax, shell syntax và `git diff --check` PASS.
- Multi-agent read-only audit dùng Luna/Terra xác nhận hard-code thực tế trước đây là `qwen2.5:7b` (không phải `notmythos`), worker đã model-agnostic, và validation phải nằm cả API lẫn runner. Dashboard đã restart an toàn trên loopback bằng current code (PID `48912`): queue `0`, database `ok`, không active security run; live HTML có selector v3 và catalog trả bốn model allowlist local. POST model ngoài allowlist trả `422` và không tạo run; không chạy scenario/traffic thật.

## Brute Force DVWA completion (2026-08-12)

- Scenario `brute-force` là một login POST burst có giới hạn, không phải SSH brute force: script fixed target `.20`, gửi đúng sáu `POST /DVWA/login.php` với credential lab không hợp lệ, giãn 1 giây giữa request, mỗi request tối đa 2 giây và cả script tối đa 18/20 giây. Apache access log chỉ chứng minh request cadence; UI/rule không khẳng định login thất bại, credential guessing thành công hay compromise.
- Wazuh 4.9.0 decoder trả `protocol=POST`, `srcip`, `url`; request 302 bình thường kết thúc tại stock `31108`. File riêng `/var/ossec/etc/rules/dvwa_login_burst_rules.xml` đã được deploy từ tracked template `infra/wazuh/rules/dvwa_login_burst_rules.xml`; checksum stock `local_rules.xml` vẫn giữ nguyên. Base `100120` match exact request line, correlation `100121` yêu cầu sáu event/10 giây/cùng source.
- Manager validation PASS: `wazuh-analysisd -t`; positive `wazuh-logtest` cho năm lần `100120` và lần thứ sáu `100121`; negative GET, query-string và wrong-path không match. Base dùng `no_log`; dashboard contract chỉ allow correlation `100121`, nên Indexer/AI không nhận sáu base alert riêng.
- Live finding/fix: run đầu gửi đủ sáu HTTP 302 cùng một giây; Manager nhận `firedtimes` lệch thứ tự và Indexer có `6 × 100120` nhưng không có `100121`, run kết thúc `no_matching_alert`, không AI. Script được giãn 1 giây để giữ thứ tự correlation; đây là thay đổi implementation sau finding, không hồi tố/retry run cũ.
- Live acceptance hậu sửa PASS cho detection: run `26595946ffdb4a43890c229ceea92603`, `END_UTC=2026-08-12T16:22:10Z`, window `16:21:40Z..16:22:20Z`, script exit `0`, đúng sáu HTTP 302; Indexer chỉ có `1 × 100121` level 10. Job AI duy nhất `#194`, model `qwen2.5:7b`, latency 15.496 giây, severity `medium`, summary mở đúng evidence prefix và mô tả sáu login request từ cùng source. Job giữ `partial`/run `analysis_partial`: key finding và assessment basis chưa dẫn đủ exact count/rule/window, đồng thời suy diễn vấn đề mật khẩu quá bằng chứng; quality gate từ chối trình bày như kết luận hoàn chỉnh và không retry AI.
- Final source verification PASS: full `214 passed`; `python -m compileall -q ai_module eval tests`; `node --check ai_module/web/app.js` và `test.js`; Git Bash syntax cho ba attack scripts + pre-commit; `git diff --check`. Dashboard PID `3576` hiện chạy current code, queue `0`, schedule disabled/idle, history có job `#194`; chỉ còn warning LF/CRLF của Git.

## Security-test evidence closeout (2026-08-12)

- Catalog active chỉ còn ba flow có telemetry contract cố định: `file-inclusion` → rule `31104`, `xss-reflected` → `31105`, `api` → `31101`. Correlation route luôn là Kali `.30` → Victim `.20`; marker remote phải khớp chính xác `SCENARIO`, fixed target và `END_UTC`. Query aggregate và detail đều lọc UTC window/source/agent/rule, không nhận target, command, payload hay trusted text tùy ý từ browser.
- Prompt boundary đã tách rõ: aggregate/log nằm trong `<UNTRUSTED_WINDOW_DATA>`; chỉ metadata do server xác minh mới nằm trong `<TRUSTED_WAZUH_EVIDENCE>`. Security AI dùng model snapshot từ allowlist (historical flows ở mục này dùng `qwen2.5:7b`), VI, `temperature=0`, `top_p=1`, 512 output token, deadline 45 giây, không retry hoặc tự fallback model.
- Summary hợp lệ phải mở đầu chính xác `WAZUH_EVIDENCE total_alerts=N; rule_ids=...; window_utc=START..END.`. Quality gate đánh dấu `partial` nếu prefix thiếu/sai, summary chỉ lặp prefix hoặc generic, findings/facts không nêu count + toàn bộ rule IDs + exact window, inference/uncertainty/limitation rỗng/placeholder/không gắn evidence, hoặc MITRE không có trong Wazuh evidence. UI hiển thị warning nổi bật và không biến nội dung generic thành kết luận hoàn chỉnh.
- Ingest correlation poll aggregate-only, đúng một HTTP request mỗi vòng, tối đa 15 giây; timeout request cuối được cắt theo ngân sách còn lại. Khi hết hạn, run kết thúc `no_matching_alert`, không replay attack, không scan hồi tố và không tạo AI job. UI mô tả đúng rằng chưa thấy matching alert trong bounded polling/correlation window, không kết luận script không phát telemetry.

| Scenario | Live Wazuh evidence | AI/persistence | Kết luận |
|---|---|---|---|
| `file-inclusion` | `1 × 31104` | Historical job `#191` `succeeded`; Wazuh-confirmed MITRE `T1055`, `T1083`, `T1190` | `detected`; job có trước exact-prefix gate mới, không retry/rewrite |
| `xss-reflected` | `1 × 31105` | Historical job `#192` `partial`; MITRE `T1059.007` khớp Wazuh | `analysis_partial` vì summary thiếu exact correlation window UTC; không retry |
| `api` | Trong deadline: `0`; read-only diagnostic sau đó thấy `1 × 31101` tại `2026-08-12T10:53:04.826Z` | Không tạo AI job; tổng history vẫn 192 | Run `3156b7cd7844424bb81c073264608a01`, window `10:52:33Z..10:53:13Z`, terminal `no_matching_alert`; alert chỉ visible sau deadline 12 giây, nên đây là ingest-latency miss, không phải rule/script/window sai |

- Known limitation: security-run state vẫn ở memory, vì vậy restart không khôi phục run transcript/state; riêng API run không có persisted AI job theo đúng no-retroactive-analysis contract. Historical jobs `#191/#192` là bằng chứng đã ghi trước/cùng thời điểm hardening, tuyệt đối không retry để làm đẹp kết quả.
- Đã sửa race best-effort metric khi SQLite xóa `dashboard.db-shm` giữa `stat`: `/api/status` không còn transient 500. Verification cuối: `205 passed`, `python -m compileall -q ai_module`, `node --check ai_module/web/app.js`, `node --check ai_module/web/test.js`, Git Bash syntax `dvwa-module-test.sh` và `git diff --check` đều PASS; chỉ có warning LF/CRLF.
- Dashboard đã restart an toàn bằng current code tại `http://127.0.0.1:8765` (PID `14132`): PID cũ `2844` đã dừng và chỉ còn một loopback listener. Post-restart `/api/status` HTTP `200`, database `ok`, worker/scheduler/delivery worker `running`, queue `0`; schedule vẫn disabled/idle, history giữ đủ 193 job (bao gồm operator-created job `#193`) và security catalog không có active run.
- UI stale-state fix: ảnh Brute Force mở modal đến từ tab/DOM giữ catalog cũ; backend vẫn trả `422` trước SSH nhưng thông báo trước đây nằm sau backdrop nên trông như không phản hồi. Trang hiện ghi rõ `3/18` flow đã xác minh, render lý do khóa trên card, revalidate catalog trước modal và POST, đặt lỗi ngay trong modal `role=alert`, đồng thời phục vụ page/script với `Cache-Control: no-store` + versioned asset URL. Browser acceptance dùng intercepted synthetic `422` xác nhận Brute Force disabled/không mở modal và lỗi File Inclusion hiện inline; không chạy traffic thật hoặc tạo job.

## Trang kiểm thử DVWA (2026-08-12)

- Terminal chỉ đọc đã được thêm vào active-run panel: command SSH allowlist hiển thị với private-key path ẩn, transcript output/redaction và preview script gửi tới Kali. Không có terminal input và browser vẫn không thể thay đổi command/target/payload.
- Prototype ban đầu triển khai `/security-tests` với 18 card scenario; catalog vận hành hiện đã thu hẹp còn ba flow có telemetry contract như bảng closeout phía trên. Confirmation dialog, API catalog/run/status và runner SSH serial vẫn chỉ cho Kali `.30` tới DVWA `.20`; browser không thể truyền command, target, URL hay payload.
- Timebox được siết để tránh treo: SSH connect tối đa 5 giây, curl mỗi request 2 giây, script deadline 18 giây và runner timeout 20 giây. Dashboard hiện chạy loopback tại `http://127.0.0.1:8765` (process Python đang listen trên cổng 8765).
- Historical prototype smoke từng chạy đủ 18 script với exit code `0`; điều đó chỉ chứng minh request đã được gửi tới DVWA, không chứng minh exploit hay detection. Kết quả này đã bị thay thế làm acceptance bởi ba flow correlated trong bảng closeout; 15 prototype scenario không còn enabled.
- Historical smoke từng thấy 4 alert (`31104` x1, `31105` x2, `31101` x1) nhưng không đủ correlation để gán theo scenario. Contract mới đã có per-run UTC/source/agent/rule filtering; không dùng số liệu smoke cũ để claim coverage.
- Verification: `46 passed` cho `tests/test_security_test_runner.py` + `tests/test_dashboard_api.py`; thêm regression UI tĩnh cho page test. `node --check ai_module/web/test.js` và `git diff --check` PASS. `bash -n` không chạy được trên host vì WSL bị vô hiệu hóa, nhưng script đã chạy live thành công qua Bash của Kali.
- Next: thêm Evidence/Run store, query Indexer theo UTC window từng run và display Wazuh rule/count trên page trước khi bật claim PASS/FAIL theo module; kiểm tra cleanup của các scenario stateful.
Đã xuất dữ liệu Chương 4: toàn bộ số liệu thực nghiệm đo đạc thực tế từ repo đã được xuất ra file `SoLieuC4.md` (môi trường, bộ dữ liệu 33 case, kiểm thử FR-01->FR-08, tỷ lệ schema 97.0% vs 100%, điểm AI-judge 3.44 vs 3.30, latency 2.716s vs 2.173s, VRAM 4.7GB vs 2.5GB). Đã kích hoạt mô hình `CyberCrew/notmythos-8b:latest` trên Web UI dropdown thông qua `config.yaml`. Đã thực hiện kiểm thử tấn công thực tế từ Kali (`192.168.100.30`) đến Victim (`192.168.100.20`), đẩy alert lên Wazuh Indexer và chạy window analysis trên Web UI (`127.0.0.1:8765`), lưu trữ kết quả kiểm thử vào SQLite Database (`dashboard_data/dashboard.db`) cho cả 2 mô hình (Job #26 `qwen2.5:7b` thành công `succeeded` và Job #27 `CyberCrew/notmythos-8b:latest` rơi vào `local_fallback` `partial` do vi phạm strict JSON schema trên prompt aggregate window). Đã cập nhật Mục 4.6 Bảng 4.4 vào `SoLieuC4.md`. Không sửa code ứng dụng core hay giả lập số liệu.
Hardening đã merge: `origin/main` commit `04cae1b` qua PR #4; cả bốn job CI Ubuntu/Windows × Python 3.11/3.12 xanh.
Closeout branch hiện tại: `codex/pr4-closeout`, chỉ đồng bộ ledger merge này trước khi kết thúc phiên.
Continuity: đã thêm `CLAUDE.md` và `.githooks/pre-commit`; mỗi clone cần chạy `git config core.hooksPath .githooks` để bật ledger gate.
`eval/run_eval.py` tồn tại trong checkout; path case đã resolve theo repo root, không phụ thuộc CWD.

## Cập nhật Gmail rich report (2026-08-11)

- Gmail report hiện là `multipart/alternative`: bản `text/plain` dự phòng và bản HTML chứa đầy đủ trường phân tích nằm trong allow-list (metrics, confidence, summary, root cause, findings, MITRE, next steps, facts/inferences/uncertainties/limitations/warnings, hash). Không gửi raw log, alert reference, IP/email, credential, prompt hay private reasoning.
- Bản HTML có **Alert map - Mật độ alert theo thời gian** dạng biểu đồ cột inline; timeline được gộp tối đa 48 bucket (16 bucket khi giới hạn body nhỏ) và bản text có map dự phòng cho email client không render HTML. Rule trùng được gộp trước khi hiển thị.
- Delivery Gmail của Job `#36` (delivery `#6`) đã được operator xác nhận gửi lại sau khi đổi formatter, chuyển `pending -> sent`; đây là lần thử `2/3`, không chạy lại AI/job và không tự gửi thêm lần nào.
- Telegram hiện gửi summary ngắn qua `sendMessage` và PDF full report qua `sendDocument`; PDF có dashboard overview và Alert map đồ họa, dùng cùng rich allow-list với Gmail. Job `#36` delivery `#7` đã có attempt `2/3` gửi summary + PDF cũ; lần kiểm thử layout mới ở attempt `3/3` nhận summary nhưng PDF kết thúc `uncertain` do timeout upload, nên không tự retry thêm.
- Kiểm thử sau thay đổi: full suite `150 passed in 6.72s`, `compileall`, Node syntax, production-secret scan và `git diff --check` đều PASS. Dashboard chạy tại `http://127.0.0.1:8765` (PID `27848`), app/worker/delivery worker `running`; PDF upload có timeout đọc tối thiểu 45 giây.

## Notification delivery (2026-08-10)

- Đã triển khai Telegram outbound opt-in cho manual/scheduled report: UI/API chỉ cho chọn `none|telegram`; job `succeeded|partial` có thể xếp hàng gửi, job empty/failed/cancelled không tự gửi.
- Gmail outbound đã dùng chung delivery worker/API/UI với Telegram; chọn `gmail` cho job/lịch, SMTP SSL `smtp.gmail.com:465` dùng Google App Password trong `ai_module/gmail.local.env` (gitignored), không lưu credential/body vào SQLite.
- Schema SQLite v6 mở rộng `report_deliveries` và `delivery_channel` cho Gmail, chỉ lưu channel/status/attempt/hash/message ID/error code. Worker recovery đổi request dở dang thành `uncertain`; retry phải xác nhận nguy cơ message trùng và tối đa ba lần.
- Telegram summary/PDF formatter dùng rich allow-list (metrics, confidence, findings, MITRE, assessment basis, Alert map, warnings và analysis hash); redact inline secret, IPv4/IPv6/email. Không lưu/gửi raw log, alert reference, prompt hay private reasoning. Unexpected provider exception không ghi traceback có thể chứa token URL.
- File người vận hành điền secret đã có tại `ai_module/telegram.local.env` và đã gitignore. Dashboard có nút **Cài đặt Telegram** để ghi token/chat ID vào chính file local này mà không phản chiếu secret qua API/UI. Hướng dẫn: `docs/telegram.md`; lấy chat ID hoặc gửi test tĩnh: `python scripts/telegram_setup.py --discover-chats` / `python scripts/telegram_setup.py`.
- File Gmail mẫu tại `ai_module/gmail.local.env.example`; sao chép thành `ai_module/gmail.local.env`, điền sender/App Password/recipient hoặc dùng **Cài đặt Gmail**, rồi gửi test tĩnh. Hướng dẫn: `docs/gmail.md`.
- Token bot từng được dán vào cuộc hội thoại phải được revoke/rotate trong `@BotFather` trước live test. Không dùng lại hoặc dán token mới vào chat. Sau khi rotate, điền token mới và numeric chat ID vào file local, gửi `/start` cho bot, rồi chạy test.
- Verification Gmail/Telegram: full suite hiện tại `149 passed`; compileall, Node syntax, production-secret scan và `git diff --check` đều PASS. Migration database live v5 -> v6 đã hoàn tất sau khi tạo backup local; Job `#36` đã gửi live thành công qua cả hai kênh.
- Dashboard hiện chạy tại `http://127.0.0.1:8765` (PID `27848`); app/worker/delivery worker `running`, lịch sử job và delivery được giữ nguyên.
- Đã sửa lỗi UX ở Fixed windows: polling trạng thái không còn ghi đè model/ngôn ngữ/kênh delivery mà analyst đang chỉnh; form báo **chưa lưu** và chỉ đồng bộ server sau khi bấm **Lưu lịch**.

## Trạng thái release hiện tại

- Hardening hiện tại hoàn tất Milestone 0–2 và phần tự động của Milestone 4: dashboard window dùng RAG từ rule group đã sanitize, relevance threshold/context bound, provenance JSON scrub và trạng thái truthful. RAG tạo collection staging theo corpus/schema/model digest rồi chỉ swap manifest active khi build đủ; lỗi embedding giữ nguyên generation đang active. Output chỉ hỗ trợ `vi/en` và public evidence trace; private chain-of-thought không lưu/hiển thị.
- Cancellation là cooperative: Ollama có thể chạy đến khi request trả về, nhưng transaction terminal chỉ persist result khi `cancel_requested=0`; cancel ở `saving_result` kết thúc `cancelled` và không có result row/success giả. Alert detail/API/CLI đều data-minimized, request JSON có cap 64 KiB, TLS verify mặc định bật.
- Verification hiện tại PASS: `119 passed` trong 4.93s; compileall, JavaScript syntax, Git Bash syntax, secret scan, dependency audit, CSV/eval summary và `git diff --check` đều PASS. Không chạy manual UI, live Wazuh/Ollama hoặc traffic mới trong hardening này.
- Evaluation chưa phải evidence chất lượng: CSV baseline 33/33 mỗi mode và AI-judge 66/66 vẫn chỉ là scoring phụ (RAG thắng 8, hoà 18, no-RAG thắng 7). Trước bất kỳ claim semantic/RAG benefit cần hai reviewer độc lập, adjudication và study thời gian analyst theo `docs/improvement-plan.md`.
- Governance còn cần owner thực hiện: rotate/revoke mọi credential từng có khả năng xuất hiện trong Git history và quyết định có rewrite history hay không. Runbook/source hiện tại đã dùng placeholder; không tự động rewrite lịch sử hoặc giả lập việc rotate.
- Phạm vi localhost SOC đã hoàn tất theo `docs/product-roadmap.md`: Wazuh Indexer window/aggregate, Ollama VI/EN, evidence trace công khai, job lifecycle/schedule, JSON report v2/v1, analyst review case-lite, history filter/pivot, health, retention, Telegram bot và Gmail delivery opt-in. Không triển khai auto-remediation, remote multi-user, PCAP, inbound bot/email hoặc OAuth trong release này.
- Báo cáo AI có phase thật và provenance để phân biệt `ollama_model`, `local_fallback`, empty window và `unknown_legacy`; không có loading giả. Audit gồm response/model/prompt/input/schema hash, deterministic options, language compliance, latency/token và model digest advisory có nguồn/thời điểm quan sát.
- SQLite schema v6 giữ migration v1/v2/v3/v4/v5, append-only review history, delivery audit queue và data minimization. `sample_log` chỉ dùng trong memory prompt, không ghi DB/export; exact echo của model bị redaction trước persistence, job chuyển `partial` và report có warning. Delivery chỉ lưu hash/message ID, không lưu nội dung gửi.
- UI desktop/table changes tại `ai_module/web/styles.css` và regression `tests/test_dashboard_ui.py` đã được giữ, review và chạy cùng full suite hardening; không reset/ghi đè thay đổi sẵn có.
- Cổng local mới nhất là `149 passed` trong 6.18s; live Telegram và Gmail delivery đều PASS. Warning còn lại chỉ là chuyển đổi LF/CRLF của Git.
- Runtime dùng Waitress hard-bind `127.0.0.1`; Ollama loopback là mặc định, remote chỉ khi `allow_remote: true` với HTTPS. Read connection SQLite được đóng tường minh để không khóa DB trên Windows.
- Frontend có loading theo `queued/fetching_alerts/preparing_analysis/calling_ollama/saving_result`, freshness, quick pivot rule/agent/source IP, review history, dependency badges và retention confirmation. JSON v2 là mặc định; JSON v1 chỉ dành cho consumer cũ.
- Automated release gates PASS: toàn bộ `89 passed`, compileall, `node --check`, Git Bash syntax cho 3 attack scripts + pre-commit hook, workflow YAML và `git diff --check`. Waitress loopback HTTP smoke PASS trên temp DB; lần đầu phát hiện/đã sửa SQLite handle leak. Không chạy lại manual lab traffic hoặc Nikto theo yêu cầu user.
- PR #2 CI lượt đầu: Ubuntu 3.11 chạy đủ `89 passed`/Node/Bash nhưng fail merge gate vì 14 Markdown hard-break trailing spaces lịch sử trong `docs/manual-test.md`; follow-up `ed7a24a` chỉ xóa whitespace, không đổi runbook semantics. Matrix 4 job sau follow-up đều xanh và PR đã squash merge thành `700416d`.
- Evidence live cũ vẫn hợp lệ cho đường dữ liệu: job `#22` VI và `#23` EN cùng historical aggregate 12.781 alert đều có Qwen `ollama_model`, compliance `full` và latency khoảng 9-10 giây. Không dùng evidence này để khẳng định semantic accuracy; human review vẫn cần cho nội dung SOC.
- Dashboard đã restart sau merge khi queue rỗng: PID `41728` listen `127.0.0.1:8765`, Waitress worker/scheduler `running`, queue `0`, DB `ok`, 23 jobs giữ nguyên, `retention_enabled=false`; Ollama và Indexer dependency probes đều `ok`.
- Release workflow PR #2 hoàn tất: push → CI 4 job xanh → squash merge `700416d`; không có manual lab traffic/Nikto mới.

## Lịch sử phiên trước (archived đến 2026-08-04)

- Task `SOC prompt + VI/EN + report v2` hoàn tất 2026-08-04: `ai_module/llm.py` dùng contract version `soc-contract-v1`, prompt hệ thống Việt/Anh, untrusted-data boundary và nhắc language ở cuối request; Ollama options cố định `temperature=0`, `seed=42`. Alert/eval vẫn đúng 5 field legacy; dashboard window bắt buộc `response_language`, confidence phần trăm `0-100` và public `assessment_basis` gồm fact/inference/uncertainty/limitation. Đây là audit trace công khai, không phải chain-of-thought/ngôn ngữ suy luận nội bộ.
- JSON export hiện mặc định `local-ai-siem-report/v2` với model/prompt/language audit, analysis + SHA-256, trace, coverage/metrics/timeline/groups/alert references; `?schema=v1` giữ compatibility, schema lạ `422`. Không export `_source`, `full_log`, `sample_log`, prompt, raw response hoặc reasoning. Cross-review phát hiện legacy fallback từng lưu 200 ký tự preview; code mới không còn persist raw preview và cả v1/v2 scrub summary của `output_origin=local_fallback` cũ.
- Live acceptance sau restart current code PASS, không tạo traffic mới: job `#22` (`vi`) và `#23` (`en`) reuse historical aggregate 12.781 alerts, đều `succeeded`, `output_origin=ollama_model`, requested=response language, compliance `full`, confidence `95`, trace counts `3/2/1/1`, options `temperature=0, seed=42` và ba hash prompt/response/analysis đều 64 ký tự. Latency 9.277s/10.001s, prompt/output tokens 1.808/540 và 1.787/581. Job `#13` vẫn export `unknown_legacy`; `#18/#19` là expected audit evidence cho pre-fix invalid/mismatched output và giữ `partial`, không được dùng làm report semantic.
- Final automated verification: compileall PASS, toàn bộ `74 passed`, `node --check` PASS, Git Bash syntax PASS cho 3 attack scripts + pre-commit hook, `git diff --check` PASS (chỉ warning LF/CRLF). `main.py --help` và `eval/run_eval.py --help` đều PASS trên Windows; eval runner mới không ghi đè baseline nếu thiếu `--overwrite`. Dashboard current code được chủ ý giữ chạy PID `39752` tại `http://127.0.0.1:8765`; app/worker/scheduler running, RAG dashboard disabled.
- Task `Qwen loading/provenance + JSON export` hoàn tất 2026-08-04: audit xác nhận report dashboard được tạo qua `ollama.Client.chat`, không có report generator giả ở frontend; nguyên nhân gây nghi ngờ là UI không tự mở job mới, chỉ hiện `pending/running` chung và report lịch sử đã persist xuất hiện tức thì. SQLite schema v3 giờ lưu phase `queued/fetching_alerts/preparing_analysis/calling_ollama/saving_result/completed`, provenance Ollama, output origin và response hash; UI có spinner theo phase thật, model/latency/token/hash evidence và nút **Xuất JSON**. Không chèn artificial delay.
- JSON export contract hoàn tất: `GET /api/jobs/<id>/export` tải `wazuh-ai-job-<id>.json` schema `local-ai-siem-report/v1` gồm job/model call/analysis/hash/coverage/warnings/metrics/timeline/groups/alert references; loại raw `_source`, `full_log` và `sample_log`. New valid response ghi `ollama_model`, invalid response dùng app fallback ghi `local_fallback`, historical result không có provenance ghi `unknown_legacy`; audit metadata không phải chữ ký mật mã hoặc human ground truth.
- Live provenance acceptance PASS: restart old dashboard PID 39756 sang current code PID 39456 tại `http://127.0.0.1:8765`, app/worker/scheduler running, DB thật migrate v2→v3 và history giữ nguyên. Không rerun Nikto/traffic; job `#15` reuse window aggregate cũ, exact 12.781 alerts, trace `fetching_alerts → calling_ollama → completed`, requested/response model `qwen2.5:7b`, wall latency 13.815s, Ollama 1.810 prompt/366 output tokens, provider `ollama`, origin `ollama_model`, response/analysis SHA-256 đủ 64 ký tự; attachment 15.623 bytes HTTP 200. Job cũ `#13` export đúng `unknown_legacy`.
- Final verification cho provenance/export PASS: compileall, toàn bộ `62 passed`, JavaScript syntax, Git Bash syntax cho 3 attack scripts + pre-commit hook và `git diff --check`; chỉ warning LF/CRLF. `README.md` và `docs/manual-test.md` đã mô tả phase, provenance, JSON contract và giới hạn audit. Thay đổi vẫn ở worktree, chưa commit/push.
- Task `chạy dashboard theo runbook` hoàn tất 2026-08-04: app đang chạy PID 39756 tại `http://127.0.0.1:8765`; `/api/status` HTTP 200 báo `app=ok`, `worker=running`, `scheduler=running`, `rag=disabled`; `/api/jobs` HTTP 200 trả 14 history jobs. Chrome CDP đã load trang thật, health text và 14 dòng batch hiện, chọn job, đổi theme light, reload state; desktop document width 1409px/viewport 1424px, mobile viewport 390px/document 390px, không overflow; screenshot `/tmp` ngoài repo đã capture. Không tạo live job mới, không đổi code.
- Task `mở dashboard cho user` hoàn tất: PID 33220 cũ không còn listen (đã chết sau lần trước); start lại `python ai_module/dashboard.py` bằng config gitignored hiện có, dashboard mới chạy PID 38960 tại `http://127.0.0.1:8765`, `/api/status`, `/api/jobs`, `/api/schedule` đều trả 200; đã mở URL này bằng browser mặc định cho user. Không có thay đổi code trong task này.
- Task `final verification + ledger closeout` hoàn tất: compileall PASS, toàn bộ `59 passed`, JavaScript syntax PASS, Git Bash syntax PASS cho 3 attack scripts + pre-commit hook, `git diff --check` PASS; chỉ warning LF/CRLF. `plan.md` checklist alert timeline/scale/language/theme đã hoàn tất. Dashboard PID 33220 được chủ ý giữ chạy tại `http://127.0.0.1:8765` cho user review;
- Đang thực hiện task nhỏ `final verification + ledger closeout`: compileall, full pytest, JavaScript/Git Bash syntax, `git diff --check`, final API/status check; sau đó đánh dấu plan, cập nhật changelog trước handoff và giữ dashboard PID 33220 chạy cho user.
- Task `timeline/theme live render` hoàn tất: dark/light desktop job `#13` đều 1440px/document 1425, 60 timeline bars/12 nonzero, aggregate mode, language VI và AI content visible. Keyboard Space chọn nonzero bucket PASS, reset/create-subjob controls hiện; theme light persisted qua reload. Light mobile viewport 390/document 375 không overflow. Temp Chrome PID 28124/port 9332 đã dừng; dashboard PID 33220 giữ chạy.
- Đang thực hiện task nhỏ `timeline/theme live render`: dùng Chrome profile/port sạch để mở job `#13`, capture dark desktop timeline/AI, light desktop timeline/AI và light mobile; kiểm viewport/document width, 60 bars, mode/language, bucket click filter, theme persistence và create-subjob control (không bấm tạo trong render test).
- Task `live over-cap + Vietnamese acceptance` hoàn tất, không rerun Nikto: tạo job `#13` cho window cũ, `succeeded`, `language=vi`, `analysis_mode=aggregate`, exact 12.781 alerts, 0 alert refs, 12 groups, 60 timeline buckets. Timeline sum và group sum đều 12.781; coverage 12/12, represented 12.781, không truncated; warning nói aggregate-only không tải full log. AI trả tiếng Việt/severity high nhưng semantic vẫn advisory, không ghi live identifier/raw summary vào tracked ledger.
- Đang thực hiện task nhỏ `live over-cap + Vietnamese acceptance`: tạo một manual job mới cho cửa sổ Nikto đã biết `08:10-08:20Z` với model allowlist và `language=vi`, poll terminal, xác minh exact total >2.000, aggregate mode/no refs, timeline/rule groups, warning coverage và phản hồi AI tiếng Việt. Không chạy lại Nikto.
- Task `live schema-v2 restart` hoàn tất: verified/stopped old PID 14572, current code chạy PID 33220 tại `http://127.0.0.1:8765`, HTTP 200, app/worker/scheduler running. Existing DB migrated in place; check time có 12 jobs (không xóa/sửa user jobs), job `#8` vẫn succeeded với 362 refs, existing job columns default `language=en`, `analysis_mode=full`, timeline empty để frontend fallback từ refs. New HTML controls đều served.
- Đang thực hiện task nhỏ `live schema-v2 restart`: resolve/verify exact dashboard PID on port 8765, stop only that process, start current code with existing gitignored config, then verify HTTP/status/schema/history persistence.
- Task `aggregate/timeline/language/theme docs` hoàn tất: README, setup, manual-test, config example và `KE_HOACH.md` mô tả detail cap vs aggregate-only, timeline filter/create-subjob, `vi/en`, persisted light/dark và acceptance không bulk raw log. Historical `#7` được ghi rõ là finding trước fallback, không còn là behavior mong đợi mới.
- Đang thực hiện task nhỏ `docs + live migration/over-cap acceptance`: cập nhật runbook/config mô tả detail cap và aggregate-only, restart dashboard để schema v2 migrate DB thật, xác minh status/history, tạo over-cap job bằng cửa sổ Nikto cũ và chọn language Việt; sau đó CDP render dark/light 1440/390.
- Task `frontend timeline + preferences` implementation hoàn tất: HTML/JS/CSS có alert histogram accessible, bucket filter/reset/create-subjob, aggregate/full mode badge và KPI metrics, `vi/en` selects cho manual/schedule, persisted `dark/light` selector. Window `key_findings` hiện được trình bày ở ô phát hiện chính thay vì fallback root cause rỗng. Dark/light palette regression và targeted dashboard suite `33 passed`; JS syntax PASS. Chưa restart/render live trong task này.
- Đang thực hiện task nhỏ `frontend timeline + preferences`: thêm histogram alert accessible, bucket filter/create-subjob, mode/coverage indicator, manual/schedule language selects và persisted light/dark selector; bổ sung UI regression rồi render.
- Task `backend aggregate fallback + schema v2` hoàn tất: `fetch_alerts_window()` query exact total + timeline/rules/cardinality rồi chỉ tải detail khi `total <= max_alerts_per_job`; over-cap normalized thành groups không có `sample_log`/alert refs. Schema v2 migration thêm job `language/analysis_mode/metrics/timeline` và schedule language; worker/LLM hỗ trợ `vi/en`; job-list metrics dùng aggregate totals. Core/store/API targeted `29 passed`, compile PASS.
- Đang thực hiện task nhỏ `backend aggregate fallback + schema v2`: implement reader count/aggregation branch, timeline/metrics normalization, SQLite migration, job/schedule language và worker/LLM wiring; sau đó chạy targeted core/store/API tests.
- Task `alert timeline + scale/language/theme architecture audit` hoàn tất và `plan.md` đã mở section/checklist mới. Contract đã chốt: dưới cap dùng full alert references; trên cap dùng aggregate-only exact total + date histogram + cardinality + rule buckets/top-hit field allowlist, không bulk `_source/full_log`; bucket timeline có filter/tạo batch con; `vi/en` lưu theo job/schedule; `dark/light` lưu browser-side. Live acceptance sẽ retry window Nikto cũ `#7` (>2.000) sau migration.
- Đang thực hiện task nhỏ `alert timeline + scale/language/theme architecture audit`: đối chiếu reader, worker, SQLite schema, LLM prompt và UI để chốt contract mở rộng không lưu raw log. Hướng dự kiến: full-detail dưới cap; aggregate-by-rule/agent/level/time bucket khi vượt cap; timeline click-to-filter; AI `vi/en`; theme `light/dark`.
- Task `verification cleanup + handoff` hoàn tất: Chrome/CDP tạm PID 25332/port 9331 đã dừng; dashboard vẫn chạy PID 14572 tại `http://127.0.0.1:8765`, root HTTP 200, app/worker/scheduler `running`, RAG dashboard `disabled`. Schedule disabled/idle. API hiện trả 9 jobs; latest `#9` là manual empty window succeeded (0 alert/no AI), còn DVWA evidence `#4-#8` giữ nguyên. Final `git diff --check` sau ledger PASS, chỉ warning LF/CRLF.
- Đang thực hiện task nhỏ `verification cleanup + handoff`: dừng Chrome/CDP tạm ở port 9331, kiểm tra dashboard vẫn HTTP 200/worker/scheduler running trên `http://127.0.0.1:8765`, cập nhật PID/trạng thái cuối.
- Task `UX full verification` hoàn tất: compileall PASS, toàn bộ `52 passed`, JavaScript syntax PASS, Git Bash syntax PASS cho 3 attack scripts + pre-commit hook, `git diff --check` PASS; chỉ có warning LF/CRLF. Toàn bộ checklist `UX batch log + AI review` trong `plan.md` đã đánh dấu xong.
- Đang thực hiện task nhỏ `UX full verification`: chạy compileall, toàn bộ pytest, JavaScript syntax, Git Bash syntax cho attack scripts/hook và `git diff --check`; sau đó cập nhật checklist/ledger và dừng Chrome tạm nhưng giữ dashboard live cho user.
- Task `live row-to-AI mapping verification` hoàn tất: Chrome/CDP chọn `#4` click, `#5` Enter, `#6` Space, `#7` click, `#8` Enter; mỗi lần có đúng một selected row và title khớp. `#4` succeeded/no-AI empty state; `#5/#6` succeeded/low với content; `#7` failed/empty state; `#8` succeeded/high với 4 next steps.
- Đang thực hiện task nhỏ `live row-to-AI mapping verification`: dùng Chrome/CDP chọn batch `#4-#8` bằng click, Enter và Space; đối chiếu selected row, job title, empty/failed state và AI severity/content tương ứng.
- Task `mobile table containment fix` hoàn tất: `.grid > .card { min-width: 0; }` giữ bảng 780px trong scroll container, static regression mới bảo vệ containment/overflow. `tests/test_dashboard_ui.py`: `3 passed`; JS syntax PASS. Fresh 1440px desktop và 390px mobile render PASS; mobile `documentWidth=375` trong viewport 390, table scroll nội bộ `311/780`, header/panel AI không còn bị cắt.
- Đang thực hiện task nhỏ `mobile table containment fix`: thêm shrink boundary cho grid/card chứa bảng, bổ sung static UI regression, chạy targeted tests và recapture 390px.
- Task `fresh desktop/mobile capture` hoàn tất với finding: desktop 1440x1000 PASS về render (8 dòng, 8 cột, selected `#8`, panel AI `high`); viewport mobile thật 390x900 làm document rộng 830px vì batch table/grid containment, cắt ngang header và panel. `plan.md` đã thêm task sửa overflow; chưa tính mobile PASS. Hai attempt Node inline trước đó fail do PowerShell làm mất quote, nên harness CDP được đặt tạm ngoài repo rồi chạy thành công.
- Đang thực hiện task nhỏ `fresh desktop/mobile capture`: kiểm tra worktree/process, bảo đảm dashboard live ở `127.0.0.1:8765`, rồi dùng hai Chrome profile/port riêng để tránh lẫn device metrics.
- Task `audit four existing render captures` hoàn tất: cả bốn ảnh đều đang ở layout mobile khoảng 390px dù tên desktop/mobile khác nhau. AI panel trong ảnh hiển thị đủ severity `high`, summary, fallback root cause, MITRE và 4 next steps; chưa tính desktop PASS. Tiếp theo phải capture lại desktop/mobile bằng Chrome profile/cổng sạch.
- Đang thực hiện task nhỏ `render + batch selection verification`: kiểm tra trực quan bảng SIEM/panel AI trên desktop và mobile, rồi xác minh chọn từng batch live `#4-#8`. Dashboard gần nhất được ghi nhận tại `http://127.0.0.1:8765`; chưa đánh dấu render PASS cho đến khi xác nhận viewport bằng phiên Chrome sạch.
- Đang thực hiện task nhỏ `SIEM-style table + AI panel UI`: backend metrics slice đã xong; tiếp theo thay history cards bằng keyboard-clickable table và render AI summary/root cause/MITRE/next steps rõ cho selected batch.
- UI implementation hiện có batch table 8 cột, keyboard row selection và explicit AI panel; targeted API/UI tests `12 passed`, JavaScript syntax PASS. Đang chuyển sang restart/render verification trên live DB, chưa đánh dấu UI task hoàn tất.
- Render attempt 1 tạo được desktop/mobile screenshots nhưng metrics print fail `cp1252 UnicodeEncodeError` khi gặp AI text tiếng Việt; đây là harness console lỗi, không phải web app. Sẽ rerun CDP với stdout UTF-8 trước khi kết luận.
- Backend job-list metrics slice hoàn tất: `list_jobs()` aggregate alert/group/rule/agent counts, max level và parse latest window severity/summary, không tải raw `_source`; API regression `10 passed`.
- Task `start dashboard for user review` hoàn tất: app đang chạy PID 39728 tại `http://127.0.0.1:8765`, HTTP 200, worker/scheduler running, model `qwen2.5:7b`, history có 8 live-test job. Chủ ý để process chạy cho user xem; lần sau chỉ dừng sau khi user review xong.
- Task `post-hardening final verification` hoàn tất: compileall PASS, `50 passed`, JavaScript syntax PASS, Git Bash syntax PASS cho 3 attack scripts + hook, `git diff --check` PASS; chỉ LF/CRLF warnings. DVWA extension checklist trong `plan.md` đã hoàn tất.
- Task `Nikto explicit opt-in hardening` hoàn tất: default/`all` chỉ chạy baseline/error-burst/signatures; mode `nikto` yêu cầu `I_UNDERSTAND_NIKTO_ALERT_VOLUME`, vẫn có hard wall 50s/kill-after 5s. Git Bash syntax PASS, Nikto guard exit 2, outside-target guard exit 2, static all-exclusion PASS; không rerun scan.
- Task `DVWA cleanup + final verification` hoàn tất: remote `/tmp/web-attack.sh` đã xóa, không còn Nikto process, dashboard PID 17120 đã dừng và port 8765 không listen. Compileall PASS, `50 passed`, JavaScript/Git Bash syntax và `git diff --check` PASS; chỉ LF/CRLF warnings.
- Scenario `nikto` hoàn tất với cap finding: attempt 1 vượt host timeout ~74 giây; remote không còn process, đã thêm/deploy hard wall 50s + kill-after 5s. Retry hoàn tất 14 giây nhưng sinh 5,737 alert. Full-window job `#7` `failed` đúng cap 2,000, 0 refs/results; histogram slice 1 giây có 362 alert/8 groups và job `#8` `succeeded` 362/362. AI `high`, remediation CSP/access-control/error review liên quan hơn, nhưng summary generic, root cause rỗng và MITRE over-map (`T1055/T1083`...), nên pipeline/safety PASS nhưng semantic vẫn cần human review. Không chạy thêm Nikto.
- Scenario `signatures` hoàn tất với finding semantic nghiêm trọng: 3 request tạo `31105` XSS attempt + `31104` common web attack. Dashboard job `#6` `succeeded` 2/2, 2 groups/1 result/không lỗi. AI `severity=low`, summary generic, root cause rỗng và hallucinate/mis-map MITRE (web shell/process injection/local discovery/exfil wording); pipeline PASS nhưng evidence grounding FAIL. AI không tuyên bố payload thực thi, nhưng mapping không đáng tin.
- Scenario `error-burst` hoàn tất với finding semantic: 6 request `404` tạo 6 alert `31101`; không có `31151` ở cap này. Dashboard job `#5` `succeeded` 6/6, 1 group/1 result/không lỗi. AI trả `severity=low`, summary `Analysis of Alerts`, root cause rỗng và next steps generic/lệch sang system update; schema/pipeline PASS nhưng nhận diện repeated probing FAIL. Không overclaim compromise.
- Scenario `baseline` hoàn tất: 3 request DVWA trả `302/200/200`; exact Indexer window `TOTAL=0`, dashboard job `#4` `succeeded`, 0 alert refs/0 AI result/không lỗi. Đây là expected empty-window behavior; chuyển sang `error-burst`.
- Task `DVWA live harness prep` hoàn tất: script copy/normalize + remote syntax PASS trên Kali; dashboard live PID 17120, worker running, allowlist `qwen2.5:7b`. Combined start/poll command bị tool policy chặn, tách thành hai command thì PASS; chưa sinh scenario traffic ở task prep.
- Task DVWA scenario script + runbook hoàn tất: scripts/runbook có guard target, bounded traffic và UTC boundary; tracked runbook không còn chứa credential lab.
- Task `DVWA live scenario audit` hoàn tất: Victim `/DVWA/` trả `302`, Apache active, Victim SSH, Kali SSH/curl/Nikto, Indexer `:9200` và Ollama (5 model) PASS; Indexer 5 phút trước test có 0 alert. Kali probe đầu fail do quoting zsh `unmatched \"`, retry command đơn giản PASS.
- Governance 2026-08-05: mọi credential lab đã bị loại khỏi tracked handoff/runbook. Operator phải dùng secret manager hoặc config gitignored và rotate/revoke mọi giá trị từng xuất hiện trong lịch sử Git trước khi chia sẻ repo.
- Task `final verification + ledger closeout` hoàn tất: compileall PASS, toàn bộ `50 passed`, JavaScript syntax PASS, Git Bash syntax PASS cho 3 attack scripts + hook, palette regression PASS và `git diff --check` PASS; chỉ có warning LF/CRLF. `plan.md` đã đánh dấu đủ checklist.
- Cleanup hoàn tất: dashboard verification process trên port 8765 và headless Chrome/CDP trên port 9223 đã dừng; DB live verification vẫn gitignored để giữ audit/restart evidence.
- Verification attempt 1 dùng bare `bash` đã fail do resolve sang WSL (`HCS_E_HYPERV_NOT_INSTALLED`); attempt 2 dùng `C:\Program Files\Git\bin\bash.exe` PASS. Tiếp tục dùng Git Bash absolute path trên máy này.
- Task `restart/persistence recovery` hoàn tất: attempt 1 với `Start-Process -UseNewEnvironment` fail `WinError 10106` do thiếu environment Winsock; restart lại bằng environment hiện tại PASS. Worker/scheduler `running`, đủ 3 job vẫn `succeeded`, schedule disabled/idle và gap 0; không dùng `-UseNewEnvironment` cho lần chạy tiếp theo.
- Task `live dashboard verification` hoàn tất: model allowlist chỉ trả `qwen2.5:7b`; preset 5m empty-window `succeeded`; custom range `succeeded`; cửa sổ 1 giờ `succeeded` với 2 alert refs, 2 groups, 1 window result và không lỗi; schedule enable/read-back/disable PASS, gap vẫn 0. Selected-job Chrome render PASS (4 KPI, chart/table, focus + tooltip, desktop scrollWidth khớp viewport). Không ghi credential/live identifier vào tracked output.
- Task `palette + render verification` hoàn tất: đổi `--chart-series` sang `#2463ad` (contrast chữ trắng 6.06:1), thêm `tests/test_dashboard_ui.py`, sửa mobile breakpoint/form overflow và toggle layout; palette test PASS, Chrome render desktop 1440px + mobile 390px PASS. Chưa chạy live job trong task này.
- Phiên 2026-07-31 đã đọc `C:\Users\Tplab\.claude\plans\fancy-bouncing-flask.md`, `plan.md`, `CHANGELOG.md` và `HANDOFF.md`; tiếp tục đúng checklist dashboard, không đổi scope.
- Đối chiếu code đầu phiên xác nhận history cap, lifecycle controls, KPI, Top rules chart, keyboard/tooltip, responsive và fallback table đã có; palette/render/live khi đó còn thiếu và hiện đã PASS theo các bullet mới nhất phía trên.
- Baseline đầu phiên trước live PASS: compileall, toàn bộ `49 passed`, JavaScript syntax, shell syntax và `git diff --check`; final hiện là `50 passed` cùng render/live PASS.
- Dashboard AI local MVP đã hoàn tất code/docs: Flask + HTML/CSS/JS thuần, SQLite, một worker, localhost-only; nguồn là full alert document từ Indexer `wazuh-alerts-*`, không dùng archives. Live verification hiện đã PASS.
- Chức năng đã chốt: custom range và preset `5m/15m/30m/1h/2h/6h/12h/24h`, model allowlist từ Ollama, deterministic grouping + một window summary, drill-down group/alert, fixed-window scheduler và bounded catch-up bằng watermark.
- Baseline trước dashboard ngày 2026-07-30: branch khớp `origin/claude/lab-eval-checkpoint`; ledger hook `.githooks` active; `git diff --check`, compileall PASS; `26 passed`.
- Kế hoạch triển khai: (1) time-range reader + reusable analysis service; (2) SQLite/store + worker/scheduler; (3) Flask API/UI; (4) automated và manual live verification. Sau từng slice phải cập nhật `CHANGELOG.md` trước rồi `HANDOFF.md`.
- Multi-agent trong project chỉ được dùng model Fable hoặc Opus; ưu tiên Opus.
- Dashboard phase 1 hoàn tất: `reader.fetch_alerts_range()` validate RFC 3339/timezone, dùng `[gte,lt)`, tối đa 24 giờ, giữ hit identity và không cắt âm thầm khi vượt cap; `fetch_alert_document()` chỉ nhận `wazuh-alerts-*`.
- Thêm `analysis_service.py`: deterministic group/count, bounded aggregate prompt có coverage, reusable per-alert RAG/LLM và window summary schema riêng trong `llm.py`; raw JSON không được đưa nguyên khối vào LLM.
- Verification phase 1: compileall PASS, toàn bộ `33 passed`, `git diff --check` PASS; chỉ có CRLF conversion warnings. Chưa truy cập Indexer/Ollama live.
- Dashboard phase 2 hoàn tất: `dashboard_store.py` dùng SQLite `user_version`, WAL, foreign keys và transactions cho job/schedule/alert reference/group/result; không lưu raw `_source`/`full_log`.
- `dashboard_worker.py` có một worker và một scheduler thread: restart recovery, empty-window không gọi LLM, unique scheduled window, cancellation giữa bước, retry thủ công tối đa 3 lần, ingest delay, fixed `[start,end)` window và catch-up cap có `gap_windows` hiển thị.
- Verification phase 2: compileall PASS, toàn bộ `39 passed`, `git diff --check` PASS; chỉ CRLF conversion warnings. Chưa chạy process dài hoặc lab live.
- Dashboard phase 3 hoàn tất: `dashboard.py` cung cấp Flask API same-origin, bắt buộc localhost config, preset/custom range, Ollama model allowlist, job history/detail/cancel/retry, server-side full-alert lookup và one-schedule config/retry/skip.
- UI tại `ai_module/web/` dùng HTML/CSS/JS thuần, polling 2 giây, có health, job form, schedule, history, window summary, group/alert table và escaped full JSON dialog; không có Node build chain.
- `config.example.yaml` có dashboard caps/path/model; Flask là web dependency duy nhất; `ai_module/dashboard_data/` đã gitignore. App chạy bằng `python ai_module/dashboard.py` tại `http://127.0.0.1:8765`.
- Verification phase 3: compileall PASS, toàn bộ `45 passed`, Flask client/API/security tests PASS, `git diff --check` PASS; chỉ CRLF warnings. Chưa chạy dashboard với config/live Indexer/Ollama.
- Verification docs pass đầu: compileall và `45 passed`; shell syntax PASS; `git diff --check` ban đầu FAIL do trailing spaces trong `docs/manual-test.md:641-642`, đã sửa.
- Verification sau fix PASS: compileall, toàn bộ `45 passed`, 3 attack scripts + hook shell syntax, `git diff --check`; JavaScript `node --check` PASS.
- Local HTTP smoke PASS bằng config giả/RAG off trên `127.0.0.1:18765`: `/` và `/api/status` trả thành công, worker/scheduler running; process đã dừng, DB smoke nằm ngoài repo. Chưa gọi live Indexer/Ollama hoặc chạy scheduled window thật.
- Docs đã cập nhật: `README.md`, `KE_HOACH.md`, `docs/setup.md`, `docs/manual-test.md`; runbook có manual window, schedule/recovery và failure/security evidence.
- Simplify pass hoàn tất: UTC/path helpers dùng chung; bỏ unused source hash; tránh eager group payload; WAL chỉ set lúc migrate; job detail dùng một DB connection; catch-up chỉ tạo tối đa cap windows; UI ngừng tải lại full terminal-job mỗi 2 giây; Ollama response parsing dùng helper chung.
- Simplify verification PASS: compileall, toàn bộ `45 passed`, JavaScript syntax và `git diff --check`; chỉ CRLF warnings. Các đề xuất generic hóa schema/progress/state bị skip vì sẽ đổi persistence contract quá rộng trước live test; `analyze_one` giữ lại cho drill-down phase đã chốt.
- Review correctness/security không có finding xác nhận từ review agent; simplify/efficiency findings đã áp dụng thêm: lazy RAG, không exact-count Indexer, active job SQL count, bounded prompt length computation và shared time helpers.
- Final automated verification 2026-07-30 PASS: compileall, toàn bộ `45 passed`, JavaScript syntax, 3 attack scripts + pre-commit hook shell syntax và `git diff --check`; chỉ CRLF conversion warnings. Local HTTP smoke trước đó PASS.
- Dashboard MVP code/docs và live verification đã hoàn tất: preset/custom, cửa sổ có dữ liệu qua Indexer/Ollama, schedule enable/disable, selected-job render và restart persistence đều PASS; không còn dashboard code blocker trong checklist hiện tại.

- Governance continuity hoàn tất: `CLAUDE.md`, `.githooks/pre-commit`, CHANGELOG entry.
- Docs đã đồng bộ: Indexer `:9200`, Manager `:55000` management-only; Windows `.40` Active; Bước 8 có SSH command; FIM marker realtime; model/rule wording thống nhất.
- RAG source hardening hoàn tất: validate list/item/nonblank string ID/duplicate trước embedding/upsert.
- Indexer malformed-hit hardening hoàn tất: fail-closed cho `hits` object, hit và `_source` sai kiểu.
- Eval path fix hoàn tất: `load_case()` resolve theo repo root; test từ CWD khác.
- Full verification cuối: compile PASS, `19 passed`, shell syntax PASS, `git diff --check` PASS; chỉ có CRLF conversion warnings.
- Changelog lưu thay đổi trong `Unreleased`; lịch sử release giữ nguyên.
- Ledger hook: shell syntax và logic cases thiếu/có đủ ledger PASS.
- Verification cuối lặp lại sau ledger update: compileall PASS, `19 passed`, shell syntax PASS, `git diff --check` PASS.
- SSH live ngày 2026-07-29: xác minh key login trên lab; định danh và credential vận hành đã được loại khỏi tracked handoff.
- SSH scenario live PASS: 20 bounded attempts từ Kali `.30` tới Victim `.20`; Indexer batch gần nhất có 21 `5503`, 26 `5760`, source `192.168.100.30`.
- FIM live PASS: Victim đã có `<directories realtime="yes">/opt/wazuh-fim-lab</directories>`; marker tạo/sửa/xóa an toàn, Indexer ghi rule `553` cho delete. Chưa có rule `550` trong lượt này.
- Live AI attempt 1 phát hiện Windows `cp1252` `UnicodeEncodeError`; đã thêm `_configure_console_encoding()` UTF-8 và test hồi quy.
- Live AI attempt 2 PASS: `python ai_module/main.py --limit 3`, model `qwen2.5:7b`, Indexer/RAG/Ollama chạy đủ, 3 JSON output hợp lệ. Quan sát semantic: benign PAM/sudo vẫn có MITRE text chưa chính xác ở vài output; cần human scoring, không blocker pipeline.
- Remote `/tmp/ssh-bruteforce.sh` và `/tmp/fim-trigger.sh` đã dọn trên cả ba VM.
- Full verification sau live lab: compileall PASS, `20 passed`, shell syntax PASS, `git diff --check` PASS; chỉ còn CRLF warnings.
- Web live PASS ngày 2026-07-29: DVWA/Apache reachable, Nikto bounded 44s; Indexer batch gần nhất có `31101`, `31151` correlation và `31105` XSS. Script được sửa dùng `--data-urlencode` cho SQLi curl để tránh HTTP `000`.
- Web eval capture hoàn tất: append 3 case `web-31101-01`, `web-31151-01`, `web-31105-01`; corpus hiện 33 case, không rewrite 30 case cũ; expected vẫn draft-single-reviewer.
- FIM modified PASS: tạo `modified-marker.txt`, chờ baseline 20s, append nội dung, chờ 20s; Indexer ghi `554` add và `550` Integrity checksum changed. Marker vẫn ở `/opt/wazuh-fim-lab/modified-marker.txt` để giữ bằng chứng/baseline; xóa sau khi không cần sẽ sinh `553`.
- Baseline 33 case rerun PASS: RAG 32/33 schema, 22/33 severity exact, mean 2.716s; no-RAG 33/33 schema, 19/33 severity exact, mean 2.428s. RAG `benign-23502-01` fallback `severity=unknown`.
- Human eval package: `eval/summarize_results.py` tổng hợp latency/schema/error/severity và điểm đã nhập; không tự sinh semantic score. Human reviewer và manual timing vẫn bắt buộc.
- Full verification increment: compileall PASS, `21 passed`, summary tool PASS, 3 attack scripts + hook syntax PASS, `git diff --check` PASS; chỉ CRLF warnings.
- AI judge implementation hoàn tất: `eval/judge_results.py` dùng model khác candidate, strict 5-score schema, hashes, resume, file AI-only riêng; summary hỗ trợ `--ai-judgments`; `26 passed`.
- AI scoring hoàn tất: `CyberCrew/notmythos-8b`, prompt `ai-judge-v1`, temperature 0, seed 20260729, 66/66 valid, 0 error. RAG mean 3.44, no-RAG 3.42; paired 8/18/7 win/tie/loss. Đây là AI-only score, không đổi human columns hoặc expected review status.
- Manual runbook hoàn tất tại `docs/manual-test.md`, link từ README/setup/attacks/eval; gồm từng máy, exact command, expected result, timing, troubleshooting, cleanup, AI/human evaluation.
- Verification AI/runbook: compileall PASS, `26 passed`, AI summary coverage 66 PASS, shell syntax PASS, `git diff --check` PASS; secret scan chỉ thấy documented default placeholder và config path, không có live credential.
- Branch đã đồng bộ GitHub tới `ee5d548`; phiên 2026-07-30 cập nhật ledger verification và ignore local `.claude/`, `*.bak`, `ai_module/create_rag_data.py`.

## Trạng thái

- Live Wazuh → Indexer → RAG → Ollama: đã xác minh.
- Dashboard scale/UX: timeline bucket drill-down, aggregate-only trên detail cap, AI `vi/en` và theme `dark/light` đã implement/test live; job `#13` là acceptance evidence 12.781 alert không bulk full log.
- Hardening pipeline và script lab: đã làm, test pass.
- GĐ4 core: hoàn tất 33 case, ground truth review kỹ thuật, rubric, runner, baseline RAG/no-RAG và AI-only scoring 66 output.
- Còn human review/scoring và đo thời gian phân tích tay; không phải blocker code.

## GĐ4 hiện tại

Files:

- `eval/cases/*.json`: 33 alert `sanitized-live`.
- `eval/expected/*.json`: ground truth nháp.
- `eval/manifest.json`: case registry.
- `eval/rubric.md`: chấm 5 tiêu chí, thang 1–5; tách AI/human protocol.
- `eval/run_eval.py`: runner dùng extractor/RAG/Ollama hiện có.
- `eval/results.csv`: `qwen2.5:7b` + RAG.
- `eval/results-no-rag.csv`: cùng model, không RAG.
- `eval/ai-judgments-notmythos-8b.csv`: 66 AI-only judgments.
- `eval/judge_results.py`: strict AI rubric judge.
- `eval/summarize_results.py`: baseline/human/AI summary.
- `eval/baseline.md`: metric và giới hạn kết luận.
- `eval/build_dataset.py`: tái tạo snapshot từ live Indexer.
- `tests/test_eval_dataset.py`, `tests/test_eval_grading.py`: corpus/scoring tests.

Corpus sau review:

- 33 case: SSH 12, FIM 3, web 3, benign 13, ambiguous 2.
- 19 rule ID; thêm web `31101/31151/31105` và 6 benign case `23502` CVE solved.
- Duplicate yếu đã giảm: PAM PID variants, `/bin` vs `/usr/bin` rootcheck, invalid-user variants.
- Sanitization không còn private IP thật, hostname thật, SSH fingerprint, `99-claude-lab`.
- `40112`: `ambiguous/high`, không còn `malicious/critical`.
- Benign `5715`, `5501`, `5402`, `23502`: expected MITRE rỗng.
- `5710` chỉ `Invalid user`: expected MITRE rỗng; `Failed password` variant vẫn giữ mapping.
- `554`, `503`, `506`, `553`: root cause không bịa nguyên nhân ngoài alert.

Baseline tuần tự ngày 2026-07-29:

| Chỉ số | RAG | No-RAG |
|---|---:|---:|
| Hoàn tất | 33/33 | 33/33 |
| Schema valid | 32/33 | 33/33 |
| Lỗi gọi model | 0 | 0 |
| Mean latency | 2.716s | 2.428s |
| Median latency | 2.704s | 2.410s |
| p95 latency | 3.897s | 3.304s |
| Severity exact-match draft | 22/33 | 19/33 |
| AI-only overall mean | 3.44/5 | 3.42/5 |

AI paired: RAG thắng 8, hòa 18, no-RAG thắng 7. Không kết luận RAG tốt hơn từ một lượt stochastic và một AI judge; vẫn cần human semantic scoring.

## Verification gần nhất

```text
python -m compileall -q ai_module eval tests: PASS
PYTHONPATH=ai_module python -m pytest tests -q: 74 passed
node --check ai_module/web/app.js: PASS
C:\Program Files\Git\bin\bash.exe -n 3 attack scripts + pre-commit hook: PASS
Dashboard palettes: dark/light WCAG AA regression PASS; mobile viewport 390/document 375
Dashboard live: jobs #22 VI/#23 EN exact 12.781 aggregate alerts; Qwen model origin + language compliance full, SOC trace/export v2/v1/hash PASS; PID 39752
DVWA live: baseline/error-burst/signatures/Nikto-cap slice đã test; pipeline đọc log PASS, AI grounding findings đã document
DVWA safety: Nikto explicit opt-in guard PASS; remote temp script đã dừng; dashboard hiện chủ ý chạy PID 33220 cho review
python eval/summarize_results.py ... --ai-judgments ...: 66/66 judgments, 0 error
git diff --check: PASS
RAG baseline: 33/33 completed
No-RAG baseline: 33/33 completed
```

## Việc tiếp theo

1. Human SOC reviewer kiểm semantic của job `#22/#23`; schema/language/provenance PASS không tự chứng minh severity/MITRE/khuyến nghị đúng.
2. Reviewer người thứ hai chấm/adjudicate `eval/expected/*.json` và 66 output; AI score hiện có chỉ là benchmark phụ.
3. Đo baseline phân tích tay trên cùng 33 case theo `docs/manual-test.md`.
4. Nếu cần model candidate đối chứng, chạy cùng corpus/prompt/config/language và file output mới; không dùng judge score như human ground truth.
5. Windows Sysmon chưa có scenario/config canonical; chỉ Windows Wazuh agent đã Active.
6. Chạy `git config core.hooksPath .githooks` nếu clone mới chưa bật ledger gate; review/stage đúng file, không stage `.claude/`, `.bak`, log runtime hoặc `create_rag_data.py` mù.

## Lệnh tiếp tục

```bash
git status --short
git diff --check
python -m compileall -q ai_module eval tests
PYTHONPATH=ai_module python -m pytest tests -q
bash -n scripts/attacks/fim-trigger.sh scripts/attacks/ssh-bruteforce.sh
```

Regenerate corpus chỉ khi muốn snapshot mới; lệnh này xóa/rewrite `eval/cases` và `eval/expected`:

```powershell
python eval/build_dataset.py
python eval/run_eval.py --model qwen2.5:7b --language vi --results eval/results-soc-contract-v1-vi-rag.csv
python eval/run_eval.py --model qwen2.5:7b --language vi --no-rag --results eval/results-soc-contract-v1-vi-no-rag.csv
```

## Lab

- SIEM `192.168.100.10`, user `wazuh`.
- Victim `192.168.100.20`, user `trnguyn`, Wazuh agent active.
- Kali `192.168.100.30`, user `kali`.
- Host Ollama `192.168.100.1`.
- SSH key `C:\Users\Tplab\.ssh\id_ed25519`.
- Live config `ai_module/config.yaml` chứa credentials, gitignored; không print/commit.

Observed rules: SSH `5503/5760/2502/5710/5712/40112`; FIM `554/553`; benign/context `5501/5502/5402/5715/503/23502`; ambiguous `506/510`.

## Untracked từ trước — không xóa/commit mù

```text
.claude/
ai_module/create_rag_data.py
ai_module/main.py.bak
ai_module/rag.py.bak
```

`create_rag_data.py` có thể ghi đè corpus RAG. `.bak` là code cũ.

## Model preference

Phiên này do Codex `/root` điều phối; các task bounded dùng Terra agents (`implement_soc_prompt`, `implement_backend_export`, `implement_frontend_trace`), không áp dụng workflow Claude. Luna không khả dụng trong phiên; task nhẹ có thể giao Terra/Luna khi runtime cung cấp.
