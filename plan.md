# Kế hoạch hoàn thiện Dashboard AI local

## Mục tiêu

Hoàn thiện UI trên Dashboard MVP hiện có: đóng vòng đời job/schedule, áp giới hạn history từ config và thêm trực quan hóa selected job dễ đọc, accessible, không thêm dependency.

## Phạm vi

- Reuse Flask API, SQLite store, worker/scheduler và vanilla HTML/CSS/JS hiện có.
- Job controls: cancel pending/running, retry failed.
- Schedule controls: retry hoặc chủ ý skip khi blocked.
- KPI selected job và một horizontal bar chart Top rules, kèm tooltip/focus và table fallback.
- Giữ localhost-only, Indexer `:9200`, alert cap 24 giờ, không lưu raw `_source`/`full_log` trong SQLite.

## Không làm

- Remote bind, auth/TLS, PIT/`search_after`, auto-backoff.
- Trend analytics cross-job, frontend/chart framework, dependency mới.
- Rewrite corpus eval hoặc thay đổi contract persistence.

## File chính

- `ai_module/dashboard.py`
- `ai_module/web/index.html`, `app.js`, `styles.css`
- `tests/test_dashboard_api.py`
- `README.md`, `docs/manual-test.md`
- `CHANGELOG.md`, `HANDOFF.md`

## Checklist

- [x] `max_job_history` được validate và áp phía server.
- [x] Job/schedule actions chỉ hiện ở state hợp lệ; skip có xác nhận.
- [x] KPI, Top rules chart và fallback table dùng cùng selected-job data.
- [x] Chart hỗ trợ hover, keyboard focus, empty state và responsive layout.
- [x] Automated tests, Python compile, JavaScript syntax, palette và diff checks pass.
- [x] Render check và live lab state được ghi trung thực.
- [x] `CHANGELOG.md` cập nhật trước `HANDOFF.md`.

## Verification

```powershell
python -m compileall -q ai_module eval tests
$env:PYTHONPATH = "ai_module"
python -m pytest tests -q
Remove-Item Env:PYTHONPATH
node --check ai_module/web/app.js
git diff --check
```

Live: chạy `python ai_module/dashboard.py` bằng config gitignored theo `docs/manual-test.md`; không ghi credential hoặc live identifier chưa sanitize vào tracked output.

## Hoàn thiện sản phẩm local SOC — 2026-08-05

Mục tiêu: chốt một bản localhost có thể vận hành và kiểm toán được sau khi đối chiếu với
Wazuh Dashboard, Security Onion và OpenSearch Security Analytics. Phạm vi không mở rộng sang
remote/multi-user khi chưa có auth, TLS và RBAC.

- [x] Khóa phạm vi và ghi roadmap sản phẩm tại `docs/product-roadmap.md`.
- [x] Bổ sung system prompt SOC VI/EN, deterministic options và public assessment basis.
- [x] Xuất JSON v2 mặc định, giữ v1 tương thích và loại raw prompt/log/reasoning khỏi export.
- [x] Bổ sung case-lite review bất biến, history filters và quick pivots.
- [x] Bổ sung dependency/queue/database health, retention thủ công và data minimization.
- [x] Chuyển dashboard sang Waitress loopback và chặn Ollama endpoint không an toàn.
- [x] Rà chéo integration và chạy toàn bộ release gates tự động (`89 passed` + Waitress smoke).
- [x] Cập nhật `CHANGELOG.md` trước `HANDOFF.md`.
- [x] Tạo PR, chờ CI xanh và merge `main` (PR #2 → `700416d`).

Không chạy lại traffic tấn công hoặc Nikto trong lượt hoàn thiện này; acceptance dùng test tự động
và evidence live đã có. Human semantic scoring vẫn là hoạt động đánh giá sau release, không phải
blocker code.

## Kế hoạch cải thiện có kiểm chứng — 2026-08-05

Phân tích read-only tại `docs/check.md` xác định giai đoạn tiếp theo là nâng tính
đúng, evidence và reproducibility thay vì thêm feature rộng. Kế hoạch đầy đủ,
acceptance criteria và release gates nằm tại `docs/improvement-plan.md`.

- [x] Milestone 0: truthful dashboard contract cho RAG/aggregate/provenance.
- [x] Milestone 1: manifest/digest embedding quan sát được, staging collection swap atomically,
  threshold, dashboard retrieval và export provenance.
- [x] Milestone 2: cancellation, strict output validation, request/raw-data safety.
- [ ] Milestone 3: two-reviewer human evaluation, paired RAG study, analyst-time benchmark.
- [~] Milestone 4: dependency/SBOM/SCA, secret governance, safety/performance regression; automation đã xong, credential rotation/history decision còn owner.

Không yêu cầu manual UI test trong giai đoạn đang hoàn thiện code; mỗi milestone
phải có automated regression evidence. Human evaluation là study chất lượng
tách biệt, thực hiện khi analysis contract đã freeze.

## Nhật ký thực hiện

### 2026-07-31 — Baseline đầu phiên

- Đã đọc kế hoạch nguồn `C:\Users\Tplab\.claude\plans\fancy-bouncing-flask.md`, `plan.md`, `CHANGELOG.md` và `HANDOFF.md`.
- PASS: `python -m compileall -q ai_module eval tests`.
- PASS: toàn bộ `49 passed`.
- PASS: `node --check ai_module/web/app.js`, shell syntax và `git diff --check`.
- Chưa đánh dấu render/live PASS; tiếp theo đối chiếu code với checklist rồi hoàn thiện phần còn thiếu.

### 2026-07-31 — Hoàn tất checklist

- Sửa chart-series đạt contrast chữ trắng `6.06:1`, thêm palette regression test và sửa form/toggle responsive; render desktop/mobile PASS.
- Live dashboard PASS: preset 5 phút, custom range, cửa sổ 1 giờ có dữ liệu qua Indexer/Ollama, selected-job KPI/chart/table và schedule enable/disable.
- Restart recovery PASS: 3 job terminal và schedule state giữ nguyên sau restart; process verification đã dừng sau khi kiểm tra.
- Final PASS: compileall, `50 passed`, JavaScript syntax, Git Bash shell syntax và `git diff --check`; chỉ còn warning LF/CRLF của Git.

### 2026-07-31 — Hoàn tất UX batch log + AI review

- Bảng SIEM batch 8 cột thay history cards; API metrics và AI panel có severity/summary/root cause/MITRE/next steps cùng empty/failed state.
- Fresh render PASS ở 1440px và 390px; thêm containment `.grid > .card { min-width: 0; }` để table scroll nội bộ, không tràn document mobile.
- Click/Enter/Space mapping PASS cho live jobs `#4–#8`; full verification PASS với `52 passed`.

## Mở rộng live DVWA — 2026-07-31

Mục tiêu: sinh một số traffic web bounded trên DVWA đã cài ở Victim, xác nhận website đọc đúng alert từ Indexer và đánh giá phản hồi AI thật theo từng cửa sổ thời gian; không phá dữ liệu DVWA hoặc mở rộng ngoài lab.

- [x] Rà soát và chuẩn hóa runbook/script cho các kịch bản DVWA an toàn.
- [x] Xác nhận DVWA, Indexer, Ollama và dashboard connectivity trước khi test.
- [x] Chạy các kịch bản, đối chiếu rule/alert mới trong Indexer.
- [x] Tạo dashboard analysis window chứa batch test và review phản hồi AI thực tế.
- [x] Ghi kết quả, giới hạn, cleanup và verification vào `CHANGELOG.md` rồi `HANDOFF.md`.
- [x] Loại Nikto khỏi default/`all` và bắt buộc explicit confirmation sau alert-volume finding.

### Kết quả live DVWA

- `baseline`: 0 alert, dashboard empty-window PASS.
- `error-burst`: 6 alert `31101`; pipeline PASS nhưng AI không nhận diện rõ repeated probing.
- `signatures`: `31105` + `31104`; pipeline PASS nhưng AI hallucinate/mis-map MITRE.
- `nikto`: 5,737 alert; full window fail-closed ở cap 2,000, slice 1 giây 362 alert phân tích thành công nhưng AI vẫn cần human review.
- Cleanup PASS; final compileall, `50 passed`, JavaScript/Git Bash syntax và `git diff --check` PASS.

## UX batch log + AI review — 2026-07-31

- [x] Mở rộng job-list API với alert/group/rule count và window AI severity/summary, không tải raw `_source`.
- [x] Thay history cards bằng bảng SIEM-style responsive, click/keyboard chọn từng batch.
- [x] Làm panel nhận xét AI rõ ràng: severity, summary, root cause, MITRE, next steps và trạng thái chưa có/failed.
- [x] Sửa containment để bảng rộng có thể scroll nội bộ mà không làm document mobile tràn ngang; recapture desktop/mobile sau fix.
- [x] Chạy full verification sau UX fix, cập nhật `CHANGELOG.md` rồi `HANDOFF.md`.

## Alert timeline + scale/language/theme — 2026-07-31

Mục tiêu: giúp người dùng thấy spike alert theo thời gian, drill-down vào bucket cần xem, xử lý cửa sổ vượt 2.000 alert mà không đọc/lưu toàn bộ raw log, đồng thời cho phép chọn ngôn ngữ AI và giao diện sáng/tối.

Nguyên tắc scale:

- Dưới `max_alerts_per_job`: giữ full-detail flow hiện tại và chỉ lưu alert reference/metadata đã sanitize vào SQLite.
- Vượt cap: Indexer chỉ trả exact total, `date_histogram`, cardinality và top rule-code buckets kèm field mẫu giới hạn; không tải `_source/full_log` hàng loạt và không tạo full-alert drill-down giả.
- Aggregate-only result phải ghi rõ mode/coverage; timeline bucket có thể được chọn để tạo một batch con hẹp hơn nếu cần full detail.
- Không dùng tăng cap mù, không PIT/`search_after`, không lưu raw `_source/full_log` trong SQLite.

Checklist:

- [x] Thêm reader aggregate-only fallback, timeline buckets và SQLite migration cho mode/metrics/language.
- [x] Truyền lựa chọn `vi/en` từ manual/schedule job vào prompt và lưu cùng job.
- [x] Thêm alert timeline accessible, click/keyboard lọc alert và tạo batch con từ bucket.
- [x] Thêm lựa chọn theme `dark/light`, lưu browser preference và bảo đảm contrast/responsive.
- [x] Cập nhật API/core/store/worker/UI tests và runbook/config docs.
- [x] Restart dashboard, phân tích lại live window >2.000 alert và render desktop/mobile.
- [x] Chạy full verification, cập nhật `CHANGELOG.md` trước `HANDOFF.md` và giữ dashboard chạy cho user review.

### Kết quả live

- Job `#13` phân tích lại window Nikto cũ bằng `aggregate` mode: exact 12.781 alert, 12 rule groups, 60 timeline buckets, 0 detail refs; timeline/group sums khớp total và coverage không truncated.
- AI language `vi` PASS; output tiếng Việt/severity high nhưng vẫn cần human semantic review.
- Dark/light desktop và light mobile render PASS; keyboard bucket selection/theme persistence PASS, mobile không overflow.
- Final PASS: compileall, `59 passed`, JavaScript/Git Bash syntax và `git diff --check`.
