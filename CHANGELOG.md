# Changelog

Ghi nhận mọi thay đổi quan trọng của repo. Format: [Keep a Changelog](https://keepachangelog.com/).

---
## [Unreleased]

### Added
- Release preparation 2026-08-14: cleaned generated local artifacts from worktree, synchronized Gmail/roadmap wording with shipped local opt-in delivery, and reverified the publish candidate with `222 passed`, compileall, JavaScript/shell syntax, secret scan, and `git diff --check`.
- Trang `/security-tests` nay có model selector cho từng lượt chạy. Catalog chỉ công khai model vừa thuộc `security_tests.allowed_analysis_models` vừa đang cài trong Ollama; API/runner kiểm tra lại trước SSH, khóa lựa chọn trong modal rồi snapshot vào run và SQLite AI job. Model mặc định vẫn là `qwen2.5:7b`, còn target/script/LLM parameters không cho browser thay đổi. Đã bỏ executable fake-curl unit test trên Windows vì PATH của Git Bash có thể rơi xuống `curl` thật; regression security-runner hiện chỉ mock subprocess hoặc đọc source tĩnh.
- Kịch bản `Brute Force (DVWA login)` nay có telemetry contract riêng: script gửi đúng sáu POST với credential lab không hợp lệ; Wazuh custom rule `100120` nhận từng `POST /DVWA/login.php` và correlation `100121` nhận sáu request trong 10 giây từ cùng source. Rule được quản lý tại `infra/wazuh/rules/dvwa_login_burst_rules.xml`, deploy thành file riêng và không sửa `local_rules.xml`; wording chỉ kết luận login POST burst, không suy diễn credential failure hay compromise từ Apache access log.
- Regression Brute Force bảo vệ fixed target, đúng sáu request, khoảng cách 1 giây, curl/script timebox, exact rule `100121`, một AI job tối đa và UI revalidate catalog. Wazuh 4.9.0 `wazuh-analysisd -t` PASS; positive `wazuh-logtest` cho `100120` ở năm dòng đầu và `100121` ở dòng thứ sáu, trong khi GET/query-string/wrong-path không match. Base `100120` dùng `no_log`, nên Indexer chỉ lưu correlation `100121`.
- Live acceptance Brute Force 2026-08-12: lượt chẩn đoán đầu gửi đủ sáu HTTP 302 nhưng cùng timestamp làm event tới Manager lệch thứ tự, tạo `6 × 100120` và không có correlation/AI; không retry hồi tố. Sau khi giãn request và suppress base, run `26595946ffdb4a43890c229ceea92603` tạo đúng `1 × 100121`, một job AI `#194` với `qwen2.5:7b`; summary dẫn đúng count/rule/window và mô tả sáu request, nhưng report giữ `partial` vì findings/inferences/uncertainties/limitations chưa dẫn đủ evidence, không retry model.
- Final Brute Force verification PASS: full `214 passed`, compileall, JavaScript syntax cho dashboard/test page, Git Bash syntax cho ba attack scripts + hook và `git diff --check`; chỉ còn warning LF/CRLF của Git.
- Trang `/security-tests` có terminal chỉ đọc cho từng lượt chạy: hiển thị command SSH allowlist (ẩn đường dẫn private key), trạng thái, transcript output đã redact và preview script chính xác được gửi tới Kali. Terminal không có ô nhập lệnh và không mở rộng quyền chạy ngoài catalog cố định. Catalog active được thu hẹp từ 18 prototype xuống ba kịch bản đã có contract telemetry: `file-inclusion` → `31104`, `xss-reflected` → `31105` và `api` → `31101`.
- Correlation security-test có trusted evidence contract riêng: chỉ chấp nhận marker remote khớp chính xác `SCENARIO`, fixed route Kali `.30` → Victim `.20` và `END_UTC`; query aggregate/detail đều khóa source, agent, rule ID và UTC window. Aggregate/log vẫn nằm trong `<UNTRUSTED_WINDOW_DATA>`, còn metadata đã được server xác minh nằm trong `<TRUSTED_WAZUH_EVIDENCE>`; không có free-form trusted prompt từ browser hay script.
- Security AI bắt buộc mở summary bằng `WAZUH_EVIDENCE total_alerts=N; rule_ids=...; window_utc=START..END.`. Quality gate từ chối prefix thiếu/sai, summary generic, facts/findings không nêu đủ count/rule/window, assessment basis placeholder hoặc không gắn evidence, và MITRE không tồn tại trong Wazuh evidence. Báo cáo bị từ chối được lưu `partial` kèm warning rõ thay vì trình bày như kết luận hoàn chỉnh.
- Live acceptance 2026-08-12: `file-inclusion` tạo `1 × 31104` và historical job `#191` succeeded; `xss-reflected` tạo `1 × 31105` và historical job `#192` partial vì thiếu exact UTC window trong summary; `api` run `3156b7cd7844424bb81c073264608a01` kết thúc `no_matching_alert`, không tạo AI job, rồi read-only diagnostic thấy `1 × 31101` chỉ visible sau deadline ingest. Không replay traffic, không retry/rewrite job lịch sử và tổng history giữ nguyên 192 job.
- Telegram delivery now sends the concise redacted summary followed by a locally generated PDF attachment containing the complete allow-listed review, Gmail-style card/table layout, and graphical Alert map. The PDF chart uses up to 48 peak-scaled bars without the 48-line text fallback, so high-volume windows remain readable. PDF generation is bounded to 12 MiB and document uploads use a 45-second minimum read timeout; a document failure after the summary is accepted is recorded as `telegram_partial_<provider_code>`/`uncertain` rather than retried silently.
- Gmail report formatter now sends the complete allow-listed AI review plus an inline HTML Alert map and plain-text fallback. Sent deliveries can be explicitly re-queued up to the existing three-attempt cap, allowing an operator to regenerate a report after a formatter update.
- Gmail delivery opt-in cho dashboard: chọn `Không gửi`, `Telegram bot` hoặc `Gmail` khi tạo job/lịch; Gmail SMTP dùng implicit TLS và Google App Password local gitignored. Delivery schema v6 giữ audit/retry/recovery chung với Telegram; dashboard có cài đặt/status/test Gmail và report chỉ gửi summary đã redact. Thêm `docs/gmail.md` và `ai_module/gmail.local.env.example`.
- Telegram delivery opt-in cho dashboard: chọn `Không gửi` hoặc `Telegram bot` khi tạo job/lịch, hàng đợi delivery SQLite schema v5 có audit hash/message ID, retry có xác nhận và recovery `uncertain` để tránh gửi trùng sau restart. Report chỉ allow-list summary đã redact; không gửi raw log, alert reference, prompt, reasoning, IP/email hay secret. Dashboard có nút **Cài đặt Telegram** ghi bot token/chat ID vào file local gitignored nhưng không bao giờ trả lại secret; thêm `docs/telegram.md`, helper `scripts/telegram_setup.py` và template `ai_module/telegram.local.env.example`.
- Thêm `CyberCrew/notmythos-8b` và `CyberCrew/notmythos-8b:latest` vào `dashboard.allowed_models` trong `ai_module/config.yaml`.
- Thực thi kiểm thử tấn công thực tế từ Kali (`192.168.100.30`) trên Web UI (`127.0.0.1:8765`), lưu trữ kết quả kiểm thử đối chứng vào SQLite Database (`dashboard_data/dashboard.db`) (Job #26 `qwen2.5:7b` - `succeeded` và Job #27 `CyberCrew/notmythos-8b:latest` - `partial`).
- Cập nhật Mục 4.6 Bảng 4.4 và nhận xét so sánh kiểm thử thực tế Web UI / SQLite vào `SoLieuC4.md`.
- Chạy benchmark mô hình đối chứng `CyberCrew/notmythos-8b` trên 33 case eval và cập nhật bảng so sánh 2 mô hình vào `SoLieuC4.md` (độ trễ 2.173s vs 2.716s, điểm AI Judge 3.30 vs 3.44, JSON valid 100% vs 97.0%, VRAM 2.5GB vs 4.7GB).
- Xuất toàn bộ số liệu thực nghiệm đo đạc thực tế từ repo ra file `SoLieuC4.md` phục vụ biên soạn Báo cáo Chương 4 (môi trường phần cứng/phần mềm, kho tri thức RAG, bộ dữ liệu 33 case sanitized-live, kiểm thử chức năng, tỷ lệ JSON valid 97.0%, điểm chất lượng AI judge, độ trễ và tài nguyên tiêu thụ).
- Release closeout PR #4: all four GitHub matrix jobs (Ubuntu/Windows × Python 3.11/3.12) passed; squash merge landed at `origin/main` `04cae1b`.
- Verified hardening slice 2026-08-05: dashboard window retrieval dùng RAG theo rule group đã sanitize, có threshold distance, context bound, provenance/export scrub và trạng thái truthful. RAG build sang Chroma collection generation mới, chỉ atomically đổi manifest active sau khi đầy đủ embedding; manifest ghi corpus/schema và embedding-model digest khi Ollama cung cấp metadata.
- Cancellation terminal commit: worker lưu result và trạng thái `succeeded|partial` trong một SQLite transaction chỉ khi `cancel_requested=0`; cancel thắng ở pha `saving_result` không tạo result row hay success giả.
- Local safety/governance: request JSON cap 64 KiB/HTTP 413, alert detail DTO redact, TLS verify mặc định, CLI raw alert opt-in, secret scan ở staged/CI và runbook dùng placeholder. Dependency lock/SBOM/SCA có pin Actions, quyền read-only và exception `pip-audit` hết hạn rõ ràng.
- Automated verification của hardening: `119 passed` (4.93s), compileall, JavaScript syntax, Git Bash syntax, secret scan, dependency audit, CSV integrity/eval summary và `git diff --check` PASS. AI-judge baseline chỉ là chỉ số phụ; human review chưa hoàn tất.
- Kế hoạch cải thiện có kiểm chứng tại `docs/improvement-plan.md`: ưu tiên truthful dashboard/RAG contract, index freshness/provenance, cancellation/output safety, two-reviewer human evaluation, reproducibility và release gates; giữ private chain-of-thought ngoài product data.
- Báo cáo đánh giá read-only được chuyển thành `docs/improvement-plan.md`: chốt backlog AI/RAG/eval/security theo evidence, không sửa code hoặc chạy lại live lab trong bước khảo sát.
- Release closeout after PR #2: all four GitHub matrix jobs (Ubuntu/Windows × Python 3.11/3.12) are green; squash merge landed at `origin/main` `700416d`. Dashboard was safely restarted with an empty queue on `127.0.0.1:8765` (PID `41728`), schema v4 preserved 23 jobs, and dependency probes reported Ollama/Indexer `ok`.
- Local SOC completion slice 2026-08-05: roadmap khảo sát Wazuh Dashboard, Security Onion và OpenSearch Security Analytics tại `docs/product-roadmap.md`; phạm vi chốt localhost, không tự remediation hay mở remote khi chưa có auth/TLS/RBAC.
- Dashboard operations schema v4: append-only analyst review (`new|acknowledged|investigating|resolved|false_positive`), severity override/tags/note, immutable history, bounded search pivots, dependency/queue/database health và retention prune chỉ terminal jobs với `confirm: true`.
- Report v2 audit mở rộng hash/digest-only cho request data, output schema và model; model digest ghi rõ nguồn/thời điểm quan sát. JSON v1 vẫn tương thích; review hiện tại/history được export an toàn.
- Production runtime hardening: Waitress loopback serving, Ollama endpoint allowlist (loopback mặc định; remote phải opt-in HTTPS), Windows-safe SQLite connection cleanup và CI matrix Ubuntu/Windows Python 3.11/3.12.
- SOC contract `soc-contract-v1` 2026-08-04: prompt hệ thống tách riêng VI/EN, coi alert/RAG/aggregate là dữ liệu không tin cậy, bắt buộc phân biệt observed facts/inferences/uncertainties/limitations, confidence `0-100`, output language và strict JSON. Ollama chạy deterministic với `temperature=0`, `seed=42`; provenance lưu prompt version/hash, requested/response language, compliance, options, timing/token và response hash nhưng không lưu prompt hay chain-of-thought.
- Dashboard report v2: export mặc định `local-ai-siem-report/v2` chứa analysis, public `assessment_basis`, model/prompt/language audit, coverage/metrics/timeline/groups/alert references; `?schema=v1` giữ consumer cũ và schema lạ trả `422`. Frontend có panel **Dấu vết phân tích SOC**, confidence %, language compliance/prompt version, nút JSON v2 và JSON v1 tương thích.
- Live acceptance contract mới: job `#22` VI và `#23` EN trên cùng historical aggregate 12.781 alert đều `succeeded`, `output_origin=ollama_model`, requested=response language, compliance `full`, confidence `95`, prompt/output/analysis SHA-256 đủ 64 ký tự và options đúng `temperature=0, seed=42`; latency lần lượt khoảng 9.28s/10.00s. Không sinh traffic/Nikto mới.
- Dashboard AI provenance/JSON export 2026-08-04: SQLite schema v3 lưu phase job và metadata không nhạy cảm từ `ollama.Client.chat` (requested/response model, output origin, Ollama timing/token fields và SHA-256 content); mỗi selected job có **Xuất JSON** trả attachment `wazuh-ai-job-<id>.json` schema `local-ai-siem-report/v1`, không chứa raw `_source`/`full_log`/`sample_log`. Kết quả lịch sử thiếu metadata được ghi trung thực `unknown_legacy`; invalid model JSON được ghi `local_fallback`, không giả là output model.
- Live provenance acceptance 2026-08-04: restart current code migrate DB thật v2→v3, giữ history; job `#15` chạy lại window aggregate cũ với `qwen2.5:7b`, trace thấy `running/fetching_alerts` rồi `running/calling_ollama` và hoàn tất sau 14.325s. Export HTTP 200 ghi `provider=ollama`, requested/response model đều `qwen2.5:7b`, `output_origin=ollama_model`, wall latency 13.815s, 1.810 prompt/366 output tokens, response/analysis hash đều 64 ký tự; job cũ `#13` export đúng `unknown_legacy`. Dashboard current code được giữ chạy PID 39456 tại `127.0.0.1:8765`.
- Provenance/export regression coverage: full verification PASS với `62 passed`, compileall, JavaScript syntax, Git Bash syntax cho 3 attack scripts + pre-commit hook và `git diff --check`; chỉ warning LF/CRLF.
- Dashboard runbook smoke 2026-08-04: existing app PID 39756 served `http://127.0.0.1:8765`; `/api/status` HTTP 200 with app/worker/scheduler healthy and RAG disabled. Chrome CDP interaction loaded page, health text rendered, 14 history rows loaded, light theme persisted, desktop document width 1409px and mobile document width 390px; screenshot captured. No code change.
- Alert timeline/scale/language/theme final verification PASS: compileall, toàn bộ `59 passed`, JavaScript syntax, Git Bash syntax cho 3 attack scripts + pre-commit hook và `git diff --check`; chỉ còn warning LF/CRLF. Dashboard live PID 33220 được giữ chạy cho user review.
- Live timeline/theme render PASS: job `#13` có 60 bars/12 nonzero ở dark và light desktop, aggregate/VI badges đúng; Space selection hiện reset/create-subjob controls; `light` persisted qua reload. Light mobile 390px có document width 375px, AI/timeline không tràn; temp Chrome/CDP đã dừng, dashboard PID 33220 giữ chạy.
- Live over-cap/language acceptance: job `#13` cho cửa sổ Nikto cũ chạy `succeeded` ở `aggregate` mode với exact 12.781 alert, 0 detail refs, 12 rule groups và 60 timeline buckets; group/timeline sums đều khớp total, coverage 12/12 không truncated. Ollama trả tiếng Việt, severity high và warning ghi rõ không tải full log; vẫn cần human semantic review.
- Live schema-v2 restart PASS: dashboard PID 33220 tại `127.0.0.1:8765`, HTTP 200, worker/scheduler running; existing history preserved (12 jobs at check), migrated jobs expose `language=en`, `analysis_mode=full`, metrics/timeline fields without losing job `#8` 362 alert references.
- Frontend alert-map/preferences slice: selected job có histogram timeline accessible, bucket filter/reset và create-subjob; KPI/mode dùng aggregate metrics; manual/schedule có `vi/en`; header có persisted `dark/light` theme với cả hai palette đạt WCAG AA. Dashboard targeted tests `33 passed`, JavaScript syntax PASS; live render còn chờ restart.
- Backend scale/language slice: reader exact-count + timeline/cardinality/rule aggregation tự chuyển `full`/`aggregate` theo detail cap; SQLite schema v2 lưu language/mode/metrics/timeline; worker phân tích aggregate-only không bulk `full_log`, truyền `vi/en` vào LLM và giữ đúng total trong history. Core/store/API targeted verification `29 passed`.
- UX verification cleanup: Chrome/CDP tạm trên port 9331 đã dừng; dashboard được giữ chạy cho user tại `http://127.0.0.1:8765` (PID 14572), HTTP 200, worker/scheduler running.
- UX batch/AI final verification PASS: compileall, toàn bộ `52 passed`, JavaScript syntax, Git Bash syntax cho 3 attack scripts + pre-commit hook và `git diff --check`; chỉ còn warning LF/CRLF của Git.
- Live CDP interaction verification chọn batch `#4-#8` bằng click/Enter/Space: selected row và job title luôn khớp; `#4` empty/no-AI, `#5/#6` review low, `#7` failed state, `#8` review high với 4 next steps.
- Render audit cho UX batch/AI xác nhận panel AI hiển thị severity, summary, fallback root cause, MITRE và 4 next steps; tuy nhiên bốn ảnh capture đầu đều dùng layout mobile khoảng 390px, nên chưa tính desktop render PASS và sẽ capture lại bằng Chrome profile/cổng sạch.
- Job history API trả SIEM batch metrics (`alert/group/rule/agent`, max level) cùng window AI severity/summary bằng aggregate query, không tải raw `_source`; dashboard API tests `10 passed`.
- Dashboard được khởi động lại để user review tại `http://127.0.0.1:8765`: HTTP 200, worker/scheduler running, allowlist `qwen2.5:7b` và 8 live-test job còn trong history; process được chủ ý để chạy sau bàn giao.
- DVWA live closeout: remote temp script và dashboard process đã dừng; post-hardening final compileall, toàn bộ `50 passed`, JavaScript/Git Bash syntax và `git diff --check` PASS, chỉ còn LF/CRLF warnings.
- DVWA `nikto` live result: attempt 1 vượt host timeout; sau hard wall wrapper, retry hoàn tất 14 giây nhưng tạo 5,737 alert. Full-window dashboard job `#7` fail-closed đúng cap 2,000; slice 1 giây job `#8` `succeeded` 362/362, 8 groups. AI `high` và remediation liên quan hơn nhưng root cause rỗng/MITRE vẫn over-map, cần human review.
- DVWA `signatures` live result: 3 request SQLi/XSS/traversal-shaped tạo `31105` XSS attempt và `31104` common web attack; dashboard job `#6` `succeeded` 2/2. AI schema hợp lệ nhưng semantic FAIL: `low`, summary generic/root cause rỗng và MITRE hallucination/mis-map dù evidence chỉ chứng minh attempt.
- DVWA `error-burst` live result: 6 request `404` tạo 6 alert `31101`; dashboard job `#5` `succeeded` 6/6, 1 group, 1 result. AI schema hợp lệ nhưng semantic yếu (`low`, summary generic, root cause rỗng, remediation lệch sang system update), không nhận diện rõ repeated probing; `31151` không xuất hiện ở cap này.
- DVWA `baseline` live result: 3 request bình thường trả `302/200/200`; exact Indexer window có 0 alert và dashboard job `#4` `succeeded` với 0 alert/0 AI result, xác nhận empty-window không gọi AI hoặc bịa kết quả.
- DVWA live harness prep: script mới đã copy/normalize và remote syntax PASS trên Kali; dashboard live khởi động với worker running và allowlist `qwen2.5:7b` trước khi sinh traffic.
- DVWA live preflight 2026-07-31: Victim `/DVWA/` trả `302`, Apache active, Kali có SSH/curl/Nikto, Indexer `:9200` và Ollama reachable; cửa sổ Indexer 5 phút trước test có 0 alert.
- Dashboard restart/persistence verification: sau khi restart process, worker/scheduler trở lại `running`, cả 3 live verification job vẫn `succeeded`, schedule giữ `idle` và `0` coverage gap.
- Live dashboard verification 2026-07-31: model allowlist trả `qwen2.5:7b`; preset 5 phút và custom empty-window đều `succeeded`; cửa sổ 1 giờ chạy Indexer/Ollama thành công với 2 alert, 2 group và 1 window result; schedule enable/read-back/disable giữ `0` gap.
- Selected-job render verification bằng headless Chrome xác nhận 4 KPI, chart/table đồng bộ, keyboard focus và tooltip hoạt động; DOM desktop không có horizontal overflow.
- `tests/test_dashboard_ui.py` kiểm tra tự động contrast các cặp màu dashboard chính, bao gồm chữ trên chart series.
- Dashboard phase 1: reader query alert theo cửa sổ UTC nửa mở tối đa 24 giờ, giữ `_index/_id/_source`, fail rõ khi vượt cap và chỉ cho phép đọc lại document thuộc `wazuh-alerts-*`.
- `analysis_service.py` cung cấp deterministic grouping, bounded prompt kèm coverage, reusable per-alert/RAG flow và strict window-analysis schema tách khỏi schema eval hiện có.
- Dashboard phase 2: SQLite schema/migration lưu job, alert reference, groups, AI results và một fixed-window schedule; worker duy nhất hỗ trợ restart recovery, dedupe scheduled window, cancellation, retry tối đa 3 lần, ingest delay và bounded catch-up có coverage gap.
- Dashboard phase 3: Flask same-origin API và giao diện HTML/CSS/JS thuần chạy `127.0.0.1:8765`, hỗ trợ preset/custom window, model allowlist từ Ollama, job history/result/group/alert detail, fixed schedule và security headers; runtime DB được gitignore.
- Dashboard docs/runbook và final verification ngày 2026-07-31: compileall, toàn bộ `50 passed`, JavaScript/Git Bash shell syntax, palette và diff checks PASS; render desktop/mobile, live Indexer/Ollama và restart persistence đều đã xác minh, process tạm đã dừng.
- Simplify/review pass dùng chung UTC/path và Ollama-response helpers, lazy-init RAG, bỏ source hash không có consumer, tránh group/prompt allocation thừa, giảm SQLite I/O, giới hạn catch-up computation, bỏ exact-total count trên Indexer và ngừng polling full terminal-job detail.
- Test hồi quy cho pipeline AI và GitHub Actions chạy trên Linux/Windows.
- `CLAUDE.md` và `.githooks/pre-commit` ghi quy trình continuity, bắt buộc staged `CHANGELOG.md` và `HANDOFF.md` khi commit thay đổi repo; subagent/multi-agent của project chỉ dùng Fable hoặc Opus.
- GĐ4: corpus alert `sanitized-live`, manifest, expected ground truth nháp, rubric chấm 1–5 và test kiểm tra cấu trúc/sanitization.
- Runner `eval/run_eval.py` tái dùng extractor, RAG và Ollama hiện có; ghi latency, schema validity, raw output và cột human score vào CSV.
- Baseline `qwen2.5:7b` cho cả RAG/no-RAG trên snapshot 30 case; kết quả thô lưu trong `eval/results*.csv`.
- Tài liệu `eval/README.md` và `eval/baseline.md` mô tả protocol model, phân tích tay và giới hạn kết quả.

### Changed
- Security analysis dùng model được operator chọn trong allowlist (mặc định `qwen2.5:7b`), tiếng Việt, `temperature=0`, `top_p=1`, tối đa 512 output token và deadline 45 giây; không retry hoặc tự fallback sang model khác. Ingest correlation chỉ poll aggregate, đúng một HTTP request mỗi vòng và không tạo AI hồi tố cho alert xuất hiện sau deadline.
- Dashboard analyst UX bổ sung filter lịch sử persisted, pivot riêng rule/agent/source IP, freshness created/finished, review timeline, structured dependency/maintenance status và loading theo phase thật; không thêm delay giả.
- Data minimization được áp dụng trước persistence: `sample_log` chỉ tồn tại trong memory prompt; exact sample-log echo từ model được redaction bounded, đánh dấu `partial` và ghi warning/audit count.
- `ai_module/main.py` và `eval/run_eval.py` hỗ trợ `--language vi|en`; CLI in analysis + provenance, eval giữ exact schema 5 field lịch sử nhưng thêm cột prompt/language/provenance. Eval mặc định ghi file gắn `soc-contract-v1` + language, từ chối ghi đè trừ khi có `--overwrite`, nên không làm hỏng `eval/results.csv` baseline cũ.
- `ANALYSIS_VERSION` tăng lên `dashboard-v3`; worker đánh `partial` và phát warning khi output language là `partial|unknown`, không silent retry hoặc giả PASS. Confidence window chuẩn hóa theo phần trăm `0-100` để khớp structured output thực tế của `qwen2.5:7b`.
- Job mới tự mở sau enqueue và UI poll phase persisted `queued/fetching_alerts/preparing_analysis/calling_ollama/saving_result`; spinner mô tả đúng bước backend, không chèn delay giả. Panel kết quả hiển thị provenance/latency/hash để phân biệt phản hồi Ollama với fallback hoặc legacy result.
- README/setup/manual runbook và kế hoạch tổng thể đã mô tả `max_alerts_per_job` là detail cap, quy trình acceptance aggregate-only/timeline subjob, lựa chọn AI `vi/en`, persisted light theme và giới hạn không bulk raw log.
- Mở rộng kế hoạch dashboard theo phản hồi UI: selected-job alert timeline có drill-down bucket; aggregate-only fallback cho cửa sổ vượt detail cap; ngôn ngữ AI `vi/en` lưu theo job/schedule; theme `dark/light` lưu ở browser. Scale path chỉ lấy count/histogram/cardinality/rule-code bucket và field mẫu giới hạn, không tải/lưu raw log hàng loạt.
- `scripts/attacks/web-attack.sh` tách mode `baseline/error-burst/signatures/nikto/all`, whitelist Victim `.20`, cap burst 3–10 request và in UTC boundary; Nikto bị loại khỏi default/`all`, yêu cầu explicit confirmation, đồng thời có `-maxtime 45s` trong hard wall 50s/kill-after 5s. Syntax/target/Nikto guards PASS mà không rerun scan.
- DVWA runbook mô tả review AI theo từng mode; mọi credential lab/Indexer đều dùng placeholder hoặc config gitignored, không lưu giá trị hoạt động trong release note.
- Ignore `.claude/`, `*.bak` và local one-shot `ai_module/create_rag_data.py` để trạng thái Git chỉ hiện source cần quản lý.
- README và `KE_HOACH.md` cập nhật trạng thái GĐ4, đường dẫn chạy eval và phần việc human review còn lại.
- Đồng bộ tài liệu lab: alert đọc từ Indexer `:9200`, Manager `:55000` chỉ quản trị; Windows agent `.40` đã Active; Bước 8/SSH và FIM marker realtime được ghi đúng vị trí.
- Thống nhất model demo nhẹ `qwen2.5:3b` với baseline GĐ4 `qwen2.5:7b`, cùng rule SSH thực tế `5503/5760/2502`.
- Dataset builder giảm dữ liệu nhận dạng lab, giữ provenance và tách input khỏi expected labels; vòng review kỹ thuật giảm duplicate, sửa `40112` thành ambiguous/high, bỏ forced MITRE trên benign/weak-evidence case và thêm benign rule `23502`.
- Chốt kế hoạch dashboard AI local: đọc `wazuh-alerts-*` theo cửa sổ tối đa 24 giờ, phân tích hybrid window/group/alert, lưu job và schedule bằng SQLite, chạy một LLM worker và chỉ phục vụ trên `127.0.0.1`.

### Fixed
- Trang `/security-tests` không còn trông như mất phản hồi khi tab cũ giữ scenario đã bị khóa: card hiển thị rõ chỉ `3/18` contract khả dụng và lý do disable, frontend revalidate catalog `no-store` khi mở modal lẫn ngay trước POST, còn lỗi `409/422/network` xuất hiện trực tiếp trong modal `role=alert` rồi khôi phục nút. Brute Force và 14 flow chưa có telemetry contract vẫn fail-closed trước SSH/traffic.
- Bounded ingest polling không còn có thể vượt ngân sách do request cuối: timeout từng query bị cắt theo thời gian còn lại trong cap 15 giây. Hết deadline chuyển `no_matching_alert`, không replay attack và không tạo AI job; UI nói rõ đây là kết quả của bounded polling/correlation window, không khẳng định script không sinh telemetry.
- Dashboard hiển thị quality warning nổi bật cho job `partial`; summary rỗng/generic không còn được render như báo cáo hoàn chỉnh. `/api/status` cũng không còn trả 500 khi SQLite xóa `dashboard.db-shm` giữa lúc đo kích thước sidecar.
- Verification sau security-evidence và stale-UI hardening: toàn bộ `205 passed`; `compileall`, JavaScript syntax cho dashboard/security-test, Git Bash syntax cho `dvwa-module-test.sh` và `git diff --check` đều PASS (chỉ còn cảnh báo LF/CRLF). Browser acceptance dùng intercepted synthetic `422`, không gửi traffic thật, xác nhận scenario bị khóa không mở modal và lỗi submit hiện inline.
- Schedule form không còn bị polling mỗi 2 giây ghi đè model/delivery đang chọn trước khi bấm **Lưu lịch**; hiển thị trạng thái thay đổi chưa lưu và chỉ đồng bộ lại sau khi lưu.
- PR #2 CI portability follow-up: loại 14 Markdown hard-break trailing spaces cũ trong `docs/manual-test.md` mà `git diff --check HEAD^ HEAD` trên merge ref phát hiện; nội dung runbook không đổi.
- Chặn config truyền trực tiếp vào dashboard/service và direct LLM API bypass endpoint safety; CLI/eval truyền đúng remote opt-in. Model digest được coi là advisory post-chat metadata thay vì bằng chứng đồng thời với chat.
- Sửa SQLite read connections không đóng handle thật trên Windows, tránh khóa database khi retention/cleanup; release verification đạt `89 passed`, compileall, Node, shell syntax, YAML và `git diff --check`.
- Không còn persist/export 200 ký tự raw model preview khi JSON/schema không hợp lệ: fallback chỉ dùng thông báo local đã kiểm soát; cả export v1/v2 xóa summary của legacy `local_fallback` để chặn prompt/log/reasoning từng bị echo. Test mới kiểm raw sentinel không lọt vào fallback, SQLite hoặc JSON report.
- Nhắc language ở cuối system prompt và sau untrusted data boundary, sửa `qwen2.5:7b` bỏ qua lựa chọn VI khi aggregate đầu vào chủ yếu là tiếng Anh; compliance vẫn kiểm độc lập và fail thành `partial|unknown` nếu output lệch/mơ hồ.
- Eval CLI cấu hình stdout/stderr UTF-8 trước `argparse`, sửa `UnicodeEncodeError` trên Windows ngay cả với `python eval/run_eval.py --help`.
- Final verification 2026-08-04: `74 passed`, compileall, `node --check ai_module/web/app.js`, Git Bash syntax cho 3 attack scripts + pre-commit hook và `git diff --check` đều PASS; chỉ còn cảnh báo chuyển LF/CRLF của Git.
- Loại bỏ sự mơ hồ khiến report lịch sử hoặc Qwen chạy nhanh trông như được frontend tạo tức thì: backend giờ lưu phase/model-call evidence, UI tự theo dõi đúng job vừa tạo và JSON export giữ audit fields để đối chiếu/tái sử dụng.
- Batch history grid item giờ có `min-width: 0`, nên bảng SIEM 780px cuộn nội bộ thay vì kéo rộng toàn document mobile; fresh render 1440px/390px PASS (`390px` viewport, `375px` document, table viewport `311px`/scroll width `780px`) và UI regression `3 passed`.
- Fresh 1440px/390px render audit xác nhận desktop batch table/panel AI đúng nhưng phát hiện bảng 780px làm document mobile nở tới 830px và cắt ngang header/panel; chưa đánh dấu mobile PASS cho đến khi sửa grid containment.
- Dashboard UI: tăng contrast chữ trắng trên Top rules bar từ `3.64:1` lên mức WCAG AA bằng series `#2463ad`, đồng thời sửa mobile form/select bị tràn ngang và căn lại toggle schedule.
- Render verification dashboard: xác nhận ảnh desktop 1440px và mobile 390px sau breakpoint responsive mới; không thêm dependency hoặc thay đổi API.
- `docs/setup.md` không còn để Bước 8 rỗng hoặc đặt lệnh SSH dưới mục Windows RDP.
- Tự index dữ liệu RAG ở lần chạy đầu thay vì query collection rỗng.
- Đọc config UTF-8 ổn định trên Windows và giữ tên MITRE technique trong prompt.
- Fallback an toàn khi LLM trả JSON không phải object.
- Áp dụng timeout cấu hình cho Ollama, Wazuh Manager và Indexer.
- Làm cứng JSON schema/response validation, path resolution, Indexer response checks và script sinh alert lab an toàn hơn.
- Hydra exit code 0 khi không tìm thấy credential không còn bị hiểu nhầm thành đăng nhập thành công.
- RAG từ chối source JSON sai top-level/item, ID rỗng hoặc trùng trước khi gọi embedding/upsert.
- Indexer response thiếu `hits` object, hit không phải object hoặc có `_source` sai kiểu giờ fail rõ thay vì bị bỏ qua âm thầm.
- Eval runner resolve `case_file` theo thư mục repo, không phụ thuộc current working directory.
- Verification cuối pass: compileall, 19 pytest, shell syntax và `git diff --check`; chỉ còn CRLF conversion warnings của Git.
- Xác minh SSH key đăng nhập thành công vào SIEM `.10`, Victim `.20` và Kali `.30` trước vòng re-test live lab.
- Re-test SSH bounded từ Kali `.30` tới Victim `.20` thành công: 20 attempts, Indexer ghi 21 rule `5503` và 26 rule `5760` từ source `192.168.100.30` trong batch gần nhất.
- Re-test FIM marker an toàn thành công với `/opt/wazuh-fim-lab/controlled-marker.txt`; Indexer ghi rule `553` (`File deleted`) cho marker, không đụng file nhạy cảm.
- Console Windows được ép UTF-8 trước khi in output tiếng Việt, sửa `UnicodeEncodeError` khi chạy `ai_module/main.py`.
- Live AI pipeline chạy lại thành công trên 3 alert Indexer gần nhất bằng `qwen2.5:7b`, có RAG và JSON output hợp lệ.
- Vòng live-lab cuối pass `20` pytest, compileall, shell syntax và `git diff --check`; script tạm trên VM đã dọn.
- Tạo checkpoint local `1fd6205` trên branch `claude/lab-eval-checkpoint`; secrets, `.claude/`, `.bak` và `create_rag_data.py` không được stage.
- Web live capture PASS sau khi normalize LF khi chuyển script sang Kali: Indexer ghi `31101`, correlation `31151` và XSS `31105`; sửa curl SQLi URL bằng `--data-urlencode` để tránh HTTP `000` do khoảng trắng thô.
- Thêm 3 case web `sanitized-live` cùng expected draft vào eval; corpus tăng từ 30 lên 33 case và dataset tests bắt buộc đủ ba rule web.
- FIM retained-marker re-test xác nhận đủ rule `554` khi add và `550` khi modify `/opt/wazuh-fim-lab/modified-marker.txt` sau baseline 20 giây.
- Rerun baseline 33 case: RAG schema 32/33, severity exact 22/33, mean 2.716s; no-RAG schema 33/33, severity exact 19/33, mean 2.428s.
- Thêm `eval/summarize_results.py` để tổng hợp metric và human scores đã nhập mà không tự bịa điểm semantic.
- Expanded eval verification pass: compileall, 21 pytest, summary tool, shell syntax và `git diff --check`.
- Commit local web/FIM/eval increment: `a267761` trên `claude/lab-eval-checkpoint`; chưa push.
- Thêm AI-only rubric judge `eval/judge_results.py`, strict schema/hash/resume và summary tách biệt human scores; 26 pytest pass.
- `CyberCrew/notmythos-8b` chấm đủ 66/66 output: RAG mean 3.44/5, no-RAG 3.42/5; paired 8 RAG wins, 18 ties, 7 no-RAG wins; AI-only, không phải human review.
- Thêm `docs/manual-test.md`: runbook đầy đủ theo Host/SIEM/Victim/Kali/Windows, exact commands, expected results, timing, troubleshooting, cleanup, baseline, AI judge và human grading.
- Verification AI scoring/runbook pass: compileall, 26 pytest, 66-judgment summary, shell syntax, `git diff --check` và secret scan.
- Commit local AI scoring/runbook: `a5f874b` trên `claude/lab-eval-checkpoint`.
- Publish checkpoint `ee5d548` lên `origin/claude/lab-eval-checkpoint`.
- Verification ngày 2026-07-30 pass: compileall, 26 pytest, 66/66 AI judgments, cú pháp 3 attack scripts + pre-commit hook và `git diff --check`.

## [1.4.0] — 2026-07-26

Hoàn tất GĐ3 — mô-đun AI local chạy thật đầu-cuối (Ollama, RAG, ép JSON schema), đã test với nhiều model.

### Added
- **`ai_module/llm.py`** — implement gọi Ollama thật (`ollama.Client().chat(..., format="json")`), thay thế stub `NotImplementedError`.
- **Few-shot example trong `SYSTEM_PROMPT`** (`llm.py`) — 1 cặp input/output mẫu đã điền sẵn, dùng chung cho mọi model (không if-else riêng theo tên model), giúp model yếu về instruction-following (vd base model) không nhầm mô tả field trong schema thành giá trị cần trả.
- **`_looks_like_echoed_schema()` + `_fallback_result()`** (`llm.py`) — cơ chế fallback dùng chung: phát hiện khi model "trả lại đề bài" (copy nguyên văn mô tả field) thay vì phân tích thực tế, tự động chuyển sang kết quả fallback thay vì trả về JSON vô nghĩa.
- **`ai_module/rag.py`** — implement đầy đủ `index()`/`query()`/`_embed()` qua ChromaDB (persistent local) + Ollama embeddings (`nomic-embed-text`), thay thế stub `NotImplementedError`.
- **`ai_module/rag_data/wazuh_rules.json`** + **`mitre_techniques.json`** — dữ liệu mẫu 11 rule Wazuh + 8 MITRE ATT&CK technique (dựa theo rule thực tế đã gặp: 5503, 550, 60106, 60642...) để RAG có dữ liệu index thật, đã xác nhận `index()` chạy thành công (19 doc).
- **`ai_module/config.example.yaml`** — thêm block `wazuh_indexer` (host/port/user/password/verify_ssl) tách riêng khỏi `wazuh` (Manager API) — khớp với kiến trúc `reader.py` thật (query thẳng Indexer, không qua Manager API).
- **`ai_module/main.py`** — cập nhật xử lý lỗi tổng quát (`except Exception` thay vì chỉ bắt `NotImplementedError`), khởi tạo RAG có try/except để không crash khi thiếu dữ liệu/model embedding.

### Changed
- Đã test end-to-end với 4 model qua Ollama trên alert thật (Windows Logon, FIM, Software Protection): `qwen2.5:7b` và `CyberCrew/notmythos-8b` cho kết quả ổn định, đúng schema, chất lượng tương đương nhau — chọn làm 2 model chính cho GĐ4. `FenkoHQ/Foundation-Sec-8B` (base model, continued pre-train trên corpus bảo mật) không tuân theo structured JSON output ổn định dù đã có few-shot — ghi nhận là hạn chế của model, không phải lỗi hệ thống (chi tiết: `eval/model-comparison.md`, chưa merge lên nhánh chính).

---
## [1.3.0] — 2026-07-17

Mở rộng infra: thêm Windows victim (`.40`) + Wazuh agent. Fix sự cố nghiêm trọng khiến Dashboard timeout sau nhiều ngày vận hành liên tục.

### Added
- **Windows victim** (`.40`) — VM Windows 10 Home, IP tĩnh Host-only `192.168.100.40`, cài Wazuh agent `4.9.0`, xác nhận **Active** trên Dashboard.
- **docs/setup.md** — thêm mục "Windows Victim Setup": cài Wazuh agent bằng `msiexec`, lưu ý bắt buộc chạy quyền Administrator, lưu ý khớp version agent với Manager.
- **docs/network.md** — cập nhật bảng IP, xác nhận Windows victim đã hoạt động (không còn "bổ sung sau"). Thêm mục troubleshoot mới: "Dashboard/Indexer timeout dù container Up".

### Fixed
- **Cài Wazuh agent Windows báo `Error 1925: You do not have sufficient privileges`** — do chạy `msiexec` trên PowerShell không có quyền Administrator (dù account đã thuộc nhóm Administrators, UAC vẫn chặn nếu terminal không được elevate). Fix bằng cách mở PowerShell qua "Run as administrator".
- **Agent Windows cài version `4.14.6` không tương thích với Manager `4.9.0`** — chênh version quá xa (5 minor version) gây rủi ro mất tương thích dữ liệu. Fix bằng cách dùng đúng bản `wazuh-agent-4.9.0-1.msi` khớp Manager.
- **Dashboard/Indexer timeout (`Connection reset by peer` khi TLS handshake) dù `docker compose ps` báo cả 3 container "Up 5 days"** — nguyên nhân gốc gồm 2 lớp:
  1. **Disk đầy 90%** — module Vulnerability Detector (`queue/vd_updater` + `queue/vd`) tích lũy tới **34GB** do tải/cập nhật CVE database liên tục không dọn. Fix: `rm -rf` 2 thư mục này (dữ liệu tự tải lại được, không mất gì).
  2. **Docker bridge network bị hỏng** sau đợt I/O nặng từ sự cố disk đầy — container vẫn tự trả lời OK ở `localhost` bên trong, nhưng hoàn toàn không reachable từ host (`ping` container IP cũng fail), khiến `docker-proxy`/port-publish mất tác dụng dù cấu hình port mapping vẫn đúng. Fix: `sudo systemctl restart docker` để Docker daemon rebuild lại iptables + bridge network.
- **`UnicodeDecodeError` khi `ai_module` đọc `config.yaml` trên Windows** — Python mặc định mở file theo encoding hệ thống (`cp1252` trên Windows), lỗi với ký tự tiếng Việt/dấu ngoặc kép kiểu "curly". Fix bằng cách chỉ định `encoding="utf-8"` tường minh ở mọi lệnh `open()` đọc file text trong `ai_module/`.
- **`fetch_alerts_api()` gọi sai endpoint** (`GET /alerts` trên Manager API, port 55000) → luôn trả `404 Not Found`. Nguyên nhân: alert không được lưu trên Manager, mà nằm ở Indexer (OpenSearch). Fix bằng cách query thẳng `POST /wazuh-alerts-*/_search` trên Indexer (port 9200), dùng credentials Indexer thay vì Manager API — cần thêm block `wazuh_indexer` (host/port/user/password) vào `config.yaml`.

### Changed
- Quy trình đổi lại password Wazuh Indexer khi quên — nhắc lại đúng luồng Docker (hash.sh → `internal_users.yml` → `docker-compose.yml` → xóa volume Indexer → `docker compose up -d`), tương tự Bước 4.5 đã ghi ở `[1.1.0]` nhưng bổ sung lưu ý: cần đợi ~1 phút cho OpenSearch Security plugin init xong sau khi container khởi động lại với volume mới trước khi test — test quá sớm sẽ thấy lỗi `Not yet initialized` gây hiểu nhầm là fail.
---
## [1.2.0] — 2026-07-10

Hoàn tất toàn bộ GĐ2 — cả 3 kịch bản sinh cảnh báo đã xác nhận chạy đúng.

### Added
- Xác nhận thành công 3/3 kịch bản GĐ2: SSH brute-force, Web attack, FIM.
- **docs/attacks.md** — cập nhật rule ID thực tế quan sát được trên Wazuh 4.9.0, khác với rule dự kiến ban đầu trong tài liệu tham khảo.

### Fixed
- **FIM không bắn alert dù script chạy đúng** — do Wazuh FIM mặc định chỉ quét theo lịch 12 tiếng/lần, không realtime. Fix bằng cách thêm `realtime="yes"` vào thẻ `<directories>` trong `ossec.conf` của Victim.
- **DVWA MySQL configuration issue** — historical lab note sanitized; credentials are no longer stored in tracked release notes.

### Changed
- Rule thực tế cho từng kịch bản (xem chi tiết `docs/attacks.md`):
  - SSH brute-force: **5503** (không phải 5710/5712)
  - Web attack: **31101/31151** (khớp nhóm 31xxx dự kiến)
  - FIM: **550** (khớp dự kiến, cần bật realtime)

## [1.1.0] — 2026-07-10

Hoàn tất GĐ1 (dựng lab SIEM) và kịch bản đầu tiên của GĐ2 (SSH brute-force). Fix nhiều sự cố hạ tầng phát sinh trong quá trình vận hành thật.

### Added
- **docs/network.md** — thêm mục "Fix bắt buộc: tắt cloud-init ghi đè netplan" và mục troubleshoot mất kết nối do VMware gán sai vSwitch.
- **docs/setup.md** — thêm Bước 4.5 "Đổi mật khẩu admin mặc định (Docker deployment)" — quy trình đúng cho Docker (hash.sh → internal_users.yml → docker-compose.yml → reset volume), thay vì dùng `wazuh-passwords-tool.sh` (chỉ dành cho bare-metal).

### Fixed
- **Mất IP tĩnh sau mỗi lần reboot VM** (SIEM, Victim) — do cloud-init tự sinh lại `/etc/netplan/50-cloud-init.yaml` ghi đè cấu hình. Fix bằng `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`.
- **SIEM không ping được Kali/Victim dù IP đúng dải** — do VMware gán nhầm virtual switch cho card mạng khi đổi Network Adapter lúc VM đang chạy. Fix bằng cách đổi tạm sang Bridged → NAT/Host-only → Power Off/Power On.
- **Alert không hiển thị trên Dashboard dù Manager đã xử lý đúng** (`alerts.json` có rule 5503 nhưng Indexer không nhận) — do Filebeat trong container Manager vẫn dùng password mặc định `<REDACTED_DEFAULT>` sau khi đổi password admin qua Dashboard UI, dẫn tới lỗi `401 Unauthorized` giữa Manager và Indexer. Fix bằng quy trình đổi password đồng bộ (xem docs/setup.md Bước 4.5).
- **Lỗi `500 Internal Server Error` khi truy cập Dashboard sau khi đổi password** — do session cookie cũ còn tồn tại trong trình duyệt. Fix bằng cách dùng tab ẩn danh hoặc xóa cookie trước khi đăng nhập lại.

### Changed
- Xác nhận rule Wazuh thực tế cho kịch bản SSH brute-force trên bản 4.9.0 là **5503** (`PAM: User login failed`), khác với dự kiến ban đầu trong `docs/attacks.md` (5710/5712) — cần cập nhật lại tài liệu này sau khi test xong toàn bộ kịch bản GĐ2.


## [1.0.0] — 2026-07-06

Khởi tạo repo harness — scaffold đầy đủ để bắt đầu dựng lab.

### Added
- **README.md** — kiến trúc hệ thống, bảng cấu hình đã chốt, quickstart, cấu trúc thư mục, roadmap 4 giai đoạn, nguyên tắc harness.
- **KE_HOACH.md** — kế hoạch lab chi tiết (sơ đồ, IP, RAM, netplan, roadmap, cấu trúc code).
- **infra/wazuh-docker/** — docker-compose placeholder (nhắc dùng script chính chủ Wazuh).
- **infra/netplan/** — 3 file netplan mẫu: SIEM (.10), Victim (.20), Attacker (.30).
- **scripts/setup/install-wazuh.sh** — script dựng Wazuh all-in-one Docker trên máy SIEM.
- **scripts/setup/install-agent.sh** — script cài Wazuh agent trên Victim, trỏ về manager.
- **scripts/attacks/** — 3 kịch bản sinh alert: ssh-bruteforce, web-attack, fim-trigger.
- **ai_module/** — stub pipeline AI đầy đủ: reader → extractor → rag → llm → main. Chưa chạy thật (implement GĐ3).
- **ai_module/config.example.yaml** — config mẫu (Wazuh API, Ollama, trường trích xuất, RAG).
- **ai_module/requirements.txt** — dependencies Python (requests, pyyaml, chromadb, ollama).
- **eval/samples/** — 2 alert mẫu JSON (SSH brute-force, FIM modified) cho `--demo`.
- **docs/network.md** — hướng dẫn mạng VMware: bảng IP, cấu hình VMnet, kiểm tra thông mạng.
- **docs/setup.md** — hướng dẫn dựng lab 8 bước từ đầu đến chạy AI module.
- **docs/attacks.md** — bảng kịch bản sinh alert + rule Wazuh dự kiến.
- **.gitignore** — loại config chứa secret, __pycache__, vector DB, model GGUF.
- **LICENSE** — MIT © 2026 Dinh Tuan Duong.
