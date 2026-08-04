# Handoff — local-ai-siem-analyzer

Ngày cập nhật: 2026-08-05
Branch release: `codex/complete-local-ai-siem`
Commit nền của branch: `a578c7c` (8 commit trước `origin/main` tại đầu phiên).
Continuity: đã thêm `CLAUDE.md` và `.githooks/pre-commit`; mỗi clone cần chạy `git config core.hooksPath .githooks` để bật ledger gate.
`eval/run_eval.py` tồn tại trong checkout; path case đã resolve theo repo root, không phụ thuộc CWD.

## Trạng thái release hiện tại

- Phạm vi localhost SOC đã hoàn tất theo `docs/product-roadmap.md`: Wazuh Indexer window/aggregate, Ollama VI/EN, evidence trace công khai, job lifecycle/schedule, JSON report v2/v1, analyst review case-lite, history filter/pivot, health và retention. Không triển khai auto-remediation, remote multi-user, PCAP hay notification trong release này.
- Báo cáo AI có phase thật và provenance để phân biệt `ollama_model`, `local_fallback`, empty window và `unknown_legacy`; không có loading giả. Audit gồm response/model/prompt/input/schema hash, deterministic options, language compliance, latency/token và model digest advisory có nguồn/thời điểm quan sát.
- SQLite schema v4 giữ migration v1/v2/v3, append-only review history và data minimization. `sample_log` chỉ dùng trong memory prompt, không ghi DB/export; exact echo của model bị redaction trước persistence, job chuyển `partial` và report có warning.
- Runtime dùng Waitress hard-bind `127.0.0.1`; Ollama loopback là mặc định, remote chỉ khi `allow_remote: true` với HTTPS. Read connection SQLite được đóng tường minh để không khóa DB trên Windows.
- Frontend có loading theo `queued/fetching_alerts/preparing_analysis/calling_ollama/saving_result`, freshness, quick pivot rule/agent/source IP, review history, dependency badges và retention confirmation. JSON v2 là mặc định; JSON v1 chỉ dành cho consumer cũ.
- Automated release gates PASS: toàn bộ `89 passed`, compileall, `node --check`, Git Bash syntax cho 3 attack scripts + pre-commit hook, workflow YAML và `git diff --check`. Waitress loopback HTTP smoke PASS trên temp DB; lần đầu phát hiện/đã sửa SQLite handle leak. Không chạy lại manual lab traffic hoặc Nikto theo yêu cầu user.
- Evidence live cũ vẫn hợp lệ cho đường dữ liệu: job `#22` VI và `#23` EN cùng historical aggregate 12.781 alert đều có Qwen `ollama_model`, compliance `full` và latency khoảng 9-10 giây. Không dùng evidence này để khẳng định semantic accuracy; human review vẫn cần cho nội dung SOC.
- Dashboard PID `39752` hiện vẫn listen `127.0.0.1:8765` từ process trước release; không dùng process này làm release acceptance và không tự sửa/xóa live DB trong lượt automated-only. Sau merge cần restart đúng process khi queue rỗng để nạp Waitress/schema v4.
- Release workflow: push branch, tạo PR vào `main`, chờ toàn bộ GitHub checks xanh rồi merge; không merge khi CI pending/fail.

## Lịch sử phiên trước (archived đến 2026-08-04)

- Task `SOC prompt + VI/EN + report v2` hoàn tất 2026-08-04: `ai_module/llm.py` dùng contract version `soc-contract-v1`, prompt hệ thống Việt/Anh, untrusted-data boundary và nhắc language ở cuối request; Ollama options cố định `temperature=0`, `seed=42`. Alert/eval vẫn đúng 5 field legacy; dashboard window bắt buộc `response_language`, confidence phần trăm `0-100` và public `assessment_basis` gồm fact/inference/uncertainty/limitation. Đây là audit trace công khai, không phải chain-of-thought/ngôn ngữ suy luận nội bộ.
- JSON export hiện mặc định `local-ai-siem-report/v2` với model/prompt/language audit, analysis + SHA-256, trace, coverage/metrics/timeline/groups/alert references; `?schema=v1` giữ compatibility, schema lạ `422`. Không export `_source`, `full_log`, `sample_log`, prompt, raw response hoặc reasoning. Cross-review phát hiện legacy fallback từng lưu 200 ký tự preview; code mới không còn persist raw preview và cả v1/v2 scrub summary của `output_origin=local_fallback` cũ.
- Live acceptance sau restart current code PASS, không tạo traffic mới: job `#22` (`vi`) và `#23` (`en`) reuse historical aggregate 12.781 alerts, đều `succeeded`, `output_origin=ollama_model`, requested=response language, compliance `full`, confidence `95`, trace counts `3/2/1/1`, options `temperature=0, seed=42` và ba hash prompt/response/analysis đều 64 ký tự. Latency 9.277s/10.001s, prompt/output tokens 1.808/540 và 1.787/581. Job `#13` vẫn export `unknown_legacy`; `#18/#19` là expected audit evidence cho pre-fix invalid/mismatched output và giữ `partial`, không được dùng làm report semantic.
- Final automated verification: compileall PASS, toàn bộ `74 passed`, `node --check` PASS, Git Bash syntax PASS cho 3 attack scripts + pre-commit hook, `git diff --check` PASS (chỉ warning LF/CRLF). `main.py --help` và `eval/run_eval.py --help` đều PASS trên Windows; eval runner mới không ghi đè baseline nếu thiếu `--overwrite`. Dashboard current code được chủ ý giữ chạy PID `39752` tại `http://127.0.0.1:8765`; app/worker/scheduler running, RAG dashboard disabled.
- Task `Qwen loading/provenance + JSON export` hoàn tất 2026-08-04: audit xác nhận report dashboard được tạo qua `ollama.Client.chat`, không có report generator giả ở frontend; nguyên nhân gây nghi ngờ là UI không tự mở job mới, chỉ hiện `pending/running` chung và report lịch sử đã persist xuất hiện tức thì. SQLite schema v3 giờ lưu phase `queued/fetching_alerts/preparing_analysis/calling_ollama/saving_result/completed`, provenance Ollama, output origin và response hash; UI có spinner theo phase thật, model/latency/token/hash evidence và nút **Xuất JSON**. Không chèn artificial delay. Credential chung của tất cả VM lab vẫn là `kali`.
- JSON export contract hoàn tất: `GET /api/jobs/<id>/export` tải `wazuh-ai-job-<id>.json` schema `local-ai-siem-report/v1` gồm job/model call/analysis/hash/coverage/warnings/metrics/timeline/groups/alert references; loại raw `_source`, `full_log` và `sample_log`. New valid response ghi `ollama_model`, invalid response dùng app fallback ghi `local_fallback`, historical result không có provenance ghi `unknown_legacy`; audit metadata không phải chữ ký mật mã hoặc human ground truth.
- Live provenance acceptance PASS: restart old dashboard PID 39756 sang current code PID 39456 tại `http://127.0.0.1:8765`, app/worker/scheduler running, DB thật migrate v2→v3 và history giữ nguyên. Không rerun Nikto/traffic; job `#15` reuse window aggregate cũ, exact 12.781 alerts, trace `fetching_alerts → calling_ollama → completed`, requested/response model `qwen2.5:7b`, wall latency 13.815s, Ollama 1.810 prompt/366 output tokens, provider `ollama`, origin `ollama_model`, response/analysis SHA-256 đủ 64 ký tự; attachment 15.623 bytes HTTP 200. Job cũ `#13` export đúng `unknown_legacy`.
- Final verification cho provenance/export PASS: compileall, toàn bộ `62 passed`, JavaScript syntax, Git Bash syntax cho 3 attack scripts + pre-commit hook và `git diff --check`; chỉ warning LF/CRLF. `README.md` và `docs/manual-test.md` đã mô tả phase, provenance, JSON contract và giới hạn audit. Thay đổi vẫn ở worktree, chưa commit/push.
- Task `chạy dashboard theo runbook` hoàn tất 2026-08-04: app đang chạy PID 39756 tại `http://127.0.0.1:8765`; `/api/status` HTTP 200 báo `app=ok`, `worker=running`, `scheduler=running`, `rag=disabled`; `/api/jobs` HTTP 200 trả 14 history jobs. Chrome CDP đã load trang thật, health text và 14 dòng batch hiện, chọn job, đổi theme light, reload state; desktop document width 1409px/viewport 1424px, mobile viewport 390px/document 390px, không overflow; screenshot `/tmp` ngoài repo đã capture. Không tạo live job mới, không đổi code. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `mở dashboard cho user` hoàn tất: PID 33220 cũ không còn listen (đã chết sau lần trước); start lại `python ai_module/dashboard.py` bằng config gitignored hiện có, dashboard mới chạy PID 38960 tại `http://127.0.0.1:8765`, `/api/status`, `/api/jobs`, `/api/schedule` đều trả 200; đã mở URL này bằng browser mặc định cho user. Không có thay đổi code trong task này. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `final verification + ledger closeout` hoàn tất: compileall PASS, toàn bộ `59 passed`, JavaScript syntax PASS, Git Bash syntax PASS cho 3 attack scripts + pre-commit hook, `git diff --check` PASS; chỉ warning LF/CRLF. `plan.md` checklist alert timeline/scale/language/theme đã hoàn tất. Dashboard PID 33220 được chủ ý giữ chạy tại `http://127.0.0.1:8765` cho user review; credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Đang thực hiện task nhỏ `final verification + ledger closeout`: compileall, full pytest, JavaScript/Git Bash syntax, `git diff --check`, final API/status check; sau đó đánh dấu plan, cập nhật changelog trước handoff và giữ dashboard PID 33220 chạy cho user. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `timeline/theme live render` hoàn tất: dark/light desktop job `#13` đều 1440px/document 1425, 60 timeline bars/12 nonzero, aggregate mode, language VI và AI content visible. Keyboard Space chọn nonzero bucket PASS, reset/create-subjob controls hiện; theme light persisted qua reload. Light mobile viewport 390/document 375 không overflow. Temp Chrome PID 28124/port 9332 đã dừng; dashboard PID 33220 giữ chạy. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `timeline/theme live render`: dùng Chrome profile/port sạch để mở job `#13`, capture dark desktop timeline/AI, light desktop timeline/AI và light mobile; kiểm viewport/document width, 60 bars, mode/language, bucket click filter, theme persistence và create-subjob control (không bấm tạo trong render test). Credential chung của tất cả VM lab vẫn là `kali`.
- Task `live over-cap + Vietnamese acceptance` hoàn tất, không rerun Nikto: tạo job `#13` cho window cũ, `succeeded`, `language=vi`, `analysis_mode=aggregate`, exact 12.781 alerts, 0 alert refs, 12 groups, 60 timeline buckets. Timeline sum và group sum đều 12.781; coverage 12/12, represented 12.781, không truncated; warning nói aggregate-only không tải full log. AI trả tiếng Việt/severity high nhưng semantic vẫn advisory, không ghi live identifier/raw summary vào tracked ledger. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `live over-cap + Vietnamese acceptance`: tạo một manual job mới cho cửa sổ Nikto đã biết `08:10-08:20Z` với model allowlist và `language=vi`, poll terminal, xác minh exact total >2.000, aggregate mode/no refs, timeline/rule groups, warning coverage và phản hồi AI tiếng Việt. Không chạy lại Nikto. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `live schema-v2 restart` hoàn tất: verified/stopped old PID 14572, current code chạy PID 33220 tại `http://127.0.0.1:8765`, HTTP 200, app/worker/scheduler running. Existing DB migrated in place; check time có 12 jobs (không xóa/sửa user jobs), job `#8` vẫn succeeded với 362 refs, existing job columns default `language=en`, `analysis_mode=full`, timeline empty để frontend fallback từ refs. New HTML controls đều served. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `live schema-v2 restart`: resolve/verify exact dashboard PID on port 8765, stop only that process, start current code with existing gitignored config, then verify HTTP/status/schema/history persistence. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `aggregate/timeline/language/theme docs` hoàn tất: README, setup, manual-test, config example và `KE_HOACH.md` mô tả detail cap vs aggregate-only, timeline filter/create-subjob, `vi/en`, persisted light/dark và acceptance không bulk raw log. Historical `#7` được ghi rõ là finding trước fallback, không còn là behavior mong đợi mới. Credential chung của tất cả VM lab vẫn là `kali` và vẫn có ở đầu runbook.
- Đang thực hiện task nhỏ `docs + live migration/over-cap acceptance`: cập nhật runbook/config mô tả detail cap và aggregate-only, restart dashboard để schema v2 migrate DB thật, xác minh status/history, tạo over-cap job bằng cửa sổ Nikto cũ và chọn language Việt; sau đó CDP render dark/light 1440/390. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Task `frontend timeline + preferences` implementation hoàn tất: HTML/JS/CSS có alert histogram accessible, bucket filter/reset/create-subjob, aggregate/full mode badge và KPI metrics, `vi/en` selects cho manual/schedule, persisted `dark/light` selector. Window `key_findings` hiện được trình bày ở ô phát hiện chính thay vì fallback root cause rỗng. Dark/light palette regression và targeted dashboard suite `33 passed`; JS syntax PASS. Chưa restart/render live trong task này. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Đang thực hiện task nhỏ `frontend timeline + preferences`: thêm histogram alert accessible, bucket filter/create-subjob, mode/coverage indicator, manual/schedule language selects và persisted light/dark selector; bổ sung UI regression rồi render. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Task `backend aggregate fallback + schema v2` hoàn tất: `fetch_alerts_window()` query exact total + timeline/rules/cardinality rồi chỉ tải detail khi `total <= max_alerts_per_job`; over-cap normalized thành groups không có `sample_log`/alert refs. Schema v2 migration thêm job `language/analysis_mode/metrics/timeline` và schedule language; worker/LLM hỗ trợ `vi/en`; job-list metrics dùng aggregate totals. Core/store/API targeted `29 passed`, compile PASS. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Đang thực hiện task nhỏ `backend aggregate fallback + schema v2`: implement reader count/aggregation branch, timeline/metrics normalization, SQLite migration, job/schedule language và worker/LLM wiring; sau đó chạy targeted core/store/API tests. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Task `alert timeline + scale/language/theme architecture audit` hoàn tất và `plan.md` đã mở section/checklist mới. Contract đã chốt: dưới cap dùng full alert references; trên cap dùng aggregate-only exact total + date histogram + cardinality + rule buckets/top-hit field allowlist, không bulk `_source/full_log`; bucket timeline có filter/tạo batch con; `vi/en` lưu theo job/schedule; `dark/light` lưu browser-side. Live acceptance sẽ retry window Nikto cũ `#7` (>2.000) sau migration. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Đang thực hiện task nhỏ `alert timeline + scale/language/theme architecture audit`: đối chiếu reader, worker, SQLite schema, LLM prompt và UI để chốt contract mở rộng không lưu raw log. Hướng dự kiến: full-detail dưới cap; aggregate-by-rule/agent/level/time bucket khi vượt cap; timeline click-to-filter; AI `vi/en`; theme `light/dark`. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Task `verification cleanup + handoff` hoàn tất: Chrome/CDP tạm PID 25332/port 9331 đã dừng; dashboard vẫn chạy PID 14572 tại `http://127.0.0.1:8765`, root HTTP 200, app/worker/scheduler `running`, RAG dashboard `disabled`. Schedule disabled/idle. API hiện trả 9 jobs; latest `#9` là manual empty window succeeded (0 alert/no AI), còn DVWA evidence `#4-#8` giữ nguyên. Final `git diff --check` sau ledger PASS, chỉ warning LF/CRLF. Credential chung của tất cả VM lab vẫn là `kali` và phải giữ trong mọi handoff/runbook.
- Đang thực hiện task nhỏ `verification cleanup + handoff`: dừng Chrome/CDP tạm ở port 9331, kiểm tra dashboard vẫn HTTP 200/worker/scheduler running trên `http://127.0.0.1:8765`, cập nhật PID/trạng thái cuối. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `UX full verification` hoàn tất: compileall PASS, toàn bộ `52 passed`, JavaScript syntax PASS, Git Bash syntax PASS cho 3 attack scripts + pre-commit hook, `git diff --check` PASS; chỉ có warning LF/CRLF. Toàn bộ checklist `UX batch log + AI review` trong `plan.md` đã đánh dấu xong. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `UX full verification`: chạy compileall, toàn bộ pytest, JavaScript syntax, Git Bash syntax cho attack scripts/hook và `git diff --check`; sau đó cập nhật checklist/ledger và dừng Chrome tạm nhưng giữ dashboard live cho user. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `live row-to-AI mapping verification` hoàn tất: Chrome/CDP chọn `#4` click, `#5` Enter, `#6` Space, `#7` click, `#8` Enter; mỗi lần có đúng một selected row và title khớp. `#4` succeeded/no-AI empty state; `#5/#6` succeeded/low với content; `#7` failed/empty state; `#8` succeeded/high với 4 next steps. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `live row-to-AI mapping verification`: dùng Chrome/CDP chọn batch `#4-#8` bằng click, Enter và Space; đối chiếu selected row, job title, empty/failed state và AI severity/content tương ứng. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `mobile table containment fix` hoàn tất: `.grid > .card { min-width: 0; }` giữ bảng 780px trong scroll container, static regression mới bảo vệ containment/overflow. `tests/test_dashboard_ui.py`: `3 passed`; JS syntax PASS. Fresh 1440px desktop và 390px mobile render PASS; mobile `documentWidth=375` trong viewport 390, table scroll nội bộ `311/780`, header/panel AI không còn bị cắt. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `mobile table containment fix`: thêm shrink boundary cho grid/card chứa bảng, bổ sung static UI regression, chạy targeted tests và recapture 390px. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `fresh desktop/mobile capture` hoàn tất với finding: desktop 1440x1000 PASS về render (8 dòng, 8 cột, selected `#8`, panel AI `high`); viewport mobile thật 390x900 làm document rộng 830px vì batch table/grid containment, cắt ngang header và panel. `plan.md` đã thêm task sửa overflow; chưa tính mobile PASS. Hai attempt Node inline trước đó fail do PowerShell làm mất quote, nên harness CDP được đặt tạm ngoài repo rồi chạy thành công. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `fresh desktop/mobile capture`: kiểm tra worktree/process, bảo đảm dashboard live ở `127.0.0.1:8765`, rồi dùng hai Chrome profile/port riêng để tránh lẫn device metrics. Credential chung của tất cả VM lab vẫn là `kali`.
- Task `audit four existing render captures` hoàn tất: cả bốn ảnh đều đang ở layout mobile khoảng 390px dù tên desktop/mobile khác nhau. AI panel trong ảnh hiển thị đủ severity `high`, summary, fallback root cause, MITRE và 4 next steps; chưa tính desktop PASS. Tiếp theo phải capture lại desktop/mobile bằng Chrome profile/cổng sạch. Credential chung của tất cả VM lab vẫn là `kali`.
- Đang thực hiện task nhỏ `render + batch selection verification`: kiểm tra trực quan bảng SIEM/panel AI trên desktop và mobile, rồi xác minh chọn từng batch live `#4-#8`. Dashboard gần nhất được ghi nhận tại `http://127.0.0.1:8765`; chưa đánh dấu render PASS cho đến khi xác nhận viewport bằng phiên Chrome sạch. Credential chung của tất cả VM lab vẫn là `kali` theo chỉ định user.
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
- Task `DVWA scenario script + runbook` hoàn tất: `web-attack.sh` có mode `baseline/error-burst/signatures/nikto/all`, chỉ nhận Victim `.20`, cap burst 3–10, Nikto 45 giây và in UTC boundary; Git Bash syntax PASS, outside-target guard exit 2 PASS. `docs/manual-test.md` và `docs/attacks.md` đã có workflow AI per-mode; password VM lab `kali` đã document theo yêu cầu user.
- Task `DVWA live scenario audit` hoàn tất: Victim `/DVWA/` trả `302`, Apache active, Victim SSH, Kali SSH/curl/Nikto, Indexer `:9200` và Ollama (5 model) PASS; Indexer 5 phút trước test có 0 alert. Kali probe đầu fail do quoting zsh `unmatched \"`, retry command đơn giản PASS.
- Credential lab theo chỉ định user ngày 2026-07-31: tất cả máy ảo dùng mật khẩu chung `kali`; phải giữ ghi chú này trong các lần cập nhật `HANDOFF.md` và runbook. Đây là lab credential được user chủ ý yêu cầu document, không đưa vào corpus/output sanitize.
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
- SSH live ngày 2026-07-29: key login PASS trên SIEM `.10` (`siem`), Victim `.20` (`trnguyn-virtual-machine`), Kali `.30` (`kali`); không cần dùng password.
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
