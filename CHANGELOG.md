# Changelog

Ghi nhận mọi thay đổi quan trọng của repo. Format: [Keep a Changelog](https://keepachangelog.com/).

---
## [Unreleased]

### Added
- Test hồi quy cho pipeline AI và GitHub Actions chạy trên Linux/Windows.
- `CLAUDE.md` và `.githooks/pre-commit` ghi quy trình continuity, bắt buộc staged `CHANGELOG.md` và `HANDOFF.md` khi commit thay đổi repo.
- GĐ4: corpus alert `sanitized-live`, manifest, expected ground truth nháp, rubric chấm 1–5 và test kiểm tra cấu trúc/sanitization.
- Runner `eval/run_eval.py` tái dùng extractor, RAG và Ollama hiện có; ghi latency, schema validity, raw output và cột human score vào CSV.
- Baseline `qwen2.5:7b` cho cả RAG/no-RAG trên snapshot 30 case; kết quả thô lưu trong `eval/results*.csv`.
- Tài liệu `eval/README.md` và `eval/baseline.md` mô tả protocol model, phân tích tay và giới hạn kết quả.

### Changed
- README và `KE_HOACH.md` cập nhật trạng thái GĐ4, đường dẫn chạy eval và phần việc human review còn lại.
- Đồng bộ tài liệu lab: alert đọc từ Indexer `:9200`, Manager `:55000` chỉ quản trị; Windows agent `.40` đã Active; Bước 8/SSH và FIM marker realtime được ghi đúng vị trí.
- Thống nhất model demo nhẹ `qwen2.5:3b` với baseline GĐ4 `qwen2.5:7b`, cùng rule SSH thực tế `5503/5760/2502`.
- Dataset builder giảm dữ liệu nhận dạng lab, giữ provenance và tách input khỏi expected labels; vòng review kỹ thuật giảm duplicate, sửa `40112` thành ambiguous/high, bỏ forced MITRE trên benign/weak-evidence case và thêm benign rule `23502`.

### Fixed
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
- Commit local AI scoring/runbook: `a5f874b` trên `claude/lab-eval-checkpoint`; chưa push.

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
- **DVWA không kết nối được MySQL** — do password trong `config.inc.php` (`kali`) không khớp với password user MySQL đã tạo (`dvwa123`). Fix bằng `ALTER USER` đồng bộ lại password.

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
- **Alert không hiển thị trên Dashboard dù Manager đã xử lý đúng** (`alerts.json` có rule 5503 nhưng Indexer không nhận) — do Filebeat trong container Manager vẫn dùng password mặc định `SecretPassword` sau khi đổi password admin qua Dashboard UI, dẫn tới lỗi `401 Unauthorized` giữa Manager và Indexer. Fix bằng quy trình đổi password đồng bộ (xem docs/setup.md Bước 4.5).
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
