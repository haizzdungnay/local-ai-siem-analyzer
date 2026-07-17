# Changelog

Ghi nhận mọi thay đổi quan trọng của repo. Format: [Keep a Changelog](https://keepachangelog.com/).

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
