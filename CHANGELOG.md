# Changelog

Ghi nhận mọi thay đổi quan trọng của repo. Format: [Keep a Changelog](https://keepachangelog.com/).

---

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

---

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
