# Changelog

Ghi nhận mọi thay đổi quan trọng của repo. Format: [Keep a Changelog](https://keepachangelog.com/).

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
