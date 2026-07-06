# local-ai-siem-analyzer

> Mô-đun **AI local** đọc alert từ **Wazuh SIEM** và giải thích thành **ngôn ngữ tự nhiên**: tóm tắt cảnh báo, giải thích nguyên nhân kích hoạt rule, đánh giá mức nghiêm trọng, gợi ý bước kiểm tra/xử lý.

Đề tài thực tập DDC24. Trọng tâm là **chất lượng AI diễn giải log**, không xây SIEM mới. Repo này là **nguồn thông tin duy nhất (single source of truth)** cho toàn bộ lab — mọi cấu hình, script, tài liệu đều nằm ở đây và chạy lại được.

---

## 1. Kiến trúc

```
                    ┌─────────────────────────────┐
                    │   MÁY THẬT (Windows host)    │
                    │   Ollama + ai_module (Python)│  native, full CPU/RAM/GPU
                    │   Host-only IP: 192.168.100.1│
                    └──────────────┬──────────────┘
                                   │ đọc alert qua API https://192.168.100.10:55000
        ┌──────────────────────────┼──────────────────────────┐
        │        Host-only VMnet1 — 192.168.100.0/24           │
   ┌────▼─────┐            ┌───────▼────────┐         ┌────────▼────────┐
   │ ATTACKER │  tấn công  │  VICTIM        │ gửi log │  SIEM           │
   │ Kali .30 │──────────► │  Ubuntu .20    │────────►│  Wazuh .10      │
   │ no agent │            │  + agent       │  agent  │  Docker AIO     │
   └──────────┘            └────────────────┘          └─────────────────┘
        (mỗi VM còn 1 card NAT riêng để ra internet)
```

**Luồng:** Kali `.30` tấn công → Victim `.20` sinh log → Wazuh agent đẩy về SIEM `.10` → `ai_module` trên host đọc alert qua API → LLM local giải thích.

---

## 2. Cấu hình đã chốt

| Hạng mục | Giá trị |
|---|---|
| Ảo hóa | VMware Workstation trực tiếp |
| Máy thật | i5 gen12, RTX 3050 4GB VRAM, 32GB RAM |
| Mạng | 2 card/VM: NAT (internet) + Host-only (`192.168.100.0/24`) |
| SIEM | Ubuntu Server no-GUI, Wazuh Docker all-in-one, `.10` |
| Victim chính | Ubuntu Server no-GUI + agent, `.20` |
| Victim phụ | Windows + Sysmon (bổ sung sau), `.40` |
| Attacker | Kali (không cài agent), `.30` |
| LLM | `qwen2.5:3b` (chính) + `qwen2.5:7b` (so sánh) |
| AI module | Python, chạy native trên host |

Bảng IP đầy đủ: xem [`docs/network.md`](docs/network.md).

---

## 3. Quickstart

> Yêu cầu: VMware Workstation, 3 VM đã cài OS, Docker trên máy SIEM, Ollama trên host.

```bash
# --- Trên máy SIEM (.10) ---
cd infra/wazuh-docker
sudo bash ../../scripts/setup/install-wazuh.sh      # dựng Wazuh all-in-one (Docker)

# --- Trên máy Victim (.20) ---
sudo bash scripts/setup/install-agent.sh 192.168.100.10   # cài agent, trỏ về SIEM

# --- Trên máy thật (host) ---
ollama pull qwen2.5:3b && ollama pull qwen2.5:7b
cd ai_module && pip install -r requirements.txt
cp config.example.yaml config.yaml                  # điền IP + API key Wazuh
python main.py --demo                                # chạy thử với alert mẫu

# --- Sinh cảnh báo (từ Kali .30) ---
bash scripts/attacks/ssh-bruteforce.sh 192.168.100.20
```

Chi tiết từng bước: [`docs/setup.md`](docs/setup.md).

---

## 4. Cấu trúc thư mục

```
local-ai-siem-analyzer/
├─ README.md                 # file này — điểm khởi đầu
├─ KE_HOACH.md               # kế hoạch tổng thể 4 giai đoạn
├─ infra/
│  ├─ wazuh-docker/          # docker-compose Wazuh all-in-one
│  └─ netplan/               # config mạng mẫu cho từng VM
├─ scripts/
│  ├─ setup/                 # install-wazuh.sh, install-agent.sh
│  └─ attacks/               # kịch bản sinh alert (ssh brute, web, fim)
├─ ai_module/                # LÕI — mô-đun AI Python
│  ├─ reader.py              # đọc alert (tail json / API)
│  ├─ extractor.py           # trích ~10 trường chính
│  ├─ rag.py                 # RAG rule Wazuh + MITRE
│  ├─ llm.py                 # gọi Ollama, ép JSON schema
│  ├─ main.py                # entrypoint
│  ├─ config.example.yaml
│  └─ requirements.txt
├─ eval/                     # 30-50 alert mẫu + bảng chấm điểm
├─ docs/                     # setup.md, network.md, attacks.md
└─ prompts/                  # (thư mục cha) log prompt quá trình làm
```

---

## 5. Roadmap (4 giai đoạn)

1. **Dựng lab SIEM** — 3 VM, mạng, Wazuh Docker, agent Active, bật thu log.
2. **Sinh cảnh báo** — SSH brute-force, web attack (DVWA), FIM. Map sẵn rule ID.
3. **Mô-đun AI (lõi)** — Ollama, trích trường chính, RAG, ép JSON schema `{summary, root_cause, severity, mitre, next_steps}`.
4. **Đánh giá** — 30–50 alert, so tay vs AI, chấm 1–5, so `3b` vs `7b`.

Chi tiết: [`KE_HOACH.md`](KE_HOACH.md).

---

## 6. Nguyên tắc làm việc (harness)

- **Repo là source of truth.** Mọi thông tin lab bám repo này; không rải rác ngoài.
- **Chạy lại được (reproducible).** Ưu tiên script tự động hơn thao tác tay; có gì làm tay thì ghi vào `docs/`.
- **Lõi trước, mở rộng sau.** Ubuntu victim + AI module làm trước; Windows/Sysmon cắm sau.
- **Không ném raw JSON vào LLM.** Luôn trích trường chính → giảm token, tăng chính xác.

## License
MIT — © 2026 Dinh Tuan Duong. Xem [LICENSE](LICENSE).
