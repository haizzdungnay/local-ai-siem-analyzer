# local-ai-siem-analyzer

> Mô-đun **AI local** đọc alert từ **Wazuh SIEM** và giải thích thành **ngôn ngữ tự nhiên**: tóm tắt cảnh báo, giải thích nguyên nhân kích hoạt rule, đánh giá mức nghiêm trọng, gợi ý bước kiểm tra/xử lý.

Đề tài thực tập Local AI Module for Analyzing and Interpreting SIEM Security Alerts. Trọng tâm là **chất lượng AI diễn giải log**, không xây SIEM mới. Repo chứa tài liệu/scrip demo đã sanitize; config live và credential phải ở `ai_module/config.yaml` gitignored hoặc secret manager. Xem [`docs/security-governance.md`](docs/security-governance.md).

---

## 1. Kiến trúc

```
                    ┌─────────────────────────────┐
                    │   MÁY THẬT (Windows host)    │
                    │   Ollama + ai_module (Python)│  native, full CPU/RAM/GPU
                    │   Host-only IP: 192.168.100.1│
                    └──────────────┬──────────────┘
                                   │ đọc alert qua Indexer https://192.168.100.10:9200
        ┌──────────────────────────┼──────────────────────────┐
        │        Host-only VMnet1 — 192.168.100.0/24           │
   ┌────▼─────┐            ┌───────▼────────┐         ┌────────▼────────┐
   │ ATTACKER │  tấn công  │  VICTIM        │ gửi log │  SIEM           │
   │ Kali .30 │──────────► │  Ubuntu .20    │────────►│  Wazuh .10      │
   │ no agent │            │  + agent       │  agent  │  Docker AIO     │
   └──────────┘            └────────────────┘          └─────────────────┘
        (mỗi VM còn 1 card NAT riêng để ra internet)
```

**Luồng:** Kali `.30` tấn công → Victim `.20` sinh log → Wazuh agent đẩy về SIEM `.10` → `ai_module` trên host đọc alert từ Wazuh Indexer `:9200` → LLM local giải thích. Manager API `:55000` chỉ dùng cho tác vụ quản trị, không lưu alert.

---

## 2. Cấu hình đã chốt

| Hạng mục | Giá trị |
|---|---|
| Ảo hóa | VMware Workstation trực tiếp |
| Máy thật | i5 gen12, RTX 3050 4GB VRAM, 32GB RAM |
| Mạng | 2 card/VM: NAT (internet) + Host-only (`192.168.100.0/24`) |
| SIEM | Ubuntu Server no-GUI, Wazuh Docker all-in-one, `.10` |
| Victim chính | Ubuntu Server no-GUI + agent, `.20` |
| Victim phụ | Windows + Wazuh agent đã Active, Sysmon bổ sung sau, `.40` |
| Attacker | Kali (không cài agent), `.30` |
| LLM | `qwen2.5:3b` (demo nhẹ) + `qwen2.5:7b` (baseline GĐ4) |
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
ollama pull nomic-embed-text                         # embedding cho RAG
pip install -r ai_module/requirements.txt
cp ai_module/config.example.yaml ai_module/config.yaml  # điền credential Indexer
python ai_module/main.py --demo                         # lần đầu tự index dữ liệu RAG
python ai_module/dashboard.py                           # http://127.0.0.1:8765

# --- Sinh cảnh báo (từ Kali .30) ---
bash scripts/attacks/ssh-bruteforce.sh 192.168.100.20
```

Chi tiết dựng lab: [`docs/setup.md`](docs/setup.md). Runbook kiểm thử thủ công toàn hệ thống, chia rõ từng máy/lệnh/kết quả: [`docs/manual-test.md`](docs/manual-test.md).

### Kiểm tra code

```bash
pip install -r ai_module/requirements-dev.txt
python -m pytest tests -q
python scripts/check_tracked_secrets.py
python scripts/audit_dependencies.py --requirements ai_module/requirements-dev.txt --allowlist ai_module/pip-audit-allowlist.json
```

Test dùng mock cho Ollama, ChromaDB và Wazuh nên không cần bật lab SIEM.

### Dashboard AI local

`python ai_module/dashboard.py` mở `http://127.0.0.1:8765`. App chỉ phục vụ trên máy chính, đọc alert từ Indexer `:9200`, không proxy credential xuống browser. Chức năng MVP:

- Preset `5m/15m/30m/1h/2h/6h/12h/24h` hoặc custom range tối đa 24 giờ.
- Chọn model, ngôn ngữ AI `Tiếng Việt/English` và giao diện `Tối/Sáng`; ngôn ngữ yêu cầu, ngôn ngữ phản hồi và mức tuân thủ đều được ghi cùng kết quả.
- System prompt SOC được version hóa (`soc-contract-v1`), tách fact/inference/uncertainty/limitation và gọi Ollama với `temperature=0`, `seed=42` để dễ audit/reproduce.
- Theo dõi phase thật `queued → fetching_alerts → preparing_analysis → calling_ollama → saving_result`; không chèn delay/loading giả.
- Timeline mật độ alert theo thời gian; chọn bucket để lọc hoặc tạo batch con drill-down.
- Dưới detail cap: deterministic grouping, alert reference và alert-detail DTO đã redact (không trả raw `_source`). Vượt cap: tự chuyển aggregate-only từ count/histogram/rule code, không tải full log hàng loạt; unique cardinality được ghi rõ là xấp xỉ.
- Dashboard retrieval dùng RAG theo rule group đã sanitize, có relevance threshold, corpus/index provenance và trạng thái effective (`not_initialized`, `ready`, `unavailable`, `disabled`); không có context phù hợp sẽ được ghi rõ thay vì giả RAG success.
- Mỗi job có **Xuất JSON v2** gồm analysis, SOC trace, metrics/timeline, alert references và provenance Ollama; có nút JSON v1 cho consumer cũ khi endpoint hỗ trợ. Kết quả cũ thiếu evidence được ghi `unknown_legacy`.
- Panel **Dấu vết phân tích SOC** chỉ trình bày fact, inference, uncertainty và limitation có thể kiểm toán; không hiển thị chain-of-thought/suy luận nội bộ model.
- Một fixed-window schedule, ingest delay và bounded catch-up; SQLite giữ job/watermark tại `ai_module/dashboard_data/` (gitignored).
- Analyst UX local: lọc/pivot lịch sử, case-lite review (status/severity/tags/note), dependency/queue/database health và retention prune có xác nhận rõ.

Tham khảo có chủ đích từ [Wazuh Dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/index.html), [Security Onion Alerts](https://docs.securityonion.net/en/2.4/alerts.html), [Security Onion Cases](https://docs.securityonion.net/en/2.4/cases.html) và [OpenSearch Security Analytics](https://docs.opensearch.org/latest/security-analytics/). Scope này không triển khai multi-user RBAC, PCAP pipeline, notification bên ngoài, auto-remediation hay enterprise correlation graph.

AI output chỉ là tư vấn. App không tự chặn IP, chạy lệnh hay sửa Wazuh. Chi tiết vận hành/test: [`docs/manual-test.md`](docs/manual-test.md).
Kế hoạch hardening/evaluation còn lại: [`docs/improvement-plan.md`](docs/improvement-plan.md).

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
│  ├─ reader.py              # đọc alert/range/aggregate từ Wazuh Indexer
│  ├─ analysis_service.py    # gom nhóm và điều phối phân tích AI
│  ├─ dashboard.py           # API + production WSGI loopback
│  ├─ dashboard_store.py     # SQLite job/review/audit state
│  ├─ dashboard_worker.py    # worker và fixed-window scheduler
│  ├─ web/                   # dashboard HTML/CSS/JS thuần
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
4. **Đánh giá** — 33 alert `sanitized-live` gồm SSH/FIM/web/benign/ambiguous, ground truth đã review kỹ thuật, rubric 1–5 và baseline `qwen2.5:7b` RAG/no-RAG; còn human review và đo thời gian phân tích tay.

Chi tiết: [`KE_HOACH.md`](KE_HOACH.md), [`eval/README.md`](eval/README.md).

---

## 6. Nguyên tắc làm việc (harness)

- **Repo là source of truth.** Mọi thông tin lab bám repo này; không rải rác ngoài.
- **Chạy lại được (reproducible).** Ưu tiên script tự động hơn thao tác tay; có gì làm tay thì ghi vào `docs/`.
- **Lõi trước, mở rộng sau.** Ubuntu victim + AI module là lõi; Windows agent `.40` đã Active, Sysmon cắm sau.
- **Không ném raw JSON vào LLM.** Luôn trích trường chính → giảm token, tăng chính xác.

## License
MIT — © 2026 Dinh Tuan Duong. Xem [LICENSE](LICENSE).
