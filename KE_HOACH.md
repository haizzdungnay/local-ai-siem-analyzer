# Kế hoạch Lab — Đề tài DDC24: Mô-đun AI local phân tích alert Wazuh

> Mục tiêu: LLM local đọc alert Wazuh → giải thích ngôn ngữ tự nhiên (tóm tắt, nguyên nhân rule, mức nghiêm trọng, bước xử lý). Trọng tâm = chất lượng AI diễn giải, không xây SIEM mới.

---

## 1. Tổng quan cấu hình đã chốt

| Hạng mục | Chốt |
|---|---|
| Ảo hóa | VMware Workstation trực tiếp |
| Máy thật | i5 gen12, RTX 3050 4GB VRAM, 32GB RAM |
| Mạng | 2 card mỗi VM: NAT (internet) + Host-only (lab) |
| Dải lab | `192.168.100.0/24` |
| SIEM | Ubuntu Server no-GUI, Wazuh Docker all-in-one, IP `.10` |
| Victim chính | Ubuntu Server no-GUI + agent, IP `.20` |
| Victim phụ | Windows + Sysmon (bổ sung sau) |
| Attacker | Kali (không cài agent), IP `.30` |
| LLM | `qwen2.5:3b` (chính) + `qwen2.5:7b` (so sánh) |
| AI module | Python, chạy native trên host |

---

## 2. Sơ đồ hệ thống

```
                    ┌─────────────────────────────┐
                    │   MÁY THẬT (Windows host)    │
                    │   Ollama + AI module Python  │  native, full CPU/RAM/GPU
                    │   Host-only IP: .1           │
                    └──────────────┬──────────────┘
                                   │ gọi API https://192.168.100.10:55000
        ┌──────────────────────────┼──────────────────────────┐
        │        Host-only VMnet1 — 192.168.100.0/24           │
   ┌────▼─────┐            ┌───────▼────────┐         ┌────────▼────────┐
   │ ATTACKER │  tấn công  │  VICTIM        │ gửi log │  SIEM           │
   │ Kali .30 │──────────► │  Ubuntu .20    │────────►│  Wazuh .10      │
   │ no agent │            │  + agent       │  agent  │  Docker AIO     │
   └──────────┘            └────────────────┘          └─────────────────┘
        (mỗi VM còn 1 card NAT riêng để ra internet)
```

Luồng: Kali `.30` đánh → Victim `.20` sinh log → agent đẩy về SIEM `.10` → AI trên host `.1` đọc alert qua API.

---

## 3. Bảng IP + phân bổ RAM

| Máy | Host-only IP | NAT | RAM | Vai trò |
|---|---|---|---|---|
| Host (máy thật) | 192.168.100.1 | — | (32GB tổng) | Ollama + AI module |
| SIEM Wazuh | 192.168.100.10 | DHCP | 6 GB | Nhận log, sinh alert |
| Victim Ubuntu | 192.168.100.20 | DHCP | 2 GB | Bị đánh, đẩy log |
| Attacker Kali | 192.168.100.30 | DHCP | 2–3 GB | Sinh tấn công |
| Victim Windows (sau) | 192.168.100.40 | DHCP | 4 GB | Log Sysmon (mở rộng) |

Ước tính khi chạy: model 3b + 3 VM ≈ 18–20GB → thoải mái. 7b + Windows → sát trần, tắt bớt Kali.

---

## 4. Cấu hình mạng VMware

1. Edit → Virtual Network Editor.
2. **VMnet1 (Host-only)**: tắt "Use local DHCP service" (để tự đặt IP tĩnh không bị đá). Subnet `192.168.100.0/24`.
3. **VMnet8 (NAT)**: giữ mặc định (có internet).
4. Mỗi VM: Settings → thêm 2 Network Adapter: 1 NAT, 1 Host-only (VMnet1).

### Netplan — máy SIEM (`.10`)
```yaml
# /etc/netplan/01-lab.yaml
network:
  version: 2
  ethernets:
    ens33:                       # card NAT — internet
      dhcp4: yes
    ens34:                       # card Host-only — lab
      dhcp4: no
      addresses: [192.168.100.10/24]
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```
`sudo netplan apply`. Victim `.20` làm y hệt, đổi địa chỉ.

> Lưu ý: default route để card NAT tự lo (dhcp4: yes). Host-only KHÔNG đặt gateway → tránh 2 default route đá nhau.

### Kali (`.30`)
GUI Network → Manual: IP `192.168.100.30/24` cho card Host-only; card NAT để DHCP.

### Kiểm tra thông mạng (theo thứ tự)
1. Victim: `ping 192.168.100.10` (tới SIEM)
2. Attacker: `ping 192.168.100.20` (tới Victim)
3. Host (CMD): `ping 192.168.100.10`
4. Host: mở `https://192.168.100.10:55000` → Wazuh trả về = OK
5. Mọi VM: `ping 8.8.8.8` (internet qua NAT)

---

## 5. Roadmap 4 giai đoạn

### GĐ1 — Dựng lab SIEM
- Cài 3 VM, set mạng như trên.
- SIEM: cài Docker → Wazuh all-in-one (`git clone wazuh-docker`, `docker compose up`).
- Victim: cài Wazuh agent, trỏ manager `192.168.100.10`.
- Xác nhận agent "Active" trên Wazuh Dashboard.
- Bật thu log: SSH/auth (`/var/log/auth.log`), Apache, FIM (`/etc`).

### GĐ2 — Sinh cảnh báo (map sẵn rule ID)
| Kịch bản | Công cụ | Rule Wazuh dự kiến |
|---|---|---|
| SSH brute-force | `hydra` từ Kali | 5710 / 5712 (multiple auth fail) |
| Web attack | `nikto`, `sqlmap` lên DVWA | 31xxx (web) |
| Sửa file quan trọng | edit `/etc/passwd`... | 550 / 554 (FIM) |
| Recon | `nmap` | tuỳ rule mạng |

### GĐ3 — Mô-đun AI local (LÕI)
- Ollama trên host: `ollama pull qwen2.5:3b` + `qwen2.5:7b`.
- Đọc alert: tail `alerts.json` HOẶC query API/OpenSearch.
- **Trích ~10 trường chính** (rule.id, level, description, srcip, agent, MITRE...) — KHÔNG ném raw JSON.
- RAG: index mô tả rule Wazuh (`ruleset/rules/*.xml`) + bảng MITRE bằng embedding local (nomic-embed-text) + ChromaDB/FAISS.
- Ép output JSON schema: `{summary, root_cause, severity, mitre, next_steps[]}`.

### GĐ4 — Đánh giá
- Chọn 30–50 alert mẫu.
- So thời gian phân tích tay vs có AI.
- Chấm chất lượng giải thích thang 1–5 (đúng nguyên nhân? gợi ý hữu ích?).
- So sánh `3b` vs `7b`: chất lượng + tốc độ → 1 mục thực nghiệm trong báo cáo.

### Mở rộng (nếu dư thời gian)
- Thêm Windows victim + Sysmon (`.40`).
- Nút "Explain" trên dashboard nhỏ.

---

## 6. Cấu trúc thư mục code (đề xuất)

```
ddc24-ai-siem/
├─ ai_module/
│  ├─ reader.py        # đọc alert (tail json / API)
│  ├─ extractor.py     # trích ~10 trường chính
│  ├─ rag.py           # ChromaDB + embedding rule/MITRE
│  ├─ llm.py           # gọi Ollama, ép JSON schema
│  └─ main.py
├─ rag_data/           # rule descriptions, MITRE table
├─ eval/               # 30-50 alert mẫu + bảng chấm điểm
└─ README.md
```

---

*Ghi chú: Ubuntu victim là lõi làm trước. Windows là nhánh cắm sau khi mô-đun AI chạy ổn.*
