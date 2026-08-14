# BÁO CÁO SỐ LIỆU THỰC NGHIỆM — CHƯƠNG 4 (ĐÃ BỔ SUNG MÔ HÌNH ĐỐI CHỨNG)

> **Nhóm A07** — Đề tài: *Nghiên cứu và xây dựng mô-đun AI cục bộ hỗ trợ phân tích và giải thích cảnh báo an ninh trên hệ thống SIEM*  
> **Thời gian xuất số liệu:** 2026-08-06  
> **Nguồn dữ liệu:** Corpus 33 case `sanitized-live` (`eval/results.csv`, `eval/results-notmythos-8b.csv`, `eval/ai-judgments-notmythos-8b.csv`, `eval/ai-judgments-notmythos-8b-candidate.csv`)

---

## 0. THÔNG TIN MÔI TRƯỜNG (Chương 3)

### Bảng 3.1 & 3.2: Cấu hình phần cứng và phần mềm máy chủ AI

| Mục | Cần điền | Giá trị đo thực tế |
|---|---|---|
| CPU máy chủ AI | Tên đầy đủ | 12th Gen Intel(R) Core(TM) i7-12700 |
| RAM máy chủ AI | GB | 32 GB |
| GPU | Tên + VRAM | NVIDIA GeForce RTX 3070 Ti (8 GB VRAM) |
| Hệ điều hành máy chủ AI | OS | Windows 11 Pro (Version 10.0.26200) |
| Phiên bản VMware Workstation | Version | VMware Workstation Pro 17.x (hoặc Docker Desktop 29.1.3) |
| Phiên bản Docker Engine | Version | 29.1.3 |
| Phiên bản Docker Compose | Version | v2.40.3-desktop.1 |
| Phiên bản Ollama | Version | 0.6.2 |
| Phiên bản Python | Version | 3.12.7 |

### Bảng 1.10b & 1.10c: Mô hình LLM

| Chỉ số | Mô hình chính | Mô hình đối chứng |
|---|---|---|
| Tên model | `qwen2.5:7b` | `CyberCrew/notmythos-8b` |
| Số tham số | 7.61B (~7B) | 8.03B (~8B) |
| Mức lượng tử hóa | Q4_K_M | Q4_K_M (Q4) |
| Dung lượng file model | 4.7 GB | 2.0 GB |

### Bảng 3.5: Kho tri thức RAG

| Mục | Giá trị |
|---|---|
| Mô hình embedding đang dùng | `nomic-embed-text` (Ollama, 274 MB) |
| Cơ sở dữ liệu vector | ChromaDB (Persistent local) |
| Tổng số đoạn (chunk) đã đánh chỉ mục | 19 đoạn |
| Trong đó: từ tập luật Wazuh | 11 rules (`wazuh_rules.json`) |
| Trong đó: từ MITRE ATT&CK | 8 techniques (`mitre_techniques.json`) |
| Thời gian đánh chỉ mục toàn bộ | ~1.2 giây |
| Số đoạn truy xuất mỗi lần (top-k) | 3 |
| Ngưỡng tương đồng tối thiểu | Distance $\le 1.0$ (`relevance_threshold`) |

---

## 1. BỘ DỮ LIỆU ĐÁNH GIÁ (Mục 4.2)

| Mục | Giá trị |
|---|---|
| **Tổng số cảnh báo dùng để đánh giá** | 33 cảnh báo |
| Cách chọn mẫu | Mẫu thực tế từ lab đã làm sạch (`sanitized-live`) |
| Nguồn cảnh báo | Kịch bản diễn tập lab (SSH Brute-force, Web Attack, FIM, Syslog) |

### Phân bố theo loại kịch bản

| Kịch bản | Rule ID liên quan | Số cảnh báo |
|---|---|---|
| Dò mật khẩu SSH | 5503, 5710, 5712, 5760, 2502, 40112 | 12 |
| Tấn công web (nikto/sqlmap/XSS) | 31101, 31105, 31151 | 3 |
| Thay đổi file (FIM) | 553, 554 | 3 |
| Trinh sát mạng (nmap) | Nằm trong nhóm Web scan / SSH probe | 0 |
| Khác (Lành tính - Benign & Mơ hồ - Ambiguous) | 503, 506, 510, 5402, 5501, 5502, 5715, 23502 | 15 |
| **TỔNG** | | **33** |

---

## 2. KIỂM THỬ CHỨC NĂNG (Mục 4.3)

### Kiểm thử danh mục yêu cầu chức năng

| Mã | Yêu cầu chức năng | Kết quả | Ghi chú nếu không đạt |
|---|---|---|---|
| FR-01 | Đọc cảnh báo từ Indexer, không thao tác thủ công | **Đạt** | Chạy tự động qua `reader.py` / OpenSearch API |
| FR-02 | Trích xuất đúng tập trường đã cấu hình | **Đạt** | `extractor.py` lọc đúng 10 trường trong `config.yaml` |
| FR-03 | Truy xuất tri thức tham chiếu (mô tả luật, MITRE) | **Đạt** | `rag.py` truy xuất top-3 từ ChromaDB thành công |
| FR-04 | Sinh diễn giải đủ trường theo lược đồ | **Đạt** | `llm.py` ép đúng JSON schema |
| FR-05 | Xác thực đầu ra, dự phòng khi sai định dạng | **Đạt** | Validator chuyển giao về fallback khi sai enum |
| FR-06 | Đổi mô hình qua tham số cấu hình | **Đạt** | Đổi model qua `config.yaml` không cần sửa code |
| FR-07 | Chạy theo lô, tổng hợp kết quả | **Đạt** | Script `run_eval.py` xử lý lô 33 case |
| FR-08 | Ghi vết xử lý (băm, phiên bản, thời điểm) | **Đạt** | Lưu thông tin sha256 và timestamp vào log/CSV |

### Tỷ lệ đầu ra hợp lệ theo lược đồ JSON

| Mục | Mô hình chính (`qwen2.5:7b`) | Mô hình đối chứng (`CyberCrew/notmythos-8b`) |
|---|---|---|
| Tổng số lần gọi model | 33 | 33 |
| Số lần trả về JSON hợp lệ ngay | 32 | 33 |
| Số lần phải dùng kết quả dự phòng (fallback) | 1 | 0 |
| **Tỷ lệ hợp lệ (%)** | **97.0%** | **100.0%** |
| Lý do fallback thường gặp nhất | LLM trả `severity: "unknown"` ngoài enum tại case `benign-23502-01` | Không có (100% hợp lệ) |

---

## 3. CHẤT LƯỢNG DIỄN GIẢI (Mục 4.4)

### 3.1. Thang chấm điểm đã dùng

| Mục | Giá trị |
|---|---|
| Thang điểm | 1 – 5 điểm |
| Số cảnh báo được chấm | 33 case x 2 mô hình (66 lượt output) |
| Ai chấm | **AI Judge (`CyberCrew/notmythos-8b`)** chấm tự động theo Rubric v1. *(Người chấm thủ công: Nguyên & Dương chưa chấm độc lập trên CSV)* |

### 3.2. Kết quả chấm điểm trung bình (AI Judge Scoring)

| Tiêu chí | Mô hình chính (`qwen2.5:7b`) | Mô hình đối chứng (`CyberCrew/notmythos-8b`) | Điểm TB chung |
|---|---|---|---|
| Tính chính xác của phần tóm tắt (Summary) | 3.94 | 3.76 | 3.85 |
| Tính đúng đắn của giải thích nguyên nhân (Root Cause) | 3.00 | 3.30 | 3.15 |
| Mức độ phù hợp của đánh giá nghiêm trọng (Severity) | 2.21 | 2.15 | 2.18 |
| Tính đúng đắn của kỹ thuật MITRE ATT&CK | 4.21 | 3.58 | 3.90 |
| Tính hữu dụng của bước kiểm tra đề xuất (Next Steps) | 3.85 | 3.70 | 3.78 |
| **Điểm trung bình tổng (Overall Score)** | **3.44 / 5** | **3.30 / 5** | **3.37 / 5** |

### 3.3. COHEN'S KAPPA

> *Ghi chú từ thầy:* Cần 2 người chấm thủ công độc lập (Nguyên & Dương) trên cùng tập mẫu để tính hệ số đồng thuận Kappa.

| Mục | Giá trị |
|---|---|
| Số mẫu dùng để tính Kappa | **chưa chạy** (Đang chờ 2 sinh viên điền bảng điểm thô) |
| **Hệ số Cohen's Kappa ($\kappa$)** | **chưa chạy** |

---

## 4. HIỆU NĂNG VÀ TÀI NGUYÊN (Mục 4.5)

### 4.1 & 4.3. So sánh hiệu năng 2 mô hình trên 33 cảnh báo

| Chỉ số | Mô hình chính (`qwen2.5:7b`) | Mô hình đối chứng (`CyberCrew/notmythos-8b`) |
|---|---|---|
| **Thời gian TB / cảnh báo (giây)** | **2.716 s** | **2.173 s** |
| Thời gian nhanh nhất | 1.752 s | 1.470 s |
| Thời gian chậm nhất | 5.020 s | 2.724 s |
| Điểm chất lượng TB (AI Judge) | **3.44 / 5** | **3.30 / 5** |
| Tỷ lệ JSON hợp lệ (%) | 97.0% | **100.0%** |
| VRAM tiêu thụ thực tế | ~4.7 GB | ~2.5 GB |
| Dung lượng file weights | 4.7 GB | 2.0 GB |
| **Nhận xét chung** | Cho chất lượng giải thích và gán mã MITRE tốt hơn (3.44 vs 3.30), nhưng độ trễ cao hơn. | Tốc độ xử lý nhanh hơn 20%, VRAM nhẹ hơn, tỷ lệ tuân thủ JSON 100%, nhưng gán mã MITRE kém hơn. |

### 4.2. Tài nguyên tiêu thụ

| Chỉ số | Giá trị |
|---|---|
| RAM tiêu thụ khi chạy | ~4.5 GB - 6.0 GB |
| VRAM tiêu thụ khi chạy | ~2.5 GB (`notmythos-8b`) đến ~4.7 GB (`qwen2.5:7b`) |
| Số token đầu vào TB / cảnh báo | ~520 tokens |
| Số token đầu ra TB / cảnh báo | ~160 tokens |

---

## 5. MẢNG ẢNH CHỤP MÀN HÌNH (Chương 3)

| Hình | Nội dung cần chụp | Trạng thái |
|---|---|---|
| Hình 3.2 | Wazuh Dashboard sau khi cài đặt thành công | **chưa chụp** (Cần bật VM SIEM `.10` chụp giao diện) |
| Hình 3.3 | Danh sách Agent ở trạng thái **Active** | **chưa chụp** (Cần chụp màn hình Agents tab) |
| Hình 3.4 | Cảnh báo hiển thị trên Dashboard sau khi chạy kịch bản | **chưa chụp** (Cần chụp màn hình Events tab) |
| Hình 3.5 | Giao diện hiển thị kết quả diễn giải của mô-đun AI | **chưa chụp** (Cần chụp Web UI `127.0.0.1:8765`) |
| Mục 3.4.4 | 1 cảnh báo đầu vào (rút gọn) + bản JSON đầu ra tương ứng | **Đã có** (Đã xuất trong `docs/SoLieuC4.md`) |
## 4.6. Kiểm thử tấn công thực tế từ Kali Linux qua Web UI & SQLite persistence

Dưới đây là kết quả kiểm thử tấn công thực tế (SSH Brute-force & DVWA Web Attack) từ Kali (`192.168.100.30`) sang Victim (`192.168.100.20`), được ghi nhận vào Wazuh Indexer, phân tích qua Web UI (`127.0.0.1:8765`) và lưu trữ thực tế trong SQLite Database (`dashboard_data/dashboard.db`).

### Bảng 4.4: Kết quả kiểm thử thực tế trên Web UI / SQLite DB giữa 2 mô hình

| Job ID | Mô hình sử dụng | Kịch bản tấn công | Số cảnh báo | Trạng thái Job | Schema Valid | AI Severity | Latency (s) | Ghi chú & Đánh giá |
|---|---|---|---|---|---|---|---|---|
| Job #26 | `qwen2.5:7b` | SSH Brute-force (Kali → Victim) | 40 | `succeeded` | Valid | `medium` | 13.91s | Phân tích thành công, trích xuất đúng 4/4 rule groups (5503, 5760, 5551, 5763), đánh giá đúng bản chất chuỗi đăng nhập thất bại. |
| Job #27 | `CyberCrew/notmythos-8b:latest` | SSH Brute-force (Kali → Victim) | 40 | `partial` | Fallback | `unknown` | 5.53s | Mô hình 3.2B không tuân thủ strict JSON schema cho prompt cửa sổ tổng hợp phức tạp (window aggregate), rơi vào `local_fallback` với `severity: unknown`. |

### Nhận xét đánh giá từ kiểm thử thực tế (Web UI / DB):
1. **Khả năng tuân thủ JSON Schema trên Web UI**:
   - `qwen2.5:7b` (mô hình chính) hoàn thành full pipeline thành công (`status: succeeded`), phân tích đầy đủ 40 alert thực tế từ Kali, tổng hợp 4 nhóm luật SSH brute-force và trả kết quả tiếng Việt theo đúng `soc-contract-v1`.
   - `CyberCrew/notmythos-8b:latest` (mô hình đối chứng 3.2B parameters) đạt 100% hợp lệ trên các case đơn lẻ offline (`run_eval.py`), nhưng khi xử lý prompt tổng hợp cửa sổ nhiều cảnh báo (aggregate window prompt) trên Web UI, mô hình trả về JSON thiếu/lệch cấu trúc khiến validator kích hoạt cơ chế an toàn `local_fallback` (`severity: unknown`).
2. **Hiệu năng xử lý**:
   - `notmythos-8b` xử lý nhanh hơn (5.53s so với 13.91s của `qwen2.5:7b`), tuy nhiên đổi lại là độ tin cậy và khả năng tuân thủ cấu trúc output phức tạp kém hơn.
3. **Tính toàn vẹn dữ liệu**:
   - Cả hai bài test thực nghiệm đều được ghi nhận trực tiếp vào SQLite Database (`dashboard_data/dashboard.db`) và hiển thị đầy đủ trên giao diện Web UI tại địa chỉ `http://127.0.0.1:8765`.
