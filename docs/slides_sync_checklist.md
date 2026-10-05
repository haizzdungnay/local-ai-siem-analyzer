# Checklist & Hướng dẫn Cập nhật Slide Báo cáo (A07)

Tài liệu này hướng dẫn chi tiết các nội dung và số liệu cần cập nhật thủ công trong slide thuyết trình `docs/slides/A07-BaoCao-Module-AI-SIEM.pptx` (và xuất lại `A07-BaoCao-Module-AI-SIEM.pdf`) trước buổi nghiệm thu/bảo vệ đề tài.

---

## 1. Bảng Đối chiếu Số liệu Khoa học (Tránh lỗi thổi phồng kết quả)

| Nội dung slide cũ | Nội dung chuẩn hóa cần thay thế | Căn cứ khoa học |
|---|---|---|
| *"RAG giúp tăng vượt trội độ chính xác thêm 9.1% so với no-RAG"* | **"RAG đạt 22/33 (66.7%) so với no-RAG 19/33 (57.6%), mức tăng +9.1 điểm chưa đạt ý nghĩa thống kê trên mẫu N=33 (McNemar exact $p = 0.58$; 95% CI: $[-12.1\%, +30.3\%]$)."** | `eval/baseline.md` |
| *"Recall mức High đạt kết quả khả quan"* | **"Recall mức High: RAG đạt 3/7 (Wilson 95% CI: $15.8\% - 75.0\%$), no-RAG đạt 1/7 ($2.6\% - 51.3\%$). Cần mở rộng số lượng case High/Critical để tăng độ nhạy phát hiện."** | `docs/confusion_matrix_qwen2.5_7b.md` |
| *"Ground truth được chuyên gia phê duyệt"* | **"Tập nhãn Ground Truth (N=33) được tạo qua quy trình Blind Review giữa 2 chuyên gia độc lập: 31/33 ca đồng thuận ($93.9\%$), 2 ca phân xử ($6.1\%$), hệ số Cohen's $\kappa = 0.91$ (linear-weighted $0.93$) đạt mức xuất sắc."** | `docs/adjudication_procedure.md` |
| *"Mô hình CyberCrew/notmythos-8b bị lượng tử hóa làm giảm tham số từ 8B về 3.2B"* | **"Mô hình `CyberCrew/notmythos-8b` có kiến trúc gốc là Llama-3.2-3B (~3.2 tỷ tham số), không phải 8 tỷ tham số. Lượng tử hóa Q4_K_M chỉ giảm độ dài bit trọng số, không làm giảm số lượng tham số mạng."** | `docs/SoLieuC4_DinhChinh.md` |

---

## 2. Các Slide Cần Cập nhật Chi tiết

### Slide: Đánh giá Hiệu năng & Thực nghiệm (Evaluation Results)
- **Cập nhật biểu đồ/bảng Confusion Matrix:**
  - Cập nhật số liệu từ `eval/confusion_matrix_qwen2.5_7b.csv`.
  - Giữ lại 1 ca `invalid` (do mô hình trả về định dạng chưa khớp hoặc rơi vào fallback) trên cột ma trận RAG.
  - Thêm chú thích chân trang: *"Khoảng tin cậy rộng do cỡ mẫu N=33; để chứng minh chênh lệch 9 điểm với power 0.8 cần mở rộng lên ~370 ca kiểm thử."*

### Slide: Kiến trúc Hệ thống & Module Dashboard (System Architecture)
- **Cập nhật sơ đồ phân rã Blueprint:**
  - Thay vì kiến trúc Dashboard nguyên khối, thể hiện rõ thiết kế **6 Flask Blueprints độc lập**:
    1. `ui_bp`: Phục vụ giao diện tĩnh và trạng thái phụ thuộc Ollama/Indexer.
    2. `jobs_bp`: Điều phối hàng đợi phân tích, phân trang, review và xuất báo cáo.
    3. `ip_analysis_bp`: Trực quan hóa nguồn IP và phân tích chuỗi tấn công (Kill Chain).
    4. `security_tests_bp`: Catalog và quản lý luồng kiểm thử tự động.
    5. `notifications_bp`: Điều phối gửi tin tức thời qua Telegram Bot và Gmail SMTP.
    6. `maintenance_bp`: Quản lý chính sách lưu trữ (retention), dọn dẹp và sao lưu SQLite.
  - Module `dashboard_reports.py`: Đóng gói DTO và che giấu địa chỉ IP (`_masked_ip`) trước khi trả về client.

### Slide: Các Giải pháp Gia cố An ninh & Tin cậy (Hardening & Trustworthiness)
- **Thêm 1 slide chuyên biệt về kỹ thuật gia cố (Security & Quality Hardening):**
  1. **Chống Prompt Injection:**
     - Chuẩn hóa văn bản NFKC, loại bỏ ký tự ẩn (zero-width), strip bidi overrides và escape ký tự phân cách `<>` (`sanitize_untrusted_text`).
     - Kiểm thử thành công trên bộ dữ liệu 20 ca tấn công đối nghịch đa dạng (`eval/adversarial/adversarial_dataset_diverse_20.json`).
  2. **Chống DNS Rebinding:**
     - Kiểm tra Host header trong `before_request` hook (`_reject_non_loopback_host`), chỉ cho phép loopback IP và host hợp lệ từ cấu hình `cors_allowed_origins`.
  3. **Xác thực Tri thức An ninh MITRE ATT&CK:**
     - Đối chiếu thời gian thực với danh mục ngoại tuyến 858 kỹ thuật Enterprise ATT&CK (`enterprise_mitre_ids.json`), tự động gắn cờ `mitre_unverified` vào provenance nếu mô hình sinh ID lạ.
  4. **Kiểm soát Độ dài Ngữ cảnh (Context Window Guardrail):**
     - Cấu hình `num_ctx: 8192`, cắt xén log thô trần 2000 ký tự và cảnh báo khi tổng token vượt 7000.
  5. **Bảo vệ Vận hành Giao tiếp:**
     - Giới hạn tải file Telegram `MAX_PDF_BYTES = 4.9MB` để chống nghẽn đường truyền băng thông thấp; tự động chuyển sang tin nhắn văn bản khi quá tải.

---

## 3. Kịch bản Trả lời Phản biện Hội đồng (Defense Q&A Preparation)

### Câu hỏi 1: "Tại sao mức cải thiện của RAG chỉ là +9.1% và chưa đạt ý nghĩa thống kê?"
- **Trả lời:**
  - Trên tập dữ liệu thực tế gồm 33 ca (`sanitized-live`), RAG cải thiện độ chính xác từ 57.6% (19/33) lên 66.7% (22/33).
  - Phân tích thống kê McNemar paired exact test cho thấy giá trị $p = 0.58$, khoảng tin cậy 95% là $[-12.1\%, +30.3\%]$. Điều này phản ánh trung thực rằng cỡ mẫu 33 ca chưa đủ lực thống kê (statistical power ≈ 7%) để bác bỏ giả thuyết $H_0$.
  - Tính toán lý thuyết chỉ ra rằng để chứng minh chênh lệch 9 điểm có ý nghĩa thống kê ($\alpha = 0.05, \text{power} = 0.80$), cần tối thiểu ~146 cặp phân loại bất đồng (tương đương quy mô tập dữ liệu ~370 ca). Nhóm đã xây dựng sẵn quy trình mở rộng dataset (F-07) cho giai đoạn tiếp theo.

### Câu hỏi 2: "Mô hình LLM cục bộ xử lý thế nào khi gặp các cảnh báo bị chèn lệnh độc hại (Prompt Injection)?"
- **Trả lời:**
  - Hệ thống áp dụng nguyên tắc phòng vệ theo chiều sâu (Defense-in-Depth):
    1. Toàn bộ log từ người dùng/thiết bị ngoài được bao bọc trong thẻ phân cách an toàn `<UNTRUSTED_ALERT>` và được tiền xử lý qua `sanitize_untrusted_text` (loại bỏ ký tự điều khiển Unicode, escape ký tự `<>`).
    2. System prompt tuân thủ hợp đồng nghiêm ngặt (`soc-contract-v2`), yêu cầu mô hình phân tích hành vi kỹ thuật thay vì thực thi chỉ thị chứa bên trong nội dung log.
    3. Bộ quy tắc sàn severity tất định (`apply_severity_floor`) can thiệp cưỡng bức: nếu log có `rule.level >= 12`, mức cảnh báo bắt buộc tối thiểu là High, vô hiệu hóa hoàn toàn nỗ lực ép hạ mức cảnh báo của kẻ tấn công.

### Câu hỏi 3: "Vì sao chọn mô hình 7B thay vì các mô hình lớn hơn hoặc API thương mại?"
- **Trả lời:**
  - Đề tài tập trung vào bài toán triển khai cục bộ (Local Edge AI) trong môi trường SOC cô lập (air-gapped):
    1. Đảm bảo 100% dữ liệu nhật ký không bị rò rỉ ra internet (tuân thủ quy định bảo vệ dữ liệu nội bộ).
    2. Mô hình `qwen2.5:7b` (lượng tử hóa Q4_K_M chiếm 4.7 GB VRAM) có thể chạy mượt mà trên máy trạm thông thường mà không đòi hỏi cụm GPU đắt đỏ.
    3. Khảo sát thực nghiệm chứng minh mô hình 7B tổng quát có khả năng bám sát cấu trúc JSON schema và phân loại alert vượt trội so với mô hình 3.2B chuyên dụng.
