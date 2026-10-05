# Quy trình Đánh giá Nhãn Độc lập (Blind Adjudication Procedure)

## 1. Mục đích & Phạm vi

Tài liệu này chuẩn hóa quy trình tạo và nghiệm thu tập nhãn chân lý (Ground Truth) phục vụ đánh giá năng lực suy luận của mô hình AI phân tích alert SIEM (`local-ai-siem-analyzer`).
Quy trình đảm bảo loại bỏ thiên kiến xác nhận (confirmation bias), đo lường định lượng độ tin cậy giữa các chuyên gia đánh giá (Inter-Rater Reliability), và thiết lập cơ chế phân xử minh bạch khi xảy ra bất đồng.

---

## 2. Rubric Phân loại Mức độ Nghiêm trọng (Severity Rubric)

Mọi reviewer phải tuân thủ nghiêm ngặt rubric 4 bậc (đồng bộ với hợp đồng phân tích `soc-contract-v2`):

| Mức độ | Định nghĩa tác động | Tiêu chí kỹ thuật & Bằng chứng log | Ví dụ điển hình |
|---|---|---|---|
| **Critical** | Đe dọa trực tiếp tính toàn vẹn của hệ thống, kiểm soát máy chủ hoặc rò rỉ dữ liệu. | RCE thành công, ransomware đang mã hóa, leo thang đặc quyền root/SYSTEM, compromise Domain Controller. | T1059 (PowerShell/Bash execution) kết hợp outbound C2 IP lạ, pass-the-hash. |
| **High** | Tấn công có chủ đích, phát hiện mã độc hoặc dấu hiệu vi phạm bảo mật nghiêm trọng. | Rootkit/trojan được phát hiện (`rootcheck`), tấn công brute force quy mô lớn, khai thác CVE có vũ khí hóa, rule Wazuh level $\ge 12$. | Rule 510 (trojaned binary), brute-force SSH/RDP liên tục từ IP lạ, mimikatz execution. |
| **Medium** | Hành vi bất thường cần điều tra, chưa xác nhận xâm phạm nhưng vi phạm kiểm soát an ninh. | Dừng dịch vụ bảo mật (agent stoppage), SSH failed login đơn lẻ cho root, thay đổi cấu hình tường lửa bất thường, quét cổng diện hẹp. | Rule 506 (Wazuh agent stopped), rule 5760 (SSH auth failure đơn lẻ cho root). |
| **Low** | Thông báo vận hành hệ thống thông thường, cảnh báo tuân thủ hoặc tấn công bị chặn tự động hoàn toàn. | CVE đã được vá thành công qua cập nhật gói, quét reconnaissance thông thường từ internet không xuyên thủng tường lửa. | Rule 23502 (solved package CVE notification), port scan bị drop tại edge. |

*Lưu ý:* Khi alert có `rule.level >= 12`, reviewer bắt buộc áp dụng mức tối thiểu là **High** (Deterministic Severity Floor), trừ khi có bằng chứng rõ ràng chứng minh là cảnh báo giả (false positive do cấu hình test).

---

## 3. Quy trình Đánh giá 3 Bước (Blind Labeling Workflow)

```
[ Alert Dataset ] 
       │
       ├──> Reviewer 1 (Blind) ──> Nhãn R1 + Rationale ──┐
       │                                                 ├──> Đối chiếu tự động
       └──> Reviewer 2 (Blind) ──> Nhãn R2 + Rationale ──┘         │
                                                                   ▼
                                                       ┌───────────────────────┐
                                                       │  Khớp nhãn (Unanimous) │ ──> Gán Ground Truth
                                                       └───────────────────────┘
                                                                   │ Bất đồng
                                                                   ▼
                                                       ┌───────────────────────┐
                                                       │ Adjudication Meeting  │ ──> Thống nhất Rationale
                                                       │ (Phân tích bối cảnh)  │ ──> Gán Ground Truth (Resolved)
                                                       └───────────────────────┘
```

### Bước 1: Gán nhãn mù độc lập (Independent Blind Review)
1. Bộ dữ liệu alert được trích xuất từ Wazuh Indexer và làm sạch định danh nhạy cảm (sanitized).
2. Dữ liệu được giao độc lập cho ít nhất 2 reviewer là kỹ sư SOC/chuyên gia bảo mật.
3. **Nguyên tắc mù (Blind principle):**
   - Reviewer không được biết kết quả dự đoán của mô hình AI (no-RAG hay RAG).
   - Reviewer không được biết danh tính và nhãn của reviewer còn lại.
   - Không trao đổi về các case đang đánh giá trong suốt giai đoạn review mù.
4. Đầu ra mỗi reviewer: File JSON chứa `{case_id: {"severity": ..., "rationale": ...}}`.

### Bước 2: Đo lường độ đồng thuận (Inter-Rater Reliability)
Hệ thống tính toán hệ số Cohen's Kappa ($\kappa$) giữa 2 reviewer trên toàn bộ tập nhãn:

$$\kappa = \frac{P_o - P_e}{1 - P_e}$$

Trong đó:
- $P_o$ (Observed agreement): Tỷ lệ các case hai reviewer cùng gán một mức severity.
- $P_e$ (Hypothetical chance agreement): Tỷ lệ đồng thuận ngẫu nhiên tính theo phân phối biên độ nhãn của từng reviewer:
  $$P_e = \sum_{c \in \{low, med, high, crit\}} P(R_1 = c) \times P(R_2 = c)$$

**Ngưỡng nghiệm thu (Acceptance Criteria):**
- $\kappa \ge 0{,}80$: Mức đồng thuận rất cao (Almost perfect agreement). Bộ nhãn đủ điều kiện dùng làm Ground Truth nghiệm thu chính thức.
- $0{,}60 \le \kappa < 0{,}80$: Mức đồng thuận khá (Substantial agreement). Chấp nhận cho các đợt benchmark sơ bộ, cần rà soát lại rubric.
- $\kappa < 0{,}60$: Mức đồng thuận không đạt. Phải dừng quy trình, đào tạo lại rubric và tiến hành gán nhãn lại từ đầu.

### Bước 3: Phân xử bất đồng (Adjudication Phase)
1. Lập danh sách các ca lệch nhãn (disagreement cases).
2. Tổ chức phiên họp phân xử (Adjudication Meeting) gồm 2 reviewer và Chủ trì kỹ thuật (Lead Security Analyst).
3. Đánh giá chi tiết:
   - Đọc toàn bộ ngữ cảnh alert, các trường dữ liệu phụ trợ (`full_log`, `rule.groups`, `agent.name`, các log lân cận cùng thời điểm).
   - Phân tích vector tấn công và tác động thực tế tới tài sản mục tiêu.
   - Thống nhất một mức nhãn cuối cùng kèm lý do phân xử cụ thể (`adjudication_rationale`).
4. Ghi nhận nhãn vào `eval/adjudicated_severity.json` với trường `"agreement": "disagreement_resolved"`.

---

## 4. Minh chứng Thực nghiệm trên Bộ Dữ liệu Baseline (N = 33)

Trên tập dữ liệu 33 ca kiểm thử thực nghiệm `sanitized-live`:
- **Đồng thuận tuyệt đối:** 31/33 ca ($P_o = 93{,}94\%$).
- **Số ca bất đồng cần phân xử:** 2 ca ($6{,}06\%$).
  1. `ambiguous-506-01` (Wazuh agent stopped):
     - R1 gán *medium*, R2 gán *low*.
     - *Phân xử:* Thống nhất **medium** do việc mất kênh thu thập telemetry an ninh tại endpoint làm gián đoạn giám sát SOC, cần điều tra ưu tiên trung bình.
  2. `ssh-5760-02` (SSH root auth failure aggregated 4 times):
     - R1 gán *medium*, R2 gán *high*.
     - *Phân xử:* Thống nhất **medium** do số lượng 4 lần thử là hành vi quét dò đáng ngờ nhưng chưa đạt ngưỡng tấn công brute-force kéo dài gây nghẽn/xâm phạm diện rộng (rule 5712/2502).
- **Hệ số Cohen's Kappa đạt được:**
  - $\kappa_{\text{unweighted}} = 0{,}91$ (Wilson 95% CI: $0{,}81 - 1{,}00$).
  - $\kappa_{\text{linear-weighted}} = 0{,}93$.
- Đạt chuẩn nghiệm thu xuất sắc ($\kappa > 0{,}80$).

---

## 5. Quy trình Áp dụng cho các Batch Mở rộng Tương lai (F-07)

Khi mở rộng tập dữ liệu lên $\approx 370$ ca (tối thiểu 30 ca high/critical):
1. **Chia batch nhỏ:** Tiến hành gán nhãn theo từng lô $50 - 100$ ca để kiểm soát độ trôi chất lượng (label fatigue).
2. **Kiểm tra trạm dừng (Stop-gate):** Sau mỗi lô 50 ca, tính $\kappa$ tức thời. Nếu $\kappa < 0{,}75$, tạm dừng phân tích tìm nguyên nhân mơ hồ trong mô tả log trước khi dán tiếp.
3. **Quản lý phiên bản Ground Truth:**
   - Mọi thay đổi ground truth phải được lưu vết trong repo git, không ghi đè trực tiếp các file baseline cũ.
   - File kết quả adjudication phải lưu đầy đủ các trường: `severity`, `agreement`, `reviewer_1`, `reviewer_2`, `adjudication_rationale`, `reviewers`, `status`.
