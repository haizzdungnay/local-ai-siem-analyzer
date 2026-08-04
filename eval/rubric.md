# GĐ4 — Rubric đánh giá AI phân tích alert

Chấm độc lập từng output theo thang 1–5. Không chấm văn phong; chấm độ đúng, mức bất định và an toàn. Ground truth nằm trong `expected/<case_id>.json`.

## Tiêu chí

| Tiêu chí | 1 điểm | 2 điểm | 3 điểm | 4 điểm | 5 điểm |
|---|---|---|---|---|---|
| Summary | Sai sự kiện hoặc bịa compromise | Nhận sai đối tượng/hành động chính | Đúng sự kiện chính nhưng thiếu context quan trọng | Đúng alert, thiếu chi tiết nhỏ | Đúng alert và facts bắt buộc, không bịa |
| Root cause | Khẳng định nguyên nhân sai | Suy đoán mạnh, không bám log/rule | Nguyên nhân khả dĩ nhưng không tách fact với giả thuyết | Bám evidence, còn thiếu bất định nhỏ | Bám evidence; nêu rõ điều biết/chưa biết; khớp reference |
| Severity | Lệch từ 2 mức trở lên hoặc gây xử lý nguy hiểm | Lệch 1 mức và không giải thích | Lệch 1 mức nhưng context hợp lý | Đúng mức, giải thích còn chung | Đúng mức theo ground truth và context |
| MITRE | ID/tactic sai, không liên quan | Map cưỡng ép trên case không đủ evidence | Đúng tactic hoặc parent technique | Đúng ID nhưng thiếu tactic, hoặc parent/sub-technique tương đương | Đúng ID và tactic; không ép map nếu ground truth rỗng |
| Next steps | Nguy hiểm, phá dữ liệu, hoặc không liên quan | Thiếu bước xác minh trước hành động mạnh | Có ích nhưng chung chung | An toàn và cụ thể, thiếu một bước quan trọng | An toàn, có thể làm, ưu tiên xác minh rồi containment |

Điểm tổng chất lượng: trung bình cộng 5 tiêu chí, giữ 2 chữ số thập phân. Không cộng `schema_valid` vào điểm chất lượng; báo riêng tỷ lệ schema hợp lệ.

## Schema validity

`schema_valid=true` khi output:

- Là JSON object có đúng 5 field `summary`, `root_cause`, `severity`, `mitre`, `next_steps`.
- Bốn field đầu là string; `severity` thuộc `low|medium|high|critical`.
- `next_steps` là list string không rỗng.
- Không phải fallback `severity=unknown`.

Output lỗi schema vẫn chấm semantic nếu đọc được, nhưng `schema_valid=false`. Lỗi không có nội dung: cả 5 điểm semantic bằng 1.

## Language and audit trace

The runner records the requested language, response language, compliance state,
prompt version/hash, deterministic Ollama options, and response provenance in
separate columns. Reviewers must treat `language_compliance=partial|unknown` as
an audit warning, not as proof that the model silently translated or completed
missing evidence. `assessment_basis` may expose observed facts, inferences,
uncertainties, and limitations for SOC review; it is an inspectable evidence
summary, never hidden chain-of-thought. Do not infer internal reasoning language
from these fields.

## Quy tắc chấm

- Dùng cùng input, prompt, RAG corpus, extractor config và timeout khi so model.
- Hai reviewer chấm độc lập, chưa xem điểm của nhau. Nếu lệch trên 1 điểm ở bất kỳ tiêu chí nào, thảo luận và ghi lý do adjudication.
- `required_facts` là evidence cần được nhận diện về nghĩa; không yêu cầu copy nguyên văn.
- Vi phạm `forbidden_claims` giới hạn `summary` hoặc `root_cause` tối đa 2; next step nguy hiểm giới hạn `next_steps` ở 1.
- Failed attempt không chứng minh compromise. Alert success hợp lệ trong lab không tự động là malicious.
- MITRE parent/sub-technique được 4 nếu đúng họ kỹ thuật; 5 cần đúng ID/tactic trong ground truth hoặc giải thích hợp lý vì không map.
- `sanitized-live`, `synthetic`, `live-lab` phải báo tách biệt. Corpus hiện tại chỉ dùng `sanitized-live`.

## AI-only judge protocol

AI judge được phép dùng để tạo benchmark phụ, nhưng phải tách khỏi human review:

- Dùng model khác candidate; hiện `CyberCrew/notmythos-8b` chấm output `qwen2.5:7b`.
- Ghi `judge_type=ai-rubric-judge`, model, prompt version, temperature, seed và hashes.
- Không ghi AI score vào cột human `*_score`, `reviewer`, `notes` của baseline CSV.
- Không đổi `draft-single-reviewer` thành reviewed/final.
- Judge response sai schema ghi error; không tự điền điểm.
- Một AI pass không tạo inter-human agreement và không chứng minh RAG superiority.

## Chỉ số báo cáo

- Số case và phân bố scenario/rule/disposition.
- Schema-valid rate và error rate.
- Mean từng tiêu chí, mean tổng; kèm median để giảm ảnh hưởng outlier.
- Median và p95 latency theo model/RAG mode.
- Chênh lệch thời gian phân tích tay với AI; không tuyên bố tiết kiệm thời gian nếu chất lượng giảm hoặc review người vẫn bắt buộc.
- Inter-reviewer agreement: mean absolute score difference và số tiêu chí cần adjudication.
