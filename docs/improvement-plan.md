# Kế hoạch cải thiện có kiểm chứng — Local AI SIEM Analyzer

Ngày đánh giá lại: 2026-08-05. Nguồn chính: `docs/check.md`, mã nguồn hiện tại và
roadmap sản phẩm. Kế hoạch này thay thế mọi diễn giải rằng bản hiện tại đã
production-ready.

## Kết luận điều phối

Sản phẩm hiện là local SOC analyst-assist có nền tảng tốt về provenance, data
minimization, structured output và test tự động. Nó chưa chứng minh được chất
lượng semantic của AI, lợi ích của RAG, hoặc hiệu quả triage đối với analyst.
Ưu tiên tiếp theo là làm đúng contract, đo được chất lượng và đóng các lỗ hổng
vận hành có thể làm kết quả không đáng tin.

`vi` và `en` là ngôn ngữ đầu ra được hỗ trợ. Không thêm tùy chọn hiển thị hay
lưu private chain-of-thought; thay vào đó, mọi kết quả phải có evidence trace
ngắn, kiểm tra được gồm observed facts, inferences, uncertainties và
limitations.

## Quy tắc thực hiện

Mọi work item tuân theo chuỗi: khảo sát -> thiết kế -> thực thi -> kiểm tra tự
động -> báo cáo evidence -> kiểm tra chéo -> điều phối/chốt. Điều phối
multi-agent là quy trình phát triển bên ngoài ứng dụng; dashboard không được
tự tạo agent có quyền tự hành động trên Wazuh hay endpoint.

- Không tuyên bố RAG, semantic accuracy hoặc production readiness khi chưa có
  evidence tương ứng.
- Không đưa raw alert, prompt, RAG text hoặc private reasoning vào SQLite,
  JSON export hay telemetry mới.
- Không thêm auto-remediation, remote bind, multi-user hoặc outbound action
  trước auth, TLS, RBAC, approval, idempotency và rollback.
- Mỗi thay đổi contract cần migration/version, regression test, release note
  trong `CHANGELOG.md` trước `HANDOFF.md`, và provenance trong JSON export.

## Milestone 0 — Chốt sự thật hiện trạng

Mục tiêu: giao diện, API và tài liệu không khiến analyst hiểu nhầm dashboard
đang dùng RAG hoặc các con số aggregate là chính xác tuyệt đối.

1. Gắn `analysis_mode` thực tế cho từng job: `no_rag`, `rag`, `rag_fallback`,
   `local_fallback` hoặc `empty_window`. `/api/status` chỉ báo RAG effective
   khi service đã xác định được trạng thái, không suy diễn từ config.
2. Gắn nhãn aggregate cardinality là `approximate` khi dùng OpenSearch
   cardinality; ghi precision setting, top-rule coverage và phần bị cắt vào
   prompt, UI và JSON export. Không dùng một sample alert để khẳng định cả
   rule group.
3. Cập nhật README/roadmap: bản phát hành là localhost, single-operator MVP;
   kết quả AI chỉ là advisory và cần human review. Giữ UI report tiếng Việt/
   Anh và public evidence trace hiện có.

Hoàn thành khi test API/UI xác minh các nhãn cho detail, aggregate, empty và
fallback job; export v2 có cùng ý nghĩa; không có tài liệu nào ngược trạng thái.

## Milestone 1 — Contract RAG đáng tin cho dashboard

Mục tiêu: dashboard hoặc dùng RAG có provenance, hoặc rõ ràng chạy no-RAG.
Khuyến nghị là triển khai RAG cho window analysis theo rule/bucket đã chọn,
không đẩy raw alert hàng loạt vào context.

1. Tạo `retrieve_for_window(...)`: sinh query từ rule ID, rule title và fact
   aggregate đã sanitize; chỉ retrieve cho các group được coverage.
2. Áp relevance threshold có cấu hình và đặt tên chính xác cho Chroma
   `distance` (lower-is-better). Context rỗng phải thành
   `no_relevant_context`, không phải giả RAG success.
3. Version index bằng `index_schema_version`, canonical corpus SHA-256,
   embedding model/version/digest, chunking configuration và build time. Khi
   manifest khác, reindex atomic vào collection mới rồi swap; xóa document đã
   biến mất khỏi corpus cũ.
4. Persist chỉ RAG provenance cần audit: mode, index manifest ID/hash,
   document ID/hash, distance, threshold, source class và retrieval time.
   Không persist nội dung tài liệu RAG đầy đủ.
5. Mở rộng JSON report theo version mới tương thích ngược; v1 giữ nguyên.
   Baseline CSV phải ghi prompt/schema/model/corpus/index digest và retrieval
   provenance để rerun có thể đối chiếu.

Hoàn thành khi thay corpus hoặc embedding manifest làm reindex đúng; document
bị xóa không còn retrieve; query xa ngưỡng không vào prompt; dashboard và CLI
cùng semantics; tests cover fresh, stale, deletion, threshold, fallback và
export scrub.

## Milestone 2 — Correctness và local safety

Mục tiêu: job cancelled không biến thành success, output rỗng không thành kết
quả hợp lệ, và local API không trả dữ liệu vượt nhu cầu xem xét.

1. Định nghĩa cancellation là cooperative cancellation. Worker kiểm tra token
   trước fetch, trước model, sau model và ngay trước persist. Nếu cancel trong
   Ollama call, request có thể chờ tới timeout nhưng result phải bị discard và
   job kết thúc `cancelled`; chỉ gọi hard abort khi client hỗ trợ an toàn và có
   test.
2. Siết `valid_output()` và parser: yêu cầu summary/root-cause có nội dung,
   `next_steps` không rỗng, evidence fields hợp lệ. Fallback phải mang
   origin/warning riêng, không nâng schema success im lặng.
3. Giới hạn JSON request body bằng config an toàn (ví dụ 64 KiB), trả 413 rõ
   ràng, và test oversized/malformed payload. Thêm cap tương tự cho raw alert
   extract và RAG input trước khi gọi model.
4. Thay alert-detail trả nguyên `_source` bằng safe projection/redaction
   allowlist. Nếu còn cần full detail local, endpoint explicit phải audit và
   scrub secrets/PII; export vẫn không có raw source.
5. Đổi `verify_ssl` mặc định sang `true`; lab muốn tắt phải explicit cùng
   warning. CLI không in raw extracted log mặc định; một cờ unsafe riêng phải
   nêu rõ rủi ro. CLI RAG fallback phải hiện `rag_fallback` và nguyên nhân đã
   sanitize.

Hoàn thành khi regression tests cover cancel-during-model, no-save-after-cancel,
empty output, oversized body/log, secret/PII echo và RAG failure; loopback và
security headers vẫn pass. Không cần UI manual test để xác nhận các contract.

## Milestone 3 — Đánh giá AI có giá trị khoa học

Mục tiêu: đo được hiệu quả thay vì dùng schema validity hoặc AI judge làm bằng
chứng chính.

1. Freeze manifest hiện tại, tách development, locked test và regression;
   kiểm tra duplicate, missing, unknown case và đúng một result mỗi case ở cả
   baseline lẫn summary. Chuẩn hóa UTF-8 trong toàn bộ tool eval trên Windows.
2. Hoàn tất ground truth bằng hai SOC reviewer độc lập, blind với RAG mode.
   Bất đồng qua adjudication; lưu reviewer pseudonym, rubric version, thời
   gian và lý do ở mức evidence, không lưu chain-of-thought.
3. Chấm 66 output RAG/no-RAG bằng rubric đã khóa, báo weighted agreement,
   confidence interval và kết quả theo cohort. AI judge chỉ là chỉ số phụ.
4. Chạy analyst-only so với AI-assist cùng case, counterbalanced thứ tự. Báo
   median/p95 time-to-triage, override rate, error rate, trust calibration và
   review burden.
5. Mở rộng lên tối thiểu 100 case đã review sau khi protocol pass: tách
   sanitized-live, live-lab, synthetic, Atomic Red Team và sau đó Sysmon;
   deduplicate theo rule/event family/source pattern. Dùng Sigma/Atomic làm
   nguồn test có ground truth, không tự nhận ATT&CK coverage 100%.
6. Đo RAG Recall@k, precision@k, expected evidence-ID hit, grounded claim,
   forced-MITRE/false-causal claim, correct abstention và RAG-harm rate qua
   ablation no-RAG/rule-only/MITRE-only/rule+MITRE.

Hoàn thành khi bảng kết quả nêu rõ sample, split, model/prompt/index versions,
human agreement và giới hạn; chỉ kết luận RAG hữu ích nếu paired human results
và grounding metrics cùng ủng hộ. Nếu không, giữ no-RAG mặc định dashboard.

## Milestone 4 — Reproducibility, governance và vận hành

Mục tiêu: release có thể build lại, audit được và không biến tài liệu lab thành
nơi lộ thông tin vận hành.

1. Containment credential trước: nếu một credential tracked còn hiệu lực, rotate
   hoặc revoke nó trước mọi release. Sau đó quyết định bằng văn bản topology lab
   là demo public đã sanitize hay dữ liệu live phải chuyển khỏi tracked repo.
   Thay credential/identifier bằng placeholder; scan cả source và docs trong
   pre-commit/CI. Việc rewrite Git history cần owner phê duyệt riêng, không làm
   tự động.
2. Lock dependencies có hashes hoặc lockfile, thêm SBOM và `pip-audit`/SCA vào
   CI, có quy trình cập nhật dependency. Pin GitHub Actions theo commit SHA,
   đặt workflow permissions tối thiểu read-only, và pin runtime Python cùng
   model/embedding metadata trong artifact release.
3. Thêm metrics local không chứa raw data: latency p50/p95/p99 theo model/RAG
   cold-warm, queue wait, timeout/fallback/cancel/dependency failure rates và
   schema-valid rate. Đặt retention cho metrics/audit metadata.
4. Mở rộng regression suite: prompt injection từ alert/RAG/rule, RAG poisoning,
   corpus/model/prompt/schema drift, aggregate truncation, retries/restart,
   request-size abuse và data-redaction leak.
5. Chỉ sau các mục trên mới thiết kế auth/RBAC/OIDC, TLS, actor audit,
   notification/ticket idempotency, correlation/asset context và PCAP pivot.
   Auto-remediation vẫn ngoài scope cho đến khi approval/rollback thực chứng.

Hoàn thành khi CI tái tạo dependency graph, audit artifact và test matrix;
runbook không chứa secret live; dashboard vẫn loopback cho tới khi auth/TLS/RBAC
có acceptance riêng.

## Thứ tự triển khai và release gate

1. Nếu có credential live, làm Milestone 4 mục 1 ngay. Sau đó Milestone 0 và
   Milestone 2 mục 1-3.
2. Milestone 1: không bật RAG dashboard trước index manifest, threshold và
   provenance.
3. Milestone 3 mục 1-4; mở corpus 100 case chỉ sau evaluator workflow ổn định.
4. Milestone 4 mục 1-4 chạy song song khi không đổi data contract; correlation
   và integration là release sau, không phải blocker bằng chứng AI.

Mỗi PR phải có scope nhỏ, migration/revert note nếu đổi persistence, test cho
regression, compileall, pytest, JavaScript/shell syntax và `git diff --check`.
CI xanh chưa đủ: gate cuối cần review contract, provenance/export scrub và
changelog/handoff nhất quán.

## Trạng thái triển khai tự động — 2026-08-05

- Hoàn tất contract code: dashboard window retrieval theo rule group đã
  sanitize; manifest corpus/index, threshold distance, provenance, trạng thái
  RAG truthful, context bound và cancellation discard-after-model. Index build
  vào generation staging, atomically swap manifest active sau khi đầy đủ
  embedding; embedding-model digest chỉ ghi khi provider thật sự cung cấp giá
  trị quan sát được (lookup lỗi không làm churn generation đang active).
- Hoàn tất local safety: schema reject output gần rỗng, body cap 64 KiB, DTO
  alert-detail redact, TLS verify default, CLI raw-output opt-in, aggregate
  cardinality/truncation warnings, UTF-8 eval summary và CSV coverage checks.
- Hoàn tất reproducibility baseline: direct dependencies pin, `pylock.toml`,
  expiring `pip-audit` exception policy, CycloneDX SBOM CI artifact, Actions
  SHA pin/read-only permissions, staged/full secret scan và governance policy.
- Chưa thể tự động hoàn tất: credential rotation/revocation cho mọi giá trị
  từng có trong lịch sử Git, Git history rewrite (nếu owner chọn), two-reviewer
  human evaluation, adjudication, analyst timing study và corpus 100 case.

## Backlog sau khi chứng minh nền tảng

- Correlation across windows/findings, asset criticality, threat-intel cache và
  analyst case workflow có actor audit.
- Import/validate Sigma, Atomic Red Team mapping và Windows Sysmon corpus khi
  lab đã có source canonical.
- Notification/ticket outbound có allowlist, delivery idempotency và explicit
  analyst approval.
- Remote/multi-user chỉ đi cùng TLS, authentication, RBAC và CSRF protection;
  không expose localhost MVP qua tunnel.
