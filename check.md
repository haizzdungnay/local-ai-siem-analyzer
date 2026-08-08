# Báo cáo kiểm thử và đánh giá Local AI SIEM Analyzer

Ngày đánh giá: 2026-08-05

## Kết luận

Đề tài tốt ở mức prototype nghiên cứu/local SOC analyst-assist. Kiến trúc đúng hướng, test tự động mạnh, chú trọng kiểm toán và data minimization. Hệ thống chưa đủ bằng chứng để gọi production-ready, chưa đủ human evaluation để kết luận AI hoặc RAG cải thiện chất lượng phân tích.

Phạm vi đánh giá chỉ đọc và kiểm thử. Không sửa code, không chạy `eval/build_dataset.py`, không tạo traffic tấn công mới, không thay corpus.

## 1. Kết quả kiểm thử

| Kiểm tra | Kết quả |
|---|---|
| `python -m pytest -q` | **91 passed / 4.40s** |
| `python -m compileall -q ai_module eval tests` | PASS |
| `node --check ai_module/web/app.js` | PASS |
| Git Bash syntax: 3 attack scripts + pre-commit hook | PASS |
| `git diff --check` | PASS, chỉ cảnh báo LF/CRLF |
| Tổng hợp baseline | PASS khi ép UTF-8 |
| Live Wazuh/Ollama/dashboard | Không chạy lại |

Có lỗi portability trên Windows `cp1252`:

```text
UnicodeEncodeError: 'charmap' codec can't encode character ...
```

`eval/summarize_results.py` lỗi khi in tiếng Việt trên console Windows mặc định. Chạy lại bằng:

```bash
PYTHONIOENCODING=utf-8 python eval/summarize_results.py eval/results.csv eval/results-no-rag.csv --ai-judgments eval/ai-judgments-notmythos-8b.csv
```

thì PASS. `eval/run_eval.py` đã tự cấu hình UTF-8 nhưng `eval/summarize_results.py` chưa có xử lý tương đương.

## 2. Điểm mạnh

### Kiến trúc đúng

- Alert lấy đúng từ Wazuh Indexer/OpenSearch `:9200`, không lấy sai từ Manager API `:55000`: `ai_module/reader.py:191-205`.
- Cửa sổ thời gian dùng UTC `[start,end)`, giới hạn tối đa 24 giờ: `ai_module/reader.py:170-188`.
- Cửa sổ lớn chuyển sang aggregate-only thay vì cắt alert âm thầm: `ai_module/reader.py:374-458`.
- Full document chỉ được đọc từ index allowlist `wazuh-alerts-*`: `ai_module/reader.py:461-475`.

### AI safety và kiểm toán tốt

- Ollama mặc định loopback; remote bắt buộc explicit opt-in và HTTPS: `ai_module/reader.py:43-65`.
- Alert và RAG context được đánh dấu untrusted; prompt cấm làm theo instruction trong log: `ai_module/llm.py:93-144`, `ai_module/llm.py:239-275`.
- JSON schema, field validation và fallback fail-closed: `ai_module/llm.py:43-79`, `ai_module/llm.py:462-536`.
- Invalid model output không được lưu raw preview: `ai_module/llm.py:352-389`.
- Có hash prompt, input, schema, response cùng latency/token provenance: `ai_module/llm.py:163-235`.
- Evidence trace tách `observed_facts`, `inferences`, `uncertainties`, `limitations`; không trình bày chain-of-thought.
- Exact sample-log echo bị redact trước persistence: `ai_module/analysis_service.py:202-237`, `ai_module/analysis_service.py:289-317`.
- JSON export scrub raw log, prompt và reasoning: `ai_module/dashboard.py:71-89`.

### Dashboard MVP có nền tốt

- Bind loopback bắt buộc: `ai_module/dashboard.py:252-279`.
- CSP, `nosniff`, `no-referrer`, API `no-store`: `ai_module/dashboard.py:405-415`.
- SQLite WAL, foreign keys, transaction, migration versioned: `ai_module/dashboard_store.py:86-117`.
- Analyst review là append-only bằng trigger DB: `ai_module/dashboard_store.py:20-42`.
- Restart recovery và schedule bounded catch-up: `ai_module/dashboard_worker.py:38-76`, `ai_module/dashboard_worker.py:174-197`.
- CI chạy Windows/Linux, Python 3.11/3.12, pytest, compile, JS và shell syntax: `.github/workflows/python-tests.yml:8-51`.

## 3. Vấn đề ưu tiên cao

### P0 — Chưa đủ bằng chứng kết luận chất lượng AI hoặc lợi ích RAG

Corpus hiện có 33 case, toàn bộ vẫn `draft-single-reviewer`. Human semantic score hiện bằng 0 case.

| Chỉ số | RAG | No-RAG |
|---|---:|---:|
| Schema valid | 32/33 | 33/33 |
| Severity exact | 22/33, 66.7% | 19/33, 57.6% |
| Mean latency | 2.716s | 2.428s |
| AI-judge overall | 3.44/5 | 3.42/5 |

Paired AI judge: RAG thắng 8, hòa 18, thua 7.

Chênh lệch AI-judge gần bằng nhiễu; severity chỉ là smoke metric. Kết luận hợp lệ hiện tại:

> Pipeline hoạt động và có tính kiểm toán; chưa chứng minh RAG cải thiện chất lượng semantic.

Evidence: `eval/baseline.md:11-24`, `eval/baseline.md:34-62`, `eval/README.md:17`, `eval/rubric.md:39-68`.

### P0 — Dashboard thực tế không dùng RAG

`AnalysisService._ensure_rag()` chỉ được gọi trong `analyze_one()`: `ai_module/analysis_service.py:248-287`.

Worker dashboard chỉ gọi `self.analysis_service.analyze_aggregate(...)` tại `ai_module/dashboard_worker.py:108-112`. `analyze_aggregate()` gọi thẳng `analyze_window()` và không lấy RAG context: `ai_module/analysis_service.py:289-317`.

Hệ quả:

- CLI/eval per-alert có thể dùng RAG.
- Manual/scheduled dashboard window không dùng RAG.
- `rag.enabled: true` không đồng nghĩa dashboard analysis dùng RAG.
- `/api/status` dựa vào `analysis_service.rag`, ban đầu luôn `None`: `ai_module/dashboard.py:433-445`.

Đây là mismatch quan trọng giữa hình dung sản phẩm và execution path.

### P1 — RAG index có thể stale

`ensure_indexed()` chỉ kiểm `collection.count() > 0`: `ai_module/rag.py:58-62`.

Không có:

- Hash corpus.
- Embedding model/version hash.
- Reindex khi nguồn sửa.
- Loại document cũ khi corpus xóa.
- Index schema/version.
- Retrieval provenance trong baseline CSV.

Đổi `wazuh_rules.json`, MITRE corpus hoặc embedding model vẫn có thể dùng vector cũ.

### P1 — Retrieval không có relevance threshold

`query()` luôn lấy top-k và lưu Chroma distance dưới tên `score`: `ai_module/rag.py:118-146`.

Chroma distance thường lower-is-better; tên `score` dễ bị hiểu ngược. Không threshold đồng nghĩa context không liên quan vẫn được đưa vào prompt, có thể làm tăng forced MITRE mapping.

### P1 — Cancel không ngắt Ollama call

Worker kiểm cancel trước fetch và trước model call, nhưng không kiểm sau model call trước khi lưu:

- `ai_module/dashboard_worker.py:79-103`
- `ai_module/dashboard_worker.py:108-154`

Nếu analyst cancel trong phase `calling_ollama`, request vẫn có thể chạy đến timeout 120 giây rồi lưu result và kết thúc `succeeded/partial`.

Cancel API vì vậy mang nghĩa “yêu cầu cancel”, không bảo đảm job bị dừng.

### P1 — Tracked repo chứa dữ liệu lab nhạy cảm trái governance hiện có

Repo tracked chứa topology lab, user/path vận hành và shared lab credential trong ledger/runbook. Điều này xung đột với quy tắc không ghi live identifiers/credentials chưa sanitize vào tracked output.

Điểm đáng chú ý:

- `HANDOFF.md:236-244`
- `docs/manual-test.md:6-25`
- `README.md:11-28`
- `ai_module/config.example.yaml:4-21`

Không nhắc lại credential trong báo cáo này. Cần quyết định rõ một trong hai:

1. Lab topology là dữ liệu demo công khai, dùng địa chỉ và credential giả; hoặc
2. Lab topology là thông tin live, chuyển ra khỏi tracked repo.

Hiện hai chính sách tồn tại đồng thời.

## 4. Vấn đề mức trung bình

### Eval schema có thể chấp nhận output rỗng

`valid_output()` dùng `all(...)` trên `next_steps`; list rỗng vẫn trả `True`: `eval/run_eval.py:54-63`.

Parser cũng cho phép list rỗng vì `_bounded_strings()` không yêu cầu ít nhất một phần tử: `ai_module/llm.py:392-400`.

Output sau có thể bị tính schema-valid dù gần như vô dụng:

```json
{
  "summary": "",
  "root_cause": "",
  "severity": "low",
  "mitre": "",
  "next_steps": []
}
```

Điều này trái rubric yêu cầu `next_steps` là list string không rỗng: `eval/rubric.md:19-26`.

### Baseline summary không kiểm coverage CSV

`summarize_results.py` không kiểm:

- Duplicate `case_id`.
- Missing case.
- Unknown case.
- Đủ đúng 33 manifest case.
- Một row cho mỗi case.

Evidence: `eval/summarize_results.py:30-66`.

AI-judge summary có coverage validation tốt hơn tại `eval/summarize_results.py:69-83`. Baseline path nên đạt cùng mức chặt.

### Aggregate metric có giá trị approximate nhưng trình bày như exact

OpenSearch `cardinality` là approximate tại `ai_module/reader.py:423-425`.

Giá trị được đưa thẳng vào prompt như fact: `ai_module/analysis_service.py:166-173`. Với cửa sổ lớn, đây không nên được mô tả là exact nếu chưa có precision configuration hoặc disclaimer.

### Aggregate-only chỉ giữ top rule buckets

`terms` aggregation bị giới hạn `max_rule_buckets`; phần còn lại chỉ được biểu diễn bằng `sum_other_doc_count`: `ai_module/reader.py:321-371`, `ai_module/reader.py:408-425`.

Code có `rules_truncated`, nhưng:

- Một alert mẫu được dùng đại diện cả rule group.
- Unique counts approximate.
- LLM chỉ thấy top groups.
- Job có thể vẫn trông đầy đủ nếu người dùng không đọc coverage warning kỹ.

### TLS lab default không an toàn nếu tái sử dụng

Config mẫu đặt `verify_ssl: false` cho Manager và Indexer: `ai_module/config.example.yaml:4-22`.

Manager helper còn dùng mặc định `False` khi field bị bỏ: `ai_module/reader.py:105-114`.

Chấp nhận được trong lab cô lập, nhưng Basic Auth qua TLS không verify dễ bị copy sang môi trường khác và lộ credential.

### Full raw alert có thể xuống browser

API alert detail trả toàn bộ `_source`: `ai_module/reader.py:461-475`. Frontend hiển thị JSON đầy đủ.

Loopback giảm rủi ro mạng, không bảo vệ khỏi process hoặc user khác trên cùng host. Raw alert có thể chứa command, token, PII hoặc dữ liệu ứng dụng.

### Local dashboard chưa có auth/CSRF secret

Origin check chỉ áp dụng khi header `Origin` tồn tại: `ai_module/dashboard.py:243-249`.

Các process local có thể:

- Tạo/cancel/retry job.
- Đổi schedule.
- Ghi analyst review.
- Chạy retention prune.
- Đọc full alert.

Đây là boundary chấp nhận được cho single-user localhost MVP, nhưng không được expose qua tunnel, reverse proxy hoặc `0.0.0.0`.

### JSON body không có size cap

`_json_body()` parse toàn body trước validation: `ai_module/dashboard.py:46-52`. Không có `MAX_CONTENT_LENGTH`. Process local có thể gây memory/queue DoS.

### CLI in raw extracted log

`full_log` nằm trong extractor fields: `ai_module/config.example.yaml:31-43`; CLI in toàn `alert_text`: `ai_module/main.py:86-89`.

Terminal history, CI log hoặc screen recording có thể lưu dữ liệu nhạy cảm, trong khi dashboard export đã scrub kỹ hơn.

### CLI RAG fail-open không có provenance rõ

CLI bắt mọi exception RAG rồi tiếp tục no-RAG: `ai_module/main.py:65-100`.

Người vận hành có thể tưởng đang chạy RAG nhưng output thực tế không có context. Eval runner thì fail nếu RAG initialization lỗi, tạo behavior khác giữa CLI và evaluation.

### Dependency chưa lock, CI chưa audit CVE

`requirements.txt` dùng broad lower bounds: `ai_module/requirements.txt:1-6`. Không có lockfile/hash, SBOM hoặc `pip-audit`. Cùng commit có thể resolve dependency khác theo thời gian.

## 5. Đánh giá so với dự án tương tự

| Hệ thống | Phạm vi | Project này mạnh hơn ở đâu | Project này thiếu gì |
|---|---|---|---|
| Wazuh | XDR/SIEM, agent, detection, FIM, vulnerability, active response | Local LLM interpretation, RAG experiment, provenance rõ | Không phải detection engine; không có active response |
| Security Onion | NIDS/NSM, alert, Hunt, Cases, PCAP, Onion AI | Nhẹ hơn; local data minimization và audit contract rõ | PCAP, Hunt, observables, analyst/team case workflow |
| Elastic Security | Detection rules, ML, Timeline, Cases, AI Assistant, Attack Discovery | Ollama local-first, không phụ thuộc SaaS/enterprise connector | Correlation, rule health, case integrations, RBAC, response |
| LimaCharlie | Cloud EDR, telemetry, D&R, automated actions, managed AI sessions | Advisor-only an toàn hơn, local/offline phù hợp đề tài | Endpoint response, tool orchestration, cloud scale, ROI tracking |
| Sigma | Detection-as-code portable | Có thể dùng làm nguồn rule/eval độc lập | Chưa tích hợp rule portability/conversion testing |
| Atomic Red Team | Adversary emulation theo ATT&CK | Phù hợp mở rộng lab có ground truth | Hiện mới SSH/FIM/web, chưa có coverage theo technique |

Định vị đúng nhất:

> Không xây SIEM mới. Xây mô-đun AI local, auditable, hỗ trợ analyst diễn giải alert do Wazuh đã phát hiện.

Định vị này khả thi và có giá trị học thuật. Không nên so số tính năng với Elastic/Security Onion; nên so chất lượng giải thích, grounding, privacy, latency và analyst time.

## 6. Chấm điểm hiện tại

| Hạng mục | Điểm | Nhận xét |
|---|---:|---|
| Kiến trúc và scope | 8/10 | Phân tách Wazuh–Indexer–AI đúng |
| Code quality/testability | 8/10 | 91 tests pass, module rõ, fail-closed tốt |
| Security local MVP | 6.5/10 | Loopback/CSP tốt; TLS, raw alert và localhost trust còn yếu |
| Auditability/data minimization | 8.5/10 | Điểm nổi bật của đề tài |
| RAG engineering | 5.5/10 | Có A/B nhưng index freshness/retrieval evidence yếu; dashboard không dùng RAG |
| AI evaluation quality | 5/10 | Corpus pilot tốt, human evaluation chưa hoàn tất |
| SOC workflow completeness | 5.5/10 | Case-lite đủ demo, chưa phải SOC platform |
| Production readiness | 4.5/10 | Không auth/RBAC/HA/lock dependency/live retry |
| Giá trị đề tài thực tập | **7.5/10** | Scope hợp lý, có điểm khác biệt local/auditable |

## 7. Thứ tự cải thiện nên ưu tiên

1. Hoàn tất human evaluation: reviewer thứ hai, adjudication, blind score 66 output, weighted agreement.
2. Đo analyst-only so với AI-assist trên cùng case: median/p95 time, override rate, error rate.
3. Làm rõ dashboard RAG contract: dùng thật hoặc công bố dashboard no-RAG.
4. Version RAG index bằng corpus hash, embedding model/digest, retrieval document ID/hash.
5. Thêm retrieval metrics: Recall@k, precision@k, context relevance và RAG-harm rate.
6. Sửa eval validity/coverage checks trước khi mở rộng corpus.
7. Thêm regression suite cho prompt injection/RAG poisoning, oversized log, stale index, cancel trong Ollama.
8. Mở rộng corpus lên tối thiểu 100 case trước kết luận model; hướng tốt là Sigma + Atomic Red Team trong lab.
9. Tăng operational safety: secure TLS defaults, body cap, redact raw-alert API, cancellation semantics.
10. Lock dependency + SCA/SBOM trước khi gọi release reproducible.
11. Thêm Windows/Sysmon case sau khi Sysmon được xác nhận.
12. Giữ auto-remediation ngoài scope cho đến khi có auth, approval, idempotency, rollback và audit actor.

## 8. Benchmark nên bổ sung

### Dataset và coverage

- Báo riêng các cohort `sanitized-live`, `live-lab`, synthetic và Atomic Red Team.
- Tách development, locked test và regression set.
- Đo coverage theo tactic/technique/sub-technique ưu tiên; không tuyên bố 100% ATT&CK coverage.
- Deduplicate theo rule, event family và source pattern để tránh metric bị inflate.

### Chất lượng diễn giải

- Summary factual precision và `required_facts` recall.
- Unsupported causal claim và forbidden-claim rate.
- Severity confusion matrix, weighted kappa, under-triage và over-triage rate.
- MITRE precision, forced-map rate và empty-when-appropriate rate.
- Safe-action và verify-before-contain rate.
- Correct abstention trên benign, ambiguous và failed-attempt.
- Claim-to-source traceability và fabricated-compromise rate.

### RAG

- Recall@k, precision@k và expected evidence-ID hit.
- Claim groundedness/faithfulness.
- Ablation no-RAG, rule-only, MITRE-only, rule+MITRE.
- Paired delta trên locked set.
- RAG-harm rate: forced MITRE, stale description, irrelevant context, hallucination delta.
- Corpus hash, embedding digest, index version, top-k và retrieved document provenance.

### SOC workflow

- Human-only so với AI-assist time-to-triage median/p95.
- Analyst override rate cho severity, MITRE và next steps.
- Escalation precision/recall.
- Review burden phút/output.
- Evidence/pivot utility.
- Analyst trust calibration.

### Reliability và safety

- Latency median/p95/p99 theo model, RAG mode, cold/warm state.
- Timeout, fallback, queue và dependency failure rate.
- Repeated-run agreement với fixed seed.
- Prompt-injection pass rate từ alert, RAG document và rule description.
- Raw-log/credential/PII echo rate; mục tiêu leak bằng 0.
- Aggregate coverage khi vượt detail cap.
- Model/prompt/schema/corpus drift regression.

## 9. Kết luận đề tài

Đề tài có nền kỹ thuật tốt hơn prototype AI-SIEM thông thường vì đã xử lý nhiều điểm thường bị bỏ qua: provenance, evidence trace, prompt injection boundary, fallback sanitization, aggregate cap và local inference.

Nút thắt hiện tại không phải thiếu tính năng. Nút thắt là evaluation validity:

- Chưa có ground truth final.
- Chưa có human score.
- Chưa đo analyst time.
- Chưa chứng minh RAG benefit.
- Dashboard chưa dùng RAG dù pipeline per-alert có RAG.

Hoàn tất các điểm này sẽ tăng giá trị đề tài nhiều hơn thêm correlation graph, PCAP hoặc auto-response.

## Nguồn tham khảo

- [Wazuh architecture](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Wazuh Dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/index.html)
- [Wazuh rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Security Onion Alerts](https://docs.securityonion.net/en/2.4/alerts.html)
- [Security Onion Cases](https://docs.securityonion.net/en/2.4/cases.html)
- [Security Onion Assistant](https://docs.securityonion.net/en/2.4/assistant.html)
- [OpenSearch Security Analytics](https://docs.opensearch.org/latest/security-analytics/)
- [Elastic Security investigation](https://www.elastic.co/docs/solutions/security/investigate)
- [Elastic AI Assistant](https://www.elastic.co/docs/solutions/security/ai/ai-assistant)
- [Elastic LLM performance matrix](https://www.elastic.co/docs/solutions/security/ai/large-language-model-performance-matrix)
- [LimaCharlie Detection & Response](https://docs.limacharlie.io/3-detection-response/)
- [LimaCharlie AI Sessions](https://docs.limacharlie.io/9-ai-sessions/)
- [Sigma specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Ragas](https://github.com/vibrantlabsai/ragas)
