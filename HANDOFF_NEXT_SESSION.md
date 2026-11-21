# Bàn giao nhanh cho phiên mới

Cập nhật **21/11/2026, Asia/Saigon**. `HANDOFF.md` giữ lịch sử chi tiết.

## Điểm bắt đầu hiện tại

- Code RAG R0.3 trên `codex/issue-13-rag-provenance`, nền `29825bf`. Bản ghép giữ logic playbook dashboard mới và provenance RAG. **617 test offline pass, 1 skip**. [CI của nhánh](https://github.com/haizzdungnay/local-ai-siem-analyzer/actions/workflows/python-tests.yml?query=branch%3Acodex%2Fissue-13-rag-provenance).
- Việc kế tiếp là đo retrieval bằng Ollama thật trên năm ca development và lưu output mới ghi digest. Hai snapshot development ghi trạng thái trước đồng bộ. Chốt playbook với #23/#29 và held-out độc lập theo #27 trước baseline. [Checklist RAG R0.3](docs/rag-evaluation-protocol.md).
- #32 giữ nghiệm thu thực tế R0. Sau baseline và #32, chuyển sang nghiệm thu công cụ điều tra chỉ đọc #14.

## Trạng thái sau review độc lập #13 (2026-11-21)

- Nhánh `codex/issue-13-rag-provenance` tại base `441db23`. Bản sửa P1–P3 và snapshot mới đều local, chưa commit/push. Xem mục #13 ngày 21/11 ở `HANDOFF.md` để nhân bản kiểm thử.
- Schema 3 ghép đúng collection–manifest, dùng staging riêng, kiểm tập ID/digest rồi mới publish. Dashboard dùng generation tương thích khi rebuild lỗi và retry sau 30 giây. Provenance phân biệt MITRE alert và KB, ghi chunk thực sự vào context. Eval giữ đủ dòng và tính `context_recall` riêng. Benchmark dùng Chroma trong bộ nhớ.
- Kiểm offline **588 passed, 1 skipped, 18 deselected**, guard không ghi nhận lượt đọc dữ liệu khóa. Chroma thật + vector giả đã kiểm 6.251 document và 40 lượt development. Snapshot `eval/baselines/rag-issue13-development-2026-11-21.json` dùng protocol v2. #13/#32 còn mở, chờ retrieval thật với digest, CI và freeze held-out/playbook độc lập.

## Snapshot #13 trước review (2026-11-19)

- Checkout hiện tại: `codex/issue-13-rag-provenance`, base `441db23`; code/docs/test/snapshot vẫn local, chưa commit/push. Hai ledger và bản bàn giao cũ được giữ nguyên lịch sử.
- #13 đã sửa phần code RAG: corpus section/provenance/index schema 2, exact rule/MITRE + semantic, batch generation swap, trạng thái retrieval qua alert/window/CLI và evaluator. **596 passed, 2 skipped** vì Ollama không chạy; compile/secret scan/whitespace và ba tracked eval tree pass.
- Chroma local thật + vector giả đã kiểm toàn 6.251 document, batch limit 5.461. Chưa đo embedding hoặc chất lượng retrieval thật. Snapshot `eval/baselines/rag-issue13-development-2026-11-19.json` là development/dirty, `formal_baseline_ready=false`; held-out/playbook freeze cuối còn chờ #23/#27/#29. #13/#32 vẫn OPEN.
- Next action: review diff và protocol `docs/rag-evaluation-protocol.md`; commit/push khi được yêu cầu, chạy CI; sau khi Ollama sẵn sàng/được phép dùng thì đo development vào output mới. Không lấy held-out để tuning hoặc chạy lab/notifier/executor. Chi tiết verification và lỗi cleanup thư mục Chroma tạm ngoài repo trong mục #13 đầu `HANDOFF.md`.

## Checkout và kết quả ngày 19/11

- Repo `haizzdungnay/local-ai-siem-analyzer`.
- Branch: `main`; HEAD đã push trước khi viết bàn giao này: `441db2388106d5ef71cdf590f59f335804713359`.
- [CI của HEAD](https://github.com/haizzdungnay/local-ai-siem-analyzer/actions/runs/44450875266): **4/4 pass**, Ubuntu/Windows × Python 3.11/3.12.
- Full suite gần nhất: **571 passed, 2 skipped**, Windows/Python 3.13.2. Hai skip vì Ollama chưa chạy; chưa nghiệm thu model/Indexer/browser/SOC thật.
- Bản bàn giao nhanh này và cập nhật hai ledger đang ở local, chưa commit/push. Kiểm `git status` trước khi sync; giữ nguyên mọi thay đổi của người dùng.

| Hạng mục | Trạng thái và kết quả |
|---|---|
| [#11](https://github.com/haizzdungnay/local-ai-siem-analyzer/issues/11) / PR #30 | **CLOSED/COMPLETED**, đã merge. Chặn search thiếu dữ liệu, giữ bucket giao cửa sổ, active-ips lỗi trả 502; coverage/error đi qua job/store/report. |
| [#12](https://github.com/haizzdungnay/local-ai-siem-analyzer/issues/12) / PR #31 | **CLOSED/COMPLETED**, merge `910dbc89b296bd62e8ed00358b8eec1ff9ee3409`. V5 giữ `B_unknown`; signals không hạ severity, chọn nhánh khớp nặng nhất; model lỗi vẫn giữ regex. Policy `playbook-evidence-v2`. |
| [#13](https://github.com/haizzdungnay/local-ai-siem-analyzer/issues/13) | **OPEN, chưa bắt đầu triển khai**. Việc code nên làm tiếp: RAG/provenance/index version/baseline. |
| [#32](https://github.com/haizzdungnay/local-ai-siem-analyzer/issues/32) | **OPEN**, 19 mục nghiệm thu thật: Indexer, model, browser/report và SOC; có expected/actual, manifest, artifact và tiêu chí đóng. |

Đóng #11/#12 chỉ chốt **code/regression**. R0 còn #13 và #32; không nghiệm thu R1 hoàn chỉnh khi hai gate này chưa đạt. #23/#29 vẫn là việc phối hợp/review playbook, không tự đóng theo #12.

## Kế hoạch code #13 ngày 19/11

1. Đọc `AGENTS.md`, body #13, mục **Issue 13** trong [implementation guide](docs/approval-remediation-implementation-guide.md), #23/#29 và protocol #27. Đối chiếu HEAD/diff thực tế, không sửa lại #11/#12 nếu chưa có regression mới.
2. Rà `ai_module/rag.py::RuleRAG._load_corpus` và schema thật trong `ai_module/rag_data/wazuh_rules.json`, `mitre_techniques.json`; tái hiện trường tri thức đang bị bỏ khỏi index/context.
3. Bổ sung nội dung theo budget, provenance và exact lookup `rule.id`/`mitre.id` kết hợp semantic retrieval. Phân biệt `disabled`, `no_match`, `filtered_out`, `error`; có ca 5712, thiếu rule, rule lạ và nhiều MITRE.
4. Version hóa corpus/index/manifest; dùng generation swap hiện có, giữ index cũ nếu rebuild lỗi. Viết regression có ý nghĩa trong test hiện có trước khi sửa.
5. Dùng development cases để chỉnh; freeze SHA/config/model digest/prompt/extractor/KB/playbook/policy cùng protocol/held-out trước lượt đo chính thức. Lưu baseline mới riêng; chưa có embedding/retrieval thật thì chưa kết luận chất lượng đã tăng hoặc đóng #13.

File cần đọc: `ai_module/rag.py`, `tests/test_ai_pipeline.py`, `tests/test_rag_benchmark.py`, `tests/test_build_kb.py`, test RAG/window trong `tests/test_dashboard_core.py`, `eval/rag_retrieval_eval.py` (kiểm đường output trước khi chạy).

Nếu chuyển sang nghiệm thu lab: dùng nguyên checklist #32, chưa cần viết checklist mới. Ghi rõ `LIVE`, `LIVE_SOURCE + FAULT_PROXY`, `MOCK`, `BROWSER`; test lỗi qua proxy không được báo là Indexer tự phát lỗi thật.

## Giới hạn cần giữ

- `branch_valid` chỉ nói ID hợp lệ; mọi nhánh R0 vẫn `branch_verified=false`, `needs_evidence`. Field refs chưa phải query receipts.
- Nhãn/cảnh báo trong `summary/root_cause` không xác minh nội dung model; model vẫn có thể suy luận sai/đề nghị đóng. `B_unknown` có thể giữ low/unknown để xếp hàng, không cấp phép đóng.
- Search hoàn chỉnh không chứng minh retention đủ hoặc snapshot chung giữa nhiều query. PIT/receipt/evaluator thuộc #14/#15.
- Hermes điều phối qua SIEM MCP là thiết kế đã chốt, **chưa có runtime**. Backend giữ scope/identity/policy/evidence/grant/approval/execution; #14 chỉ tool đọc cố định, grant động sau #18. Không thêm generic shell/plugin tự cài để né quyền.
- Đọc alert từ Indexer/OpenSearch `:9200`; Manager API `:55000` chỉ quản trị. Baseline GĐ4 `qwen2.5:7b`; `qwen2.5:3b` chỉ demo nhẹ.
- Không đưa credentials hoặc IP/host/fingerprint live chưa sanitize vào tracked artifact/GitHub. Không chạy `eval/build_dataset.py`, không rewrite `eval/cases/`/`eval/expected/`, không lấy held-out để chỉnh playbook.
- Không tự vận hành lab/notifier/executor hoặc cấp quyền ghi chỉ vì các issue code đã đóng. Subagent trong project chỉ Fable/Opus, ưu tiên Opus; nếu không có model phù hợp thì làm trực tiếp.

## Kiểm tra và bàn giao

```powershell
git status --short --branch
git log -3 --oneline
python -m pytest tests -q -p no:cacheprovider --tb=short -rs
python -m compileall -q ai_module eval tests
python scripts/check_tracked_secrets.py
git diff --check
```

Chỉ pull fast-forward khi đã bảo toàn local edits. Khi bắt đầu code mới, tạo branch `codex/…`; hook `core.hooksPath=.githooks` đã bật. Sau kết quả repo: cập nhật **CHANGELOG Unreleased trước, HANDOFF ngay sau**; ghi fail/skip/giới hạn, review staged diff và stage cả hai ledger trước commit. Không báo mock là lab thật; chỉ đóng issue đã đạt phạm vi nghiệm thu.

Prompt mở phiên mới để đo RAG R0.3

> Đọc HANDOFF.md, AGENTS.md và protocol RAG R0.3. Kiểm tra SHA và CI. Khi Ollama sẵn sàng, đo năm ca development với digest xác minh, output riêng và Chroma tạm. Đối chiếu recall/coverage và context recall. Giữ held-out độc lập theo #27, phối hợp freeze playbook ở #23/#29 và cập nhật hai ledger. Phần nghiệm thu hệ thống thực tế theo #32.
