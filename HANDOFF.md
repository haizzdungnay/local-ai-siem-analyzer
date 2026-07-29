# Handoff — local-ai-siem-analyzer

Ngày cập nhật: 2026-07-29
Branch: `claude/lab-eval-checkpoint`
Commit nền trước phiên: `78cb31b`
Checkpoint local: `1fd6205`, `d3984ee`, `a267761`, `9377c78`, AI/runbook `a5f874b`, ledger `0a3a8c0` trên `claude/lab-eval-checkpoint`.
Pre-push verification: compileall PASS, `26 passed`, AI summary 66/66 PASS, `git diff --check` PASS. `gh` CLI không cài; dùng `git push` trực tiếp.
Continuity: đã thêm `CLAUDE.md` và `.githooks/pre-commit`; mỗi clone cần chạy `git config core.hooksPath .githooks` để bật ledger gate.
`eval/run_eval.py` tồn tại trong checkout; path case đã resolve theo repo root, không phụ thuộc CWD.

## Cập nhật phiên hiện tại

- Governance continuity hoàn tất: `CLAUDE.md`, `.githooks/pre-commit`, CHANGELOG entry.
- Docs đã đồng bộ: Indexer `:9200`, Manager `:55000` management-only; Windows `.40` Active; Bước 8 có SSH command; FIM marker realtime; model/rule wording thống nhất.
- RAG source hardening hoàn tất: validate list/item/nonblank string ID/duplicate trước embedding/upsert.
- Indexer malformed-hit hardening hoàn tất: fail-closed cho `hits` object, hit và `_source` sai kiểu.
- Eval path fix hoàn tất: `load_case()` resolve theo repo root; test từ CWD khác.
- Full verification cuối: compile PASS, `19 passed`, shell syntax PASS, `git diff --check` PASS; chỉ có CRLF conversion warnings.
- Changelog lưu thay đổi trong `Unreleased`; lịch sử release giữ nguyên.
- Ledger hook: shell syntax và logic cases thiếu/có đủ ledger PASS.
- Verification cuối lặp lại sau ledger update: compileall PASS, `19 passed`, shell syntax PASS, `git diff --check` PASS.
- SSH live ngày 2026-07-29: key login PASS trên SIEM `.10` (`siem`), Victim `.20` (`trnguyn-virtual-machine`), Kali `.30` (`kali`); không cần dùng password.
- SSH scenario live PASS: 20 bounded attempts từ Kali `.30` tới Victim `.20`; Indexer batch gần nhất có 21 `5503`, 26 `5760`, source `192.168.100.30`.
- FIM live PASS: Victim đã có `<directories realtime="yes">/opt/wazuh-fim-lab</directories>`; marker tạo/sửa/xóa an toàn, Indexer ghi rule `553` cho delete. Chưa có rule `550` trong lượt này.
- Live AI attempt 1 phát hiện Windows `cp1252` `UnicodeEncodeError`; đã thêm `_configure_console_encoding()` UTF-8 và test hồi quy.
- Live AI attempt 2 PASS: `python ai_module/main.py --limit 3`, model `qwen2.5:7b`, Indexer/RAG/Ollama chạy đủ, 3 JSON output hợp lệ. Quan sát semantic: benign PAM/sudo vẫn có MITRE text chưa chính xác ở vài output; cần human scoring, không blocker pipeline.
- Remote `/tmp/ssh-bruteforce.sh` và `/tmp/fim-trigger.sh` đã dọn trên cả ba VM.
- Full verification sau live lab: compileall PASS, `20 passed`, shell syntax PASS, `git diff --check` PASS; chỉ còn CRLF warnings.
- Web live PASS ngày 2026-07-29: DVWA/Apache reachable, Nikto bounded 44s; Indexer batch gần nhất có `31101`, `31151` correlation và `31105` XSS. Script được sửa dùng `--data-urlencode` cho SQLi curl để tránh HTTP `000`.
- Web eval capture hoàn tất: append 3 case `web-31101-01`, `web-31151-01`, `web-31105-01`; corpus hiện 33 case, không rewrite 30 case cũ; expected vẫn draft-single-reviewer.
- FIM modified PASS: tạo `modified-marker.txt`, chờ baseline 20s, append nội dung, chờ 20s; Indexer ghi `554` add và `550` Integrity checksum changed. Marker vẫn ở `/opt/wazuh-fim-lab/modified-marker.txt` để giữ bằng chứng/baseline; xóa sau khi không cần sẽ sinh `553`.
- Baseline 33 case rerun PASS: RAG 32/33 schema, 22/33 severity exact, mean 2.716s; no-RAG 33/33 schema, 19/33 severity exact, mean 2.428s. RAG `benign-23502-01` fallback `severity=unknown`.
- Human eval package: `eval/summarize_results.py` tổng hợp latency/schema/error/severity và điểm đã nhập; không tự sinh semantic score. Human reviewer và manual timing vẫn bắt buộc.
- Full verification increment: compileall PASS, `21 passed`, summary tool PASS, 3 attack scripts + hook syntax PASS, `git diff --check` PASS; chỉ CRLF warnings.
- AI judge implementation hoàn tất: `eval/judge_results.py` dùng model khác candidate, strict 5-score schema, hashes, resume, file AI-only riêng; summary hỗ trợ `--ai-judgments`; `26 passed`.
- AI scoring hoàn tất: `CyberCrew/notmythos-8b`, prompt `ai-judge-v1`, temperature 0, seed 20260729, 66/66 valid, 0 error. RAG mean 3.44, no-RAG 3.42; paired 8/18/7 win/tie/loss. Đây là AI-only score, không đổi human columns hoặc expected review status.
- Manual runbook hoàn tất tại `docs/manual-test.md`, link từ README/setup/attacks/eval; gồm từng máy, exact command, expected result, timing, troubleshooting, cleanup, AI/human evaluation.
- Verification AI/runbook: compileall PASS, `26 passed`, AI summary coverage 66 PASS, shell syntax PASS, `git diff --check` PASS; secret scan chỉ thấy documented default placeholder và config path, không có live credential.
- Next: stage reviewed files và commit checkpoint; chưa push.

## Trạng thái

- Live Wazuh → Indexer → RAG → Ollama: đã xác minh.
- Hardening pipeline và script lab: đã làm, test pass.
- GĐ4 core: hoàn tất 33 case, ground truth review kỹ thuật, rubric, runner, baseline RAG/no-RAG và AI-only scoring 66 output.
- Còn human review/scoring và đo thời gian phân tích tay; không phải blocker code.

## GĐ4 hiện tại

Files:

- `eval/cases/*.json`: 33 alert `sanitized-live`.
- `eval/expected/*.json`: ground truth nháp.
- `eval/manifest.json`: case registry.
- `eval/rubric.md`: chấm 5 tiêu chí, thang 1–5; tách AI/human protocol.
- `eval/run_eval.py`: runner dùng extractor/RAG/Ollama hiện có.
- `eval/results.csv`: `qwen2.5:7b` + RAG.
- `eval/results-no-rag.csv`: cùng model, không RAG.
- `eval/ai-judgments-notmythos-8b.csv`: 66 AI-only judgments.
- `eval/judge_results.py`: strict AI rubric judge.
- `eval/summarize_results.py`: baseline/human/AI summary.
- `eval/baseline.md`: metric và giới hạn kết luận.
- `eval/build_dataset.py`: tái tạo snapshot từ live Indexer.
- `tests/test_eval_dataset.py`, `tests/test_eval_grading.py`: corpus/scoring tests.

Corpus sau review:

- 33 case: SSH 12, FIM 3, web 3, benign 13, ambiguous 2.
- 19 rule ID; thêm web `31101/31151/31105` và 6 benign case `23502` CVE solved.
- Duplicate yếu đã giảm: PAM PID variants, `/bin` vs `/usr/bin` rootcheck, invalid-user variants.
- Sanitization không còn private IP thật, hostname thật, SSH fingerprint, `99-claude-lab`.
- `40112`: `ambiguous/high`, không còn `malicious/critical`.
- Benign `5715`, `5501`, `5402`, `23502`: expected MITRE rỗng.
- `5710` chỉ `Invalid user`: expected MITRE rỗng; `Failed password` variant vẫn giữ mapping.
- `554`, `503`, `506`, `553`: root cause không bịa nguyên nhân ngoài alert.

Baseline tuần tự ngày 2026-07-29:

| Chỉ số | RAG | No-RAG |
|---|---:|---:|
| Hoàn tất | 33/33 | 33/33 |
| Schema valid | 32/33 | 33/33 |
| Lỗi gọi model | 0 | 0 |
| Mean latency | 2.716s | 2.428s |
| Median latency | 2.704s | 2.410s |
| p95 latency | 3.897s | 3.304s |
| Severity exact-match draft | 22/33 | 19/33 |
| AI-only overall mean | 3.44/5 | 3.42/5 |

AI paired: RAG thắng 8, hòa 18, no-RAG thắng 7. Không kết luận RAG tốt hơn từ một lượt stochastic và một AI judge; vẫn cần human semantic scoring.

## Verification gần nhất

```text
python -m compileall -q ai_module eval tests: PASS
PYTHONPATH=ai_module python -m pytest tests -q: 26 passed trước runbook; chạy lại verification cuối sau docs.
bash -n scripts/attacks/fim-trigger.sh scripts/attacks/ssh-bruteforce.sh: PASS
git diff --check: PASS; chỉ có CRLF warnings
RAG baseline: 30/30 completed
No-RAG baseline: 30/30 completed
```

## Việc tiếp theo

1. Reviewer người thứ hai chấm/adjudicate `eval/expected/*.json` và 66 output; AI score hiện có chỉ là benchmark phụ.
2. Đo baseline phân tích tay trên cùng 33 case theo `docs/manual-test.md`.
3. Nếu cần model candidate đối chứng, chạy cùng corpus/prompt/config; không dùng judge score như human ground truth.
4. Windows Sysmon chưa có scenario/config canonical; chỉ Windows Wazuh agent đã Active.
5. Chạy `git config core.hooksPath .githooks` nếu clone mới chưa bật ledger gate.
6. Review/stage đúng file trước commit; không stage `.claude/`, `.bak` hoặc `create_rag_data.py` mù.

## Lệnh tiếp tục

```bash
git status --short
git diff --check
python -m compileall -q ai_module eval tests
PYTHONPATH=ai_module python -m pytest tests -q
bash -n scripts/attacks/fim-trigger.sh scripts/attacks/ssh-bruteforce.sh
```

Regenerate corpus chỉ khi muốn snapshot mới; lệnh này xóa/rewrite `eval/cases` và `eval/expected`:

```powershell
python eval/build_dataset.py
python eval/run_eval.py --model qwen2.5:7b --results eval/results.csv
python eval/run_eval.py --model qwen2.5:7b --no-rag --results eval/results-no-rag.csv
```

## Lab

- SIEM `192.168.100.10`, user `wazuh`.
- Victim `192.168.100.20`, user `trnguyn`, Wazuh agent active.
- Kali `192.168.100.30`, user `kali`.
- Host Ollama `192.168.100.1`.
- SSH key `C:\Users\Tplab\.ssh\id_ed25519`.
- Live config `ai_module/config.yaml` chứa credentials, gitignored; không print/commit.

Observed rules: SSH `5503/5760/2502/5710/5712/40112`; FIM `554/553`; benign/context `5501/5502/5402/5715/503/23502`; ambiguous `506/510`.

## Untracked từ trước — không xóa/commit mù

```text
.claude/
ai_module/create_rag_data.py
ai_module/main.py.bak
ai_module/rag.py.bak
```

`create_rag_data.py` có thể ghi đè corpus RAG. `.bak` là code cũ.

## Model preference

Subagent mặc định Opus; Sonnet/Haiku chỉ task rất nhẹ.
