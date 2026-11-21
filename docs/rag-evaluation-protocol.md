# RAG R0.3 evaluation protocol v2

Ngày cập nhật 2026-11-21. Issue #13, phối hợp playbook #23/#29 và protocol #27.

## Development và nghiệm thu độc lập

- `eval/rag_development_cases.json` là năm ca synthetic **development**, đã biết khi sửa code.
  Target lấy từ mapping corpus hoặc cố ý thiếu để đo coverage. Không có nhãn SOC độc lập.
- Không đọc nhãn `eval/cases`, `eval/expected`, `eval/stratified_370` hoặc local locked exports
  để chỉnh formatter, threshold, signal hay playbook. Không chạy `eval/build_dataset.py`.
- `eval/test_set_lock.json` giữ nhận dạng dữ liệu cũ, không chứng minh có split độc lập mới.
  Held-out mới cần người review độc lập chốt nguồn, nhãn, version/hash, danh sách split
  và tình trạng chưa dùng để tuning. Hiện **pending**, chưa có baseline nghiệm thu.
- Freeze playbook cuối phải thống nhất #23, sau đợt tín hiệu và trước đánh giá held-out.
  Snapshot development không chốt thay quyết định này.

## Corpus và context

| Nguồn | Field dùng | Section |
|---|---|---|
| Wazuh rule | description, text, MITRE, level, groups, frequency/timeframe, if_sid/if_matched_sid, file | overview |
| MITRE | name, description, tactics/tactic, subtechnique_of; text chỉ fallback thiếu description | overview |
| MITRE | detection | detection |
| MITRE | mitigation_details (ID/name/guidance), fallback mitigations | mitigations |

Mỗi document tối đa 2.000 ký tự, tối đa ba chunk/section, có cờ `section_truncated`.
ID root giữ `rule-5712`/`mitre-T1110`; phần tiếp dùng `:section:chunk` từ 0.
Schema 3 giữ file nguồn tương đối, record SHA-256, section, field có mặt trong từng chunk và corpus version/digest.
Context tối đa 12.000 ký tự trước khi đóng gói prompt. Chunk không vừa ngân sách được bỏ nguyên để giữ field provenance chính xác.
Mỗi reference trong context ghi `document_id` và `rendered_text_chars`. `top_k=3` mặc định tính cả exact và semantic chunks.
Exact ID vượt qua bộ lọc semantic và có `distance=null`. Exact MITRE ghi `lookup_basis=alert_annotation|kb_mapping`.
`mitre_grounding` phân biệt annotation của alert, suy luận từ mapping KB và suy luận chưa xác nhận.
`mitre_unverified` chỉ kiểm ID có trong catalog. Cả annotation lẫn mapping KB đều cần bằng chứng bổ sung để kết luận kỹ thuật đã xảy ra.

## Generation và model

Mỗi lượt build có collection staging và manifest tạm riêng. Chỉ publish sau khi đối chiếu đủ ID và digest.
Query giữ collection và manifest cùng generation trong suốt lượt đọc. `ensure_indexed()` nhận pointer mới và so lại corpus/digest.
Dashboard dùng được generation schema 3 tương thích khi rebuild lỗi và thử lại theo nhu cầu sau 30 giây.
Index schema cũ cần rebuild. Generation đã publish được giữ để reader đang chạy có thể đọc tiếp.
Digest lấy từ Ollama `list()` quanh các lần dùng vector. Nếu digest thiếu hoặc đổi, build dừng và query chỉ giữ kết quả exact có sẵn.
Ollama không trả digest gắn vào từng vector. Giữ nguyên tag trong lượt đo để tránh trường hợp tag đổi rồi quay lại giữa hai lần quan sát.

## Đo retrieval

So sánh semantic-only với exact + semantic trên cùng corpus/config/model digest, k = 1/3/5/10,
threshold cấu hình (mặc định 1.0). Không dùng expected MITRE IDs làm input query: `mitre_ids`
đầu vào phải có trong alert/development fixture; `targets` chỉ dùng sau truy xuất.
Khử trùng chunk về root source ID khi tính Hit@k, Recall@k, MRR.
Ghi retrieval recall, `context_recall` tính từ chunk thực sự vào context và coverage target có trong KB.
Giữ ca thiếu rule hoặc lỗi truy xuất trong mẫu.
Ghi status `used`, `partial`, `no_match`, `filtered_out`, `error`; `disabled` là trạng thái caller.
Báo per-case IDs/distances/method, số query lỗi, context budget; lỗi không loại khỏi mẫu.
N là số case, không phải số lần chạy. Không suy kết quả model/grounding hay SOC từ retrieval.

## Snapshot và output

Từ repo root, tạo snapshot development offline trước lượt đo:

```powershell
python eval/rag_retrieval_eval.py --freeze-only --output <new-snapshot.json>
```

Lượt embedding/retrieval thật, chỉ khi Ollama đã sẵn sàng và được phép dùng:

```powershell
python eval/rag_retrieval_eval.py --output <new-development-results.json>
```

Output dùng exclusive-create. Hai benchmark và `run_eval.py` dùng Chroma trong bộ nhớ và thư mục manifest riêng cho mỗi lượt.
Test integration của benchmark cũ cần `SIEM_RUN_LIVE_RAG_BENCHMARK=1` và Ollama đã sẵn sàng.
Runner development chỉ đọc development fixture,
không khởi động Ollama/lab hoặc gọi LLM sinh văn bản. Snapshot chứa Git HEAD, dirty flag và
hash file runtime/prompt/extractor/playbook/policy, config hash, corpus-source hashes,
protocol/hash, held-out lock/hash và model names. Khi đo thật thêm index manifest, embedding
digest và generator digest nếu quan sát được. Không ghi endpoint/credential/raw config hoặc alert.
Freeze-only không có digest quan sát, không phải baseline chốt. Hash file working tree giữ
đúng code chưa commit; trước đo chính thức phải commit/pin SHA và đối chiếu snapshot lần nữa.

## Nghiệm thu RAG R0.3

- [ ] Chạy năm ca development trên Ollama thật, ghi embedding digest, coverage, recall và `context_recall`.
  Đối chiếu ca có rule 5712, ca thiếu rule và trạng thái `no_match`/`disabled`.
- [ ] Freeze playbook với #23/#29 và khóa version/hash, nguồn, nhãn người và split held-out độc lập với #27.
- [ ] Chạy baseline chính thức bằng `qwen2.5:7b` trên SHA có CI xanh. Lưu output mới cùng config, corpus, prompt,
  extractor, playbook, protocol, held-out, digest của hai model, lệnh kiểm tra và giới hạn kết quả.

Theo dõi nghiệm thu Indexer/model/browser/report/SOC tại #32. Bản giao code R0.3 lưu bằng chứng regression,
khôi phục index và snapshot development trong `HANDOFF.md`.
