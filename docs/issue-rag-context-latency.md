# Issue: Đo và đảm bảo thời gian nạp/đọc RAG + phân tích, và bảo đảm model (local/cloud) nhận đủ ngữ cảnh

> Tiêu đề đề xuất: `RAG/context: đo thời gian từng bước, ép model nhận đủ ngữ cảnh (local + cloud), model 9b không được kém 7b`
> Nhãn đề xuất: `rag`, `performance`, `quality`, `model`
> Trạng thái: đã tạo thành [issue #34](https://github.com/haizzdungnay/local-ai-siem-analyzer/issues/34).

## 1. Vấn đề

1. **Không biết thời gian đi đâu.** Một lượt phân tích gồm: đọc alert từ Indexer → gom nhóm → embedding + truy vấn RAG → dựng prompt → LLM. Chỉ có `total_duration`/`load_duration`/`prompt_eval_*`/`eval_*` của Ollama (`ai_module/llm.py:671`, `dashboard_reports.py:262`). Không có thời gian riêng cho embedding, truy vấn Chroma, và tổng prompt trước khi gọi model. Không phân biệt được RAG chậm, nạp model nguội, hay model sinh chậm.
2. **Không có bằng chứng model đã đọc hết ngữ cảnh.** `num_ctx` được đặt ở nhiều nơi với giá trị khác nhau: mặc định `OLLAMA_OPTIONS` 8192 (`llm.py:40`), config `ollama.analysis.num_ctx` 16384, và `adaptive_pacing_options()` chọn 4096/8192/16384 theo VRAM (`llm.py:318`). Prompt (cửa sổ alert tối đa 64.000 ký tự + RAG tối đa 12.000 ký tự, `analysis_service.py:30`) không được so với `num_ctx` trước khi gọi. Khi vượt, Ollama hoặc báo 400 (đã gặp ở 8426 token > 8192, HANDOFF 2026-10-21) hoặc cắt ngữ cảnh mà không báo. Hiện `prompt_eval_count` có ghi vào provenance nhưng không được đối chiếu với độ dài prompt dự kiến.
3. **Model 9b cho kết quả kém hơn 7b.** `qwen35-9b-pentest-v5` (GGUF Q4_K_M) trả chất lượng thấp hơn `qwen2.5:7b` trên cùng đầu vào. Đây không chấp nhận được: model lớn hơn/chuyên biệt hơn không được phép kém baseline. Chưa có bảng so sánh đối chứng có kiểm soát để tìm nguyên nhân (cắt ngữ cảnh, thinking, lượng tử hóa, prompt/schema không hợp, `num_predict` thấp).
4. **Chưa có cơ chế cho model cloud.** Chỉ có Ollama (`ollama.Client.chat`). Roadmap `docs/hybrid-ai-gateway-roadmap.md` mới là kế hoạch; mọi thứ liên quan đến `num_ctx`, `keep_alive`, `num_batch`, pacing là riêng của Ollama và không áp dụng cho cloud. Cloud vẫn có giới hạn context/output/rate riêng và độ trễ mạng, nên cần cùng một hợp đồng "đủ ngữ cảnh" độc lập provider.

## 2. Mục tiêu

- Mỗi lượt phân tích có **bảng thời gian theo giai đoạn** và **ngân sách thời gian** kiểm chứng được cho local và cloud.
- Mọi provider/model chỉ trả kết quả "hoàn chỉnh" khi **bằng chứng cho thấy toàn bộ ngữ cảnh đã nạp được xử lý**; ngược lại trạng thái phải là `partial`/lỗi rõ ràng, không im lặng.
- `qwen35-9b-pentest-v5` (hoặc bất kỳ model lớn hơn) **không được là mặc định/được chọn** nếu chưa đạt tối thiểu bằng `qwen2.5:7b` trên bộ eval chung.

## 3. Yêu cầu

### 3.1 Đo thời gian (mọi provider)

Ghi vào provenance/job (không ghi nội dung alert, prompt, RAG text hay khóa API):

| Giai đoạn | Ghi nhận |
|---|---|
| Đọc Indexer | ms, số alert, cờ truncated |
| Gom nhóm/dựng aggregate | ms, số nhóm vào prompt |
| RAG embedding | ms mỗi truy vấn, số truy vấn |
| RAG truy vấn Chroma | ms, số chunk, `context_chars`, trạng thái |
| Dựng prompt | ms, ký tự, **token ước lượng** |
| Gọi model | ms; Ollama: `load_duration`, `prompt_eval_duration`, `eval_duration`; cloud: TTFB và tổng |
| Tổng | ms end-to-end, độ trễ vào hàng đợi |

Ngân sách đề xuất (cần xác nhận bằng đo thật trên lab, đây không phải kết quả đã đo): cửa sổ lab ~250 alert, `qwen2.5:7b` đã nạp sẵn (`keep_alive` 15m) hoàn tất < 60 giây; RAG (embedding + truy vấn) < 3 giây; cảnh báo khi vượt ngân sách. Tách số liệu "model nguội" và "model nóng". Tham chiếu: job 265 trên 240 alert mất ~27,5 giây.

### 3.2 Bảo đảm đủ ngữ cảnh

- **Pre-flight**: ước lượng token của (system + window + RAG + schema) rồi so với giới hạn *thực tế* của model/provider. Không dùng giá trị mặc định ngầm; `num_ctx` gửi đi phải là một nguồn duy nhất (config → clamp theo model/VRAM), có chỗ ghi lại trong provenance.
- **Post-flight (Ollama)**: so `prompt_eval_count` với ước lượng; chênh lệch bất thường hoặc `done_reason = length` → đánh dấu `context_truncated` / `partial`, không coi là thành công.
- **Hết ngân sách**: giảm có chủ đích theo thứ tự đã định (bớt nhóm ưu tiên thấp → rút gọn RAG theo `top_k`/độ liên quan), ghi rõ phần bị bỏ; không để model tự cắt.
- **Cloud**: adapter khai báo `max_context_tokens`, `max_output_tokens`, hỗ trợ structured output; pre-flight dùng các giá trị này (không dùng `num_ctx`/GPU). Dùng usage trả về (input/output tokens) để đối chiếu giống post-flight Ollama. Cloud tắt mặc định, chỉ bật theo opt-in rõ ràng, không fallback tự động giữa local và cloud, embedding RAG vẫn local (theo invariant của hybrid roadmap). Không gửi dữ liệu thô nhạy cảm nếu chưa có chính sách mask IP đã duyệt.
- **Canary kiểm tra "đã đọc hết"**: thêm test có dữ kiện đặt ở đầu, giữa và cuối ngữ cảnh (kể cả phần RAG); model phải tham chiếu đúng. Chạy trên local và cloud để phát hiện cắt/"lost in the middle".
- Kết quả phải ghi rõ RAG `used`/`partial`/`error` và số chunk thực sự vào prompt (đã có một phần ở provenance R0.3, cần nối với bước pre/post-flight).

### 3.3 Chất lượng model: 9b không được thua 7b

- Chạy `qwen35-9b-pentest-v5` và `qwen2.5:7b` trên **cùng** bộ ca (eval hiện có, RAG bật/tắt), cùng `num_ctx` ≥ prompt, `think=False`, cùng seed/temperature; so severity (độ chính xác, confusion matrix), schema hợp lệ, tỉ lệ fallback, độ trễ.
- Loại trừ lần lượt các nguyên nhân: (a) prompt bị cắt do `num_ctx`; (b) thinking/`num_predict` làm hết token (đã từng xảy ra); (c) lượng tử hóa Q4_K_M; (d) fine-tune làm lệch schema; (e) prompt/schema tối ưu cho 7b.
- Nếu sau điều chỉnh vẫn thấp hơn 7b: bỏ khỏi danh sách chọn mặc định/`allowed_models` của luồng phân tích, ghi lý do. Không đưa model nào vào mặc định khi chưa có bảng so sánh.

## 4. Tiêu chí nghiệm thu

- [ ] Mỗi job/provenance có đủ bảng thời gian ở 3.1; có test xác nhận các trường tồn tại và không chứa nội dung alert/prompt/khóa.
- [ ] Có số đo thực trên lab: model nguội/nóng, RAG bật/tắt, 3 cỡ cửa sổ (nhỏ/vừa/lớn tới ngưỡng cắt); lưu vào `eval/` kèm môi trường (GPU, quant, phiên bản Ollama).
- [ ] Pre-flight chặn/giảm có kiểm soát khi prompt vượt giới hạn; kết quả cắt ngữ cảnh luôn là `partial`, có test.
- [ ] Canary đầu/giữa/cuối pass trên `qwen2.5:7b` và model được chọn; có bản mock cho adapter cloud trong CI (không gọi mạng).
- [ ] Bảng so sánh 9b vs 7b trên cùng bộ ca; quyết định giữ/bỏ có ghi nguyên nhân.
- [ ] Đồng bộ `config.example.yaml`, README, `docs/manual-test.md`, hybrid roadmap; không ghi credential/IP live chưa sanitize.

## 5. Ngoài phạm vi

- Triển khai đầy đủ Model Gateway/quản lý khóa API (thuộc hybrid roadmap); issue này chỉ yêu cầu hợp đồng đo và đủ ngữ cảnh mà adapter phải tuân theo.
- Train/fine-tune lại model.

## 6. Liên quan

- `ai_module/llm.py` (`OLLAMA_OPTIONS`, `adaptive_pacing_options`, `_provenance`), `ai_module/analysis_service.py` (`MAX_WINDOW_RAG_CONTEXT_CHARS`, `_window_rag_context`), `ai_module/rag.py`.
- `docs/hybrid-ai-gateway-roadmap.md`, `docs/rag-evaluation-protocol.md`, HANDOFF mục "model qwen35-9b-pentest-v5 trên RTX 5070 Ti" (2026-10-21).
