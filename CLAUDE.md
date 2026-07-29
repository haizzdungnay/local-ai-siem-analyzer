# Project instructions

- Alert production path: Wazuh Indexer/OpenSearch `:9200`; Manager API `:55000` chỉ quản trị, không lưu alert.
- `qwen2.5:3b` dùng demo nhẹ; baseline GĐ4 dùng `qwen2.5:7b` RAG/no-RAG.
- Windows victim `.40` và Wazuh agent đã Active; Sysmon chưa xác nhận.
- Không ghi credentials, hostname/IP/fingerprint live chưa sanitized vào output tracked.
- Không chạy `eval/build_dataset.py` nếu không chủ ý rewrite `eval/cases/` và `eval/expected/`.

## Change protocol

1. Sau mỗi kết quả repo hoàn thành, cập nhật `CHANGELOG.md` mục `Unreleased` bằng thay đổi factual.
2. Ngay sau đó cập nhật `HANDOFF.md`: trạng thái, file/việc đã xong, verification, blocker/giới hạn và next action.
3. Nếu verification fail, ghi lỗi vào `HANDOFF.md`; không đánh dấu hoàn tất.
4. Khi đổi port/model/rule/trạng thái lab, search và đồng bộ docs, script, config comments liên quan.
5. Trước commit: review staged diff; stage cả `CHANGELOG.md` và `HANDOFF.md`.

Bật hook kiểm tra ledger một lần cho mỗi clone:

```bash
git config core.hooksPath .githooks
```
