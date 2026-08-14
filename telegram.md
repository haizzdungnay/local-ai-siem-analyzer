# Kế hoạch tích hợp Telegram vào hệ thống thông báo

## 1. Mục tiêu

Cho phép người vận hành nhận báo cáo SIEM qua Telegram Bot theo cơ chế opt-in.
Với từng job thủ công hoặc lịch tự động, người dùng chọn một trong hai giá trị:

- `Không gửi` (`none`)
- `Telegram bot` (`telegram`)

Khi job kết thúc ở trạng thái `succeeded` hoặc `partial`, hệ thống xếp một
delivery vào hàng đợi và gửi một tin tóm tắt đã che dữ liệu nhạy cảm kèm file
PDF đầy đủ trong phạm vi allow-list tới chat đã cấu hình. PDF có dashboard
overview và Alert map dạng đồ họa. Job `failed`, `cancelled` hoặc không có alert
không tự gửi. Lỗi Telegram không được làm thay đổi kết quả phân tích AI đã lưu.

File này là kế hoạch kỹ thuật và checklist nghiệm thu đầy đủ. Hướng dẫn vận hành
ngắn gọn sau triển khai nằm tại `docs/telegram.md`.

## 2. Trạng thái hiện tại

Phần Telegram đã được triển khai theo kiến trúc trong kế hoạch này:

- [x] Có `TelegramNotifier` gọi Telegram Bot API theo chiều outbound.
- [x] Secret nằm trong `ai_module/telegram.local.env` đã gitignore hoặc biến môi
  trường của process.
- [x] Dashboard có form nhập bot token/chat ID, status và nút gửi test.
- [x] Job thủ công và lịch tự động chọn được `none` hoặc `telegram`.
- [x] Job thành công tự enqueue delivery; job hoàn tất có nút gửi thủ công.
- [x] Có delivery worker, audit SQLite, retry thủ công và recovery
  `sending -> uncertain` sau restart.
- [x] Gửi summary ngắn bằng `sendMessage` và PDF đầy đủ bằng `sendDocument`.
- [x] PDF dùng card/table hierarchy như Gmail HTML, có dashboard overview và
  Alert map đồ họa tối đa 48 bucket, không lặp text map 48 dòng.
- [x] Đã smoke test Job `#36` delivery `#7`: attempt `2/3` nhận summary + PDF
  cũ; attempt `3/3` nhận summary nhưng PDF timeout và được đánh dấu `uncertain`,
  không chạy lại AI/job.
- [x] Có unit/API/store/worker/UI test và helper tìm chat ID/gửi test.

Các bước kiểm thử live vẫn phải thực hiện lại khi thay bot token, chat ID, mạng
hoặc chính sách Telegram.

## 3. Phạm vi và nguyên tắc

### 3.1 Trong phạm vi

- Gửi summary ngắn bằng `sendMessage` và báo cáo đầy đủ dạng PDF bằng
  `sendDocument`.
- Hỗ trợ chat riêng, group hoặc supergroup có numeric chat ID hợp lệ.
- Cài đặt credential/destination trên dashboard local.
- Gửi message kiểm tra tĩnh trước khi bật gửi report.
- Tự gửi theo job/lịch đã opt-in và gửi thủ công cho job hoàn tất.
- Lưu audit delivery nhưng không lưu message body hoặc credential.
- Phân loại kết quả `sent`, `failed`, `uncertain` và retry có xác nhận.

### 3.2 Ngoài phạm vi

- Nhận lệnh từ Telegram, webhook hoặc long-polling trong dashboard runtime.
- Cho bot điều khiển Wazuh, Ollama, job hoặc lịch.
- Gửi raw alert, raw log, prompt hoặc chain-of-thought.
- Nhiều chat ID cho cùng một cấu hình.
- Bot command menu, callback button, inline keyboard hoặc message editing.
- Auto-retry không cần người vận hành xác nhận.

Giới hạn này giữ bề mặt tấn công nhỏ: dashboard chỉ phát outbound report đã
redact và không mở thêm một kênh điều khiển từ Internet vào máy local.

## 4. Quyết định kỹ thuật

### 4.1 Telegram Bot API

- Endpoint gửi: `POST https://api.telegram.org/bot<TOKEN>/sendMessage`.
- Endpoint file: `POST https://api.telegram.org/bot<TOKEN>/sendDocument` với
  multipart PDF sinh cục bộ.
- Request dùng JSON, không đưa token vào body hoặc log.
- Không bật `parse_mode`; gửi plain text để tránh lỗi/injection Markdown hoặc
  HTML từ nội dung do model sinh ra.
- Đặt `disable_web_page_preview: true` để URL trong summary không tạo preview
  ngoài ý muốn.
- Không theo HTTP redirect để token không bị chuyển sang host khác.
- Connect timeout 5 giây; read timeout mặc định 15 giây và giới hạn 3..60 giây.
- Summary giới hạn cấu hình mặc định 3.500 ký tự, luôn thấp hơn giới hạn 4.096
  ký tự của Telegram. Full report không bị cắt vào summary mà nằm trong PDF,
  giới hạn 12 MiB trước khi upload.

### 4.2 Định danh đích

MVP chỉ chấp nhận numeric chat ID theo regex `-?[0-9]{1,20}`:

- Chat riêng thường dùng số dương.
- Group/supergroup thường dùng số âm.
- Không nhận username dạng `@name`, URL hoặc danh sách nhiều chat.

Người dùng phải chủ động gửi `/start` cho bot trong chat riêng, hoặc thêm bot vào
group rồi gửi một message để Telegram tạo update có chat ID.

### 4.3 Token

Token phải đúng cấu trúc cơ bản `<bot_id>:<secret>` và được validate trước khi
lưu/gọi API. Bất kỳ token nào từng được dán vào chat, terminal transcript, issue
hoặc file tracked đều phải revoke và tạo lại bằng `@BotFather`; xóa hội thoại
không thay thế việc rotate token.

## 5. Trải nghiệm người dùng

### 5.1 Tạo job thủ công

Dropdown `Nhận báo cáo` có:

- `Không gửi`
- `Telegram bot`

Nếu chọn Telegram nhưng notifier chưa `enabled` hoặc chưa `configured`, backend
từ chối tạo job với lỗi rõ ràng. Frontend không được tự đổi lựa chọn của người
dùng.

### 5.2 Lịch tự động

Dropdown `Gửi mỗi cửa sổ` lưu `delivery_channel` cùng interval, model và ngôn
ngữ. Mỗi scheduled job sao chép channel từ generation lịch tương ứng.

Polling trạng thái không được ghi đè model, ngôn ngữ hoặc kênh gửi đang được
người dùng chỉnh trước khi bấm `Lưu lịch`.

### 5.3 Cài đặt Telegram

Card `Telegram delivery` hiển thị các giá trị an toàn:

- `channel`
- `enabled`
- `configured`
- `max_message_chars`

Nút `Cài đặt Telegram` mở dialog nhập:

- Bot token bằng input `type="password"`.
- Numeric chat ID bằng input text có pattern số âm/dương.

Form không prefill dữ liệu đã lưu. Khi lưu, API chỉ trả trạng thái an toàn, không
trả bot token hoặc chat ID. Notifier đọc file local ở mỗi lần kiểm tra/gửi nên
không cần restart sau khi đổi cấu hình.

### 5.4 Gửi test và report thủ công

- `Gửi test Telegram` gửi đúng một message cố định, không chứa dữ liệu SIEM.
- Job `succeeded/partial` có action `Gửi Telegram` với hộp xác nhận.
- Job đã có delivery cùng channel không tạo row trùng.
- Delivery `failed/uncertain` có action retry với cảnh báo có thể tạo message
  trùng nếu provider đã nhận request trước khi kết nối lỗi.

## 6. Luồng kiến trúc

```text
Dashboard local
    |
    +-- Lưu settings ----------> telegram.local.env (gitignored)
    |
    +-- Tạo job/lưu lịch ------> jobs/schedule.delivery_channel
                                      |
                               worker phân tích AI
                                      |
                          job succeeded hoặc partial
                                      |
                          report_deliveries (pending)
                                      |
                              delivery worker
                                      |
                         TelegramNotifier.send_report
                                      |
                            Telegram Bot API
                                      |
                         sent / failed / uncertain
```

Phân tích AI và outbound delivery là hai transaction/worker độc lập. Một report
đã phân tích thành công vẫn giữ trạng thái thành công nếu Telegram lỗi.

## 7. Cấu hình và secret

### 7.1 `config.example.yaml`

Cấu hình không chứa secret:

```yaml
notifications:
  telegram:
    enabled: false
    env_file: "telegram.local.env"
    token_env: "SIEM_TELEGRAM_BOT_TOKEN"
    chat_id_env: "SIEM_TELEGRAM_CHAT_ID"
    max_message_chars: 3500
    timeout_seconds: 15
```

`enabled: false` là mặc định an toàn. File local có thể bật riêng bằng
`SIEM_TELEGRAM_ENABLED=true` mà không phải ghi secret vào YAML.

### 7.2 File local

Template `ai_module/telegram.local.env.example`:

```text
# Copy thành telegram.local.env; file thật phải được gitignore.
SIEM_TELEGRAM_ENABLED=true
SIEM_TELEGRAM_BOT_TOKEN=
SIEM_TELEGRAM_CHAT_ID=
```

Yêu cầu đối với `ai_module/telegram.local.env`:

- File thật nằm trong `.gitignore`.
- Chỉ được resolve bên trong `ai_module`; từ chối path traversal hoặc symlink ra
  ngoài module.
- Giới hạn tối đa 16 KiB.
- Mỗi dòng phải là `KEY=VALUE`, key phải đúng pattern biến môi trường.
- Tên biến token/chat ID/enabled không được trùng.
- Khi lưu qua dashboard, ghi file tạm trong cùng thư mục rồi `os.replace()` để
  bảo đảm atomic.
- Cố gắng đặt mode `0600`; trên Windows dùng ACL kế thừa và không fail setup nếu
  POSIX mode không áp dụng.
- Không log, export, lưu SQLite hoặc phản chiếu credential/destination qua API.

Biến môi trường process được ưu tiên hơn file local để hỗ trợ triển khai bằng
secret manager sau này.

## 8. Backend theo file

### 8.1 `ai_module/telegram_notifier.py`

Module chịu trách nhiệm độc lập cho provider:

- `TelegramSettings`: enabled, tên env, path, message limit và timeout.
- `settings_from_config()`: validate cấu hình ngay khi runtime khởi tạo.
- `load_env_file()`: đọc file local có giới hạn và không thực thi nội dung.
- `status()`: chỉ trả metadata an toàn.
- `configure_local()`: validate token/chat ID, ghi atomic và không trả secret.
- `discover_chats()`: đọc tối đa 20 update gần đây cho helper setup; không expose
  endpoint này trên dashboard.
- `render_report()`: tạo plain-text allow-list và payload SHA256.
- `_post()`: gọi Bot API, cấm redirect và map lỗi sang code ổn định.
- `send_test()`: gửi message kiểm tra tĩnh.
- `send_report()`: gửi report đã redact và trả `message_id/payload_sha256`.

HTTP session được inject qua constructor để unit test không gọi mạng thật.

### 8.2 `ai_module/dashboard_worker.py`

- Runtime khởi tạo một `TelegramNotifier`.
- Delivery worker chạy độc lập với analysis worker và scheduler.
- Sau khi lưu thành công analysis, job có channel `telegram` được enqueue.
- Delivery worker claim một row `pending`, lấy job detail rồi gọi notifier.
- Chỉ job `succeeded/partial` được gửi.
- Exception provider được chuyển thành `failed/uncertain`; exception không mong
  đợi chỉ log job/delivery ID, không log URL chứa token hoặc response body.
- Store finalization lỗi thì delivery thành `uncertain`; worker vẫn tiếp tục.

### 8.3 `ai_module/dashboard_store.py`

Schema v5 bổ sung:

- `jobs.delivery_channel IN ('none','telegram')`.
- `schedule.delivery_channel IN ('none','telegram')`.
- `report_deliveries.channel IN ('telegram')`.
- `UNIQUE(job_id, channel)` để chống enqueue trùng.

Audit row chỉ lưu:

| Trường | Ý nghĩa |
|---|---|
| `job_id`, `channel` | Job và provider |
| `status` | `pending/sending/sent/failed/uncertain` |
| `attempt_count` | Số lần worker đã claim để gửi |
| `payload_sha256` | Hash message đã redact |
| `provider_message_id` | Telegram message ID, tối đa 80 ký tự |
| `error_code` | Mã lỗi an toàn, không chứa response text |
| timestamp | created/updated/sent time |

Không lưu message text, bot token hoặc chat ID. Delivery bị xóa cascade khi job
bị prune theo retention.

State transition:

```text
pending -> sending -> sent
                   -> failed -----> pending (retry thủ công)
                   -> uncertain --> pending (retry thủ công)

sending --restart--> uncertain
```

Retry chỉ áp dụng cho `failed/uncertain` và tối đa ba attempt.

### 8.4 `ai_module/dashboard.py`

Các API:

- `GET /api/notifications/status`
- `POST /api/notifications/telegram/settings`
- `POST /api/notifications/telegram/test`
- `POST /api/jobs/<id>/delivery`
- `POST /api/deliveries/<id>/retry`

Mọi POST kiểm tra same-origin, JSON body có giới hạn và yêu cầu `confirm: true`
cho thao tác lưu credential/gửi/retry.

Payload lưu settings:

```json
{
  "bot_token": "<bot-token>",
  "chat_id": "<numeric-chat-id>",
  "confirm": true
}
```

Response không phản chiếu input:

```json
{
  "status": "saved",
  "telegram": {
    "channel": "telegram",
    "enabled": true,
    "configured": true,
    "max_message_chars": 3500
  }
}
```

`_resolve_delivery_channel()` chỉ nhận `none/telegram` và yêu cầu Telegram đã
bật/cấu hình trước khi tạo job hoặc lưu lịch.

### 8.5 Frontend

`ai_module/web/index.html`:

- Option Telegram trong job/schedule dropdown.
- Card status/settings/test.
- Dialog credential không prefill và có accessibility label.

`ai_module/web/app.js`:

- `loadTelegramStatus()` lấy status và bật/tắt nút test.
- Form settings gửi JSON rồi reset input.
- Test/send/retry đều có confirm và thông báo kết quả.
- Job detail render audit delivery, `Gửi Telegram` và `Retry Telegram`.
- Polling không được ghi đè draft model/channel của form lịch.

`ai_module/web/styles.css`:

- Form settings hai cột trên desktop, một cột trên mobile.
- Dialog và action giữ cùng visual language với dashboard hiện tại.

### 8.6 Helper và tài liệu

`scripts/telegram_setup.py` hỗ trợ:

- Gửi test message tĩnh với cấu hình local.
- `--discover-chats` đọc update gần đây sau khi người dùng gửi `/start`.
- Không nhận token qua command-line argument để tránh lưu trong shell history.
- Không in token; chat ID chỉ hiện khi người dùng chủ động chạy discovery.

`docs/telegram.md` hướng dẫn setup, lấy chat ID, gửi test, chọn channel, retry và
quy tắc bảo mật.

## 9. Hợp đồng nội dung report

`render_summary_report()` đọc phần cần thiết cho tin tóm tắt; `render_report()`
và `telegram_pdf.render_pdf_report()` dùng cùng bản rich report với Gmail cho
phần PDF:

- Job ID, status, cửa sổ thời gian, model và ngôn ngữ.
- Metrics tổng alert/group/rule/agent/max level, confidence và rule ID nổi bật
  đã gộp.
- Severity, summary, root cause, key findings, MITRE và next steps có giới hạn.
- Observed facts, inferences, uncertainties, limitations và warnings có giới
  hạn.
- Alert map/Mật độ alert theo thời gian dạng đồ họa trong PDF, tối đa 48 bucket;
  scale theo peak và chỉ ghi nhãn các bucket cao để vẫn đọc được ở hàng nghìn
  alert.
- SHA256 của analysis canonical.

Không đọc/không gửi:

- `job_alerts`, index name, document ID hoặc alert reference.
- Raw log, sample log, full Wazuh document.
- Source IP, IPv6, email address.
- Prompt, private reasoning, chain-of-thought hoặc tool trace.
- Credential, token, API key, password hoặc chuỗi inline secret.

Các trường text đi qua `_safe_text()` để:

- Ép kiểu an toàn và giới hạn độ dài.
- Loại control character.
- Redact IPv4/IPv6, email và pattern secret.
- Giới hạn summary ở `max_message_chars` và PDF ở 12 MiB trước khi upload.

Payload hash được tính trên summary và bytes PDF đã redact, giúp đối chiếu nội
dung đã gửi mà không cần lưu message body. Nếu summary đã được Telegram nhận
nhưng PDF lỗi, delivery là `uncertain` để retry thủ công không che giấu nguy cơ
message/file trùng.

## 10. Phân loại lỗi và retry

| Tình huống | Mã lỗi | Trạng thái |
|---|---|---|
| Telegram đang tắt/thiếu token-chat ID | `configuration` | `failed` |
| Connect/read timeout | `telegram_timeout` | `uncertain` |
| Lỗi mạng/connection | `telegram_network_error` | `uncertain` |
| HTTP 429 | `telegram_rate_limited` | `failed` |
| HTTP 5xx | `telegram_provider_error` | `uncertain` |
| HTTP 4xx khác | `telegram_http_<code>` | `failed` |
| JSON không hợp lệ | `telegram_invalid_response` | `failed` |
| PDF không thể tạo | `telegram_pdf_generation` | `failed` |
| PDF vượt giới hạn | `telegram_pdf_size_limit` | `failed` |
| Summary đã gửi, PDF lỗi | `telegram_partial_<provider_code>` | `uncertain` |
| Bot API trả `ok != true` | `telegram_api_<code>` | `failed` |
| Exception không dự kiến | `unexpected_error` | `failed` |
| Restart khi đang `sending` | `recovered_in_flight` | `uncertain` |

Timeout/network/5xx là `uncertain` vì Telegram có thể đã nhận request trước khi
client biết kết quả. Không auto-retry các trường hợp này. Người vận hành retry
thủ công và chấp nhận khả năng có hai message giống nhau.

HTTP 429 hiện yêu cầu retry thủ công. Giai đoạn sau có thể lưu `retry_after` dạng
metadata an toàn và lên lịch backoff, nhưng không được block analysis worker.

## 11. Bảo mật

### 11.1 Secret handling

- Token không xuất hiện trong URL log, traceback, response API hoặc UI.
- Không log exception body từ thư viện HTTP vì URL exception có thể chứa token.
- File local được gitignore và không nằm trong report export/SQLite.
- Settings form không prefill; browser không giữ credential lâu hơn request.
- Token test/production phải tách riêng và rotate khi nghi ngờ lộ.

### 11.2 Destination safety

- Chỉ numeric chat ID đã validate.
- Test message cố định giúp xác nhận đúng chat trước khi gửi report thật.
- Khuyến nghị chat riêng hoặc group đã được phê duyệt cho SOC.
- Khi đổi chat ID, gửi test lại trước khi bật lịch tự động.
- Bot trong group chỉ cần quyền gửi message; không cấp quyền admin không cần
  thiết.

### 11.3 Outbound data safety

- Dùng allow-list thay vì lấy full job rồi blacklist một số trường.
- Plain text, không preview, không attachment.
- Giới hạn độ dài ở từng trường và toàn message.
- Không nhận inbound command/webhook nên bot không thể điều khiển dashboard.

## 12. Kế hoạch kiểm thử

### 12.1 Unit test notifier

`tests/test_telegram_notifier.py` cần bao phủ:

- Config mặc định/override và validation type/range.
- Env path chỉ nằm trong module, file size/key/syntax hợp lệ.
- Env process ưu tiên hơn file local.
- Token/chat ID hợp lệ và các input xấu bị từ chối.
- Ghi settings atomic, cleanup file tạm, status không lộ credential.
- Report allow-list, redaction, truncate và hash ổn định.
- `sendMessage` dùng JSON, không redirect, không `parse_mode`, tắt preview.
- Test message tĩnh.
- Mapping timeout/network/429/4xx/5xx/invalid JSON/API error.
- Chat discovery deduplicate và chỉ trả numeric ID/type an toàn.
- Không có token trong exception string hoặc test output.

HTTP session phải mock/fake hoàn toàn; unit test không gọi Telegram thật.

### 12.2 Store và worker

`tests/test_dashboard_store_worker.py`:

- Schema/migration tạo đúng delivery columns và checks.
- Enqueue chỉ cho job `succeeded/partial`.
- `UNIQUE(job_id, channel)` chống row trùng.
- Claim tăng attempt và chuyển `pending -> sending` atomic.
- Mark sent lưu hash/message ID; mark problem chỉ nhận mã an toàn.
- Retry chỉ cho `failed/uncertain`, tối đa ba attempt.
- Restart chuyển `sending -> uncertain`.
- Worker gửi đúng job, provider lỗi không làm chết thread.
- Analysis thành công không bị đổi trạng thái khi enqueue/send lỗi.
- Job rỗng/failed/cancelled không tự gửi.

### 12.3 API

`tests/test_dashboard_api.py`:

- Channel mặc định `none`.
- Chọn Telegram bị từ chối khi tắt/thiếu cấu hình.
- Settings/test yêu cầu same-origin, JSON và `confirm: true`.
- Response settings/status không chứa token/chat ID.
- Test route map status code an toàn.
- Manual delivery chỉ cho terminal job và không enqueue trùng.
- Retry route có confirm và giới hạn trạng thái/attempt.

### 12.4 UI và regression

`tests/test_dashboard_ui.py` cùng kiểm tra thủ công:

- Đủ dropdown option, card, dialog, input và button ID.
- JavaScript gọi đúng endpoint settings/test/delivery/retry.
- Form reset sau save/close và không prefill credential.
- Model/channel lịch đang chỉnh không bị polling ghi đè.
- Nút test bị disable khi chưa configured.
- Layout sử dụng được trên desktop/mobile và thao tác bàn phím.
- `node --check ai_module/web/app.js`.
- `python -m compileall ai_module scripts`.
- Chạy full `pytest` và secret scan trước bàn giao.

### 12.5 Live smoke test

Chỉ chạy khi người vận hành xác nhận bot/chat đích:

1. Revoke token từng bị lộ và tạo token mới.
2. Gửi `/start` cho bot hoặc một message trong group.
3. Lưu token/chat ID bằng dashboard hoặc file local.
4. Gửi test tĩnh và xác nhận message đến đúng chat.
5. Chạy một job nhỏ chọn Telegram.
6. Theo dõi audit `pending -> sending -> sent`, attempt bằng 1.
7. Đối chiếu summary đã redact, file PDF mở được với dashboard overview/Alert
   map đồ họa và payload hash được lưu.
8. Restart dashboard, xác nhận delivery `sent` không bị gửi lại.
9. Thử đổi chat ID, gửi test lại và xác nhận notifier đọc cấu hình mới.

Không ghi token/chat ID thật vào tài liệu, ảnh chụp, terminal output hoặc bản bàn
giao.

## 13. Thứ tự triển khai chuẩn

### Giai đoạn 1 - Cấu hình và provider adapter

- Thêm config example, env example và `.gitignore`.
- Implement validation, local file, Bot API client, test/discovery và report
  formatter.
- Hoàn thiện unit test không dùng mạng thật.

Điều kiện qua giai đoạn: test notifier pass, không có secret trong diff/log/API.

### Giai đoạn 2 - Durable delivery

- Nâng schema, thêm `delivery_channel` và `report_deliveries`.
- Implement enqueue/claim/finalize/retry/recovery.
- Tách delivery worker khỏi analysis worker.

Điều kiện qua giai đoạn: migration/store/worker test pass và lỗi Telegram không
ảnh hưởng analysis result.

### Giai đoạn 3 - API và dashboard

- Thêm status/settings/test API.
- Mở channel Telegram cho manual job, schedule và completed job.
- Thêm card/dialog/actions/audit cùng guard không overwrite form lịch.

Điều kiện qua giai đoạn: API/UI test pass, desktop/mobile dùng được.

### Giai đoạn 4 - Tài liệu và live validation

- Hoàn thiện helper, README, changelog, handoff và hướng dẫn vận hành.
- Chạy full regression, syntax/compile check và secret scan.
- Gửi test/report thật sau khi người vận hành xác nhận destination.

### Giai đoạn 5 - Vận hành sau triển khai

- Theo dõi delivery `failed/uncertain`, rate limit và attempt count.
- Rotate token định kỳ hoặc ngay khi nghi ngờ lộ.
- Gửi test lại sau mọi thay đổi bot/chat ID/network.
- Review allow-list mỗi khi schema report AI bổ sung trường mới.

## 14. Tiêu chí hoàn thành

- Người dùng chọn được `Không gửi` hoặc `Telegram bot` cho job và lịch.
- Backend không chấp nhận Telegram khi chưa bật/cấu hình.
- Settings lưu local, không cần restart và không phản chiếu token/chat ID.
- Test Telegram chỉ gửi message tĩnh.
- Job `succeeded/partial` tự enqueue; job rỗng/failed/cancelled không tự gửi.
- Delivery có audit, hash, message ID, attempt, retry và recovery `uncertain`.
- Summary và PDF chỉ chứa allow-list đã redact; PDF có dashboard overview và
  Alert map đồ họa scale theo peak, không chứa timeline text fallback.
- Lỗi provider không thay đổi kết quả AI hoặc làm chết delivery worker.
- Polling không ghi đè model/kênh đang chỉnh trong lịch.
- Unit/API/store/worker/UI test, compile, JavaScript check và secret scan đều
  pass.
- Live test xác nhận đúng chat và restart không gửi lại delivery đã hoàn tất.

## 15. Vận hành và xử lý sự cố

| Hiện tượng | Kiểm tra/giải pháp |
|---|---|
| `configured: false` | Kiểm tra đủ token/chat ID trong file local hoặc env process |
| Bot không gửi vào chat riêng | Gửi `/start`, sau đó gửi test lại |
| Bot không gửi vào group | Kiểm tra bot còn trong group, quyền gửi và numeric group ID âm |
| HTTP 401/404 | Token sai/đã revoke; tạo token mới và lưu lại |
| HTTP 400 | Chat ID sai hoặc bot không có quyền gửi tới chat |
| HTTP 429 | Chờ rate limit hết rồi retry thủ công |
| `telegram_pdf_generation` | Kiểm tra Pillow/font local và đọc error code an toàn trong audit |
| `telegram_pdf_size_limit` | Giảm phạm vi report hoặc kiểm tra giới hạn nội dung PDF |
| `uncertain` | Kiểm tra chat trước; chỉ retry nếu chấp nhận nguy cơ message trùng |
| Đổi chat ID nhưng vẫn gửi chỗ cũ | Refresh status, gửi test; kiểm tra env process có đang override file local |
| File settings không lưu được | Đóng editor đang lock file và kiểm tra quyền ghi `ai_module` |

## 16. Tương thích với kế hoạch Gmail

Khi triển khai `gmail.md`, Telegram phải tiếp tục hoạt động mà không đổi contract
công khai. Các phần nên dùng chung là safe report DTO/redaction, exception nền,
notifier registry, delivery worker và danh sách audit theo channel. Credential,
formatter, provider client, test connection và tài liệu vận hành vẫn tách riêng
cho từng kênh.

Mỗi job/lịch tiếp tục chọn đúng một kênh tự động: `none`, `telegram` hoặc
`gmail`. Gửi thủ công qua kênh còn lại có thể tạo audit row riêng nhờ khóa
`UNIQUE(job_id, channel)` sau migration Gmail.
