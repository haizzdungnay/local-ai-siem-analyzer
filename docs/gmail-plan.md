# Kế hoạch tích hợp Gmail vào hệ thống thông báo



## 1. Mục tiêu

Mở rộng cơ chế gửi báo cáo hiện tại để người vận hành có thể chọn đúng một trong
ba giá trị cho từng job hoặc lịch tự động:

- `Không gửi` (`none`)
- `Telegram bot` (`telegram`)
- `Gmail` (`gmail`)

Khi job kết thúc ở trạng thái `succeeded` hoặc `partial`, hệ thống xếp một
delivery vào hàng đợi và gửi báo cáo đầy đủ trong phạm vi allow-list đã che dữ
liệu nhạy cảm qua kênh được chọn. Job `failed`, `cancelled` hoặc báo cáo rỗng
không tự gửi. Việc gửi Gmail không được ảnh hưởng đến kết quả phân tích nếu nhà
cung cấp email gặp lỗi.

## 2. Hiện trạng cần giữ nguyên

- Dashboard chỉ chạy local/loopback và mọi API thay đổi trạng thái đều kiểm tra
  origin.
- Mỗi job và lịch hiện lưu một `delivery_channel`; đây là mô hình phù hợp với
  yêu cầu chọn một trong hai phương thức Telegram/Gmail.
- Telegram đã có hàng đợi `report_deliveries`, worker độc lập, trạng thái
  `pending/sending/sent/failed/uncertain`, số lần thử, hash payload và mã lỗi an
  toàn.
- Telegram chỉ gửi dữ liệu nằm trong allow-list; không gửi raw log, alert
  reference, prompt, reasoning nội bộ, IP, email hoặc secret.
- Secret Telegram nằm ngoài SQLite và report export. Gmail phải tuân theo cùng
  nguyên tắc.
- Delivery đang ở trạng thái `sending` khi ứng dụng restart được chuyển thành
  `uncertain` để tránh tự động gửi trùng.

## 3. Quyết định kỹ thuật cho bản đầu tiên

### 3.1 Phương thức xác thực

Dùng Gmail SMTP với **Google App Password**, không nhận mật khẩu đăng nhập Google
thông thường.

- SMTP host cố định: `smtp.gmail.com`.
- Cổng cố định: `465`, kết nối `SMTP_SSL` ngay từ đầu.
- TLS dùng `ssl.create_default_context()` để kiểm tra chứng thư và hostname.
- Tài khoản Google phải bật xác minh hai bước và tạo App Password riêng cho ứng
  dụng này.
- Nếu Google Workspace không cho phép App Password, Gmail API/OAuth 2.0 sẽ là
  giai đoạn sau; không đưa OAuth vào MVP để tránh lưu refresh token và thêm luồng
  callback phức tạp.

### 3.2 Phạm vi người nhận

MVP hỗ trợ một địa chỉ nhận báo cáo. Địa chỉ gửi và địa chỉ nhận có thể khác
nhau. Nhiều người nhận, CC/BCC, attachment và danh sách phân phối để dành cho
giai đoạn sau nhằm giảm nguy cơ gửi nhầm dữ liệu.

### 3.3 Định dạng thư

- Thư là `multipart/alternative`: bản `text/plain` dự phòng và bản HTML để
  Gmail web/mobile trình bày báo cáo dễ đọc hơn; không dùng file đính kèm.
- Subject dự kiến: `[SIEM AI][<SEVERITY>] Job #<ID> - <WINDOW>`.
- Body gồm trạng thái job, cửa sổ thời gian, model, metrics, severity,
  confidence, rule nổi bật, tóm tắt, root cause, key findings, MITRE, next
  steps, observed facts, inferences, uncertainties, limitations, warning và
  analysis hash. Các rule trùng được gộp trước khi hiển thị.
- Bản HTML có **Alert map - Mật độ alert theo thời gian** dạng biểu đồ cột inline
  từ dashboard timeline. Timeline được gộp còn tối đa 48 bucket (hoặc 16 bucket
  khi giới hạn body nhỏ); bản text có map dự phòng cho email client không render
  HTML.
- Nội dung body có giới hạn, dự kiến 20.000 ký tự. Mọi danh sách và trường text
  đều có giới hạn riêng trước khi ghép thư.
- Chỉ đưa dữ liệu trong allow-list vào cả hai bản thư; không gửi raw log, alert
  reference, IP/email, credential, prompt hoặc private reasoning.
- `payload_sha256` tính trên body text đã chuẩn hóa và đã redact; không tính các
  header biến đổi như `Date` hoặc `Message-ID`.
- `Message-ID` được tạo cục bộ và lưu tối đa 80 ký tự vào
  `provider_message_id`. Trạng thái `sent` chỉ có nghĩa Gmail SMTP đã chấp nhận
  thư, không đảm bảo thư đã vào Inbox thay vì Spam hoặc bị bounce sau đó.

## 4. Trải nghiệm người dùng mục tiêu

### 4.1 Tạo job thủ công và lịch tự động

Hai dropdown `Nhận báo cáo` và `Gửi mỗi cửa sổ` có các lựa chọn `Không gửi`,
`Telegram bot`, `Gmail`. Backend từ chối tạo job/lưu lịch với `gmail` nếu Gmail
đang tắt hoặc thiếu cấu hình.

Việc refresh trạng thái định kỳ không được ghi đè model, ngôn ngữ hoặc kênh gửi
mà người dùng đang chỉnh trước khi bấm lưu lịch.

### 4.2 Cài đặt Gmail

Thêm card `Gmail delivery` cạnh card Telegram, gồm:

- Trạng thái `enabled` và `configured`.
- Nút `Cài đặt Gmail` mở dialog nhập Gmail gửi, App Password và email nhận.
- Nút `Gửi test Gmail`, chỉ bật khi cấu hình hợp lệ.
- Form không điền lại giá trị đã lưu và API không trả lại địa chỉ hoặc App
  Password.
- Sau khi lưu không cần restart; notifier đọc file local tại thời điểm gửi.

### 4.3 Job đã hoàn tất

- Job `succeeded/partial` có nút `Gửi Gmail` với hộp xác nhận.
- Delivery audit hiển thị đúng channel, trạng thái, attempt và mã lỗi an toàn.
- Nếu cùng một job đã được gửi thủ công qua cả Telegram và Gmail, giao diện hiển
  thị cả hai delivery thay vì chỉ hàng mới nhất.
- Retry chỉ xuất hiện với `failed/uncertain`, yêu cầu xác nhận nguy cơ thư trùng
  và vẫn giới hạn tối đa ba attempt như hiện tại.

Luồng tổng quát:

```text
Job hoàn tất
    |
    +-- delivery_channel = none ------> kết thúc
    |
    +-- telegram/gmail ---------------> report_deliveries (pending)
                                             |
                                      delivery worker
                                             |
                                    notifier theo channel
                                             |
                              sent / failed / uncertain
```

## 5. Cấu hình và secret

### 5.1 `config.example.yaml`

Thêm cấu hình không chứa secret:

```yaml
notifications:
  telegram:
    # Giữ nguyên cấu hình hiện có.
  gmail:
    enabled: false
    env_file: "gmail.local.env"
    sender_email_env: "SIEM_GMAIL_SENDER_EMAIL"
    app_password_env: "SIEM_GMAIL_APP_PASSWORD"
    recipient_email_env: "SIEM_GMAIL_RECIPIENT_EMAIL"
    max_body_chars: 20000
    timeout_seconds: 15
    subject_prefix: "[SIEM AI]"
```

SMTP host và port không cho nhập từ dashboard để App Password không thể bị gửi
đến SMTP server tùy ý. Nếu sau này cần Google Workspace relay, phải thêm một
thiết kế riêng với allow-list host.

### 5.2 File local

Tạo `ai_module/gmail.local.env.example`:

```text
# Copy thành gmail.local.env; file thật phải được gitignore.
SIEM_GMAIL_ENABLED=true
SIEM_GMAIL_SENDER_EMAIL=
SIEM_GMAIL_APP_PASSWORD=
SIEM_GMAIL_RECIPIENT_EMAIL=
```

Thêm `ai_module/gmail.local.env` vào `.gitignore`. File thật:

- Chỉ được nằm trong `ai_module`, không chấp nhận path traversal hoặc symlink
  ra ngoài module.
- Giới hạn kích thước 16 KiB, chỉ chấp nhận đúng các key đã định nghĩa.
- Ghi bằng file tạm rồi atomic replace; xóa file tạm nếu ghi thất bại.
- Không log nội dung, không lưu vào SQLite, report export, response API hoặc
  frontend state.
- Cố gắng giới hạn quyền đọc file cho user hiện tại trên hệ điều hành; nếu không
  thể thì cảnh báo trong tài liệu vận hành.

App Password có thể được nhập với khoảng trắng theo cách Google hiển thị; code
chuẩn hóa bỏ khoảng trắng trước khi đăng nhập nhưng không bao giờ trả lại giá
trị đã chuẩn hóa.

## 6. Thay đổi backend theo file

### 6.1 Payload an toàn dùng chung

Tạo `ai_module/notification_report.py` và chuyển phần allow-list/redaction dùng
chung ra khỏi `telegram_notifier.py`:

- `build_safe_report(job)` chỉ đọc các trường được phép.
- `redact_text()` che email, IPv4/IPv6, control character và mẫu secret.
- `analysis_sha256()` tạo hash ổn định từ analysis đã lưu.
- Telegram và Gmail tự format dữ liệu an toàn thành giới hạn riêng của từng
  provider.

Giữ test snapshot/contract cho Telegram để việc tách module không làm thay đổi
nội dung hoặc giảm mức redact hiện có.

### 6.2 Gmail notifier

Tạo `ai_module/gmail_notifier.py` với interface tương đương Telegram:

- `GMAIL_CHANNEL = "gmail"`.
- `GmailSettings`, `GmailConfigurationError`, `GmailDeliveryError`.
- `settings_from_config(cfg)` validate boolean, tên biến môi trường, path, timeout,
  subject prefix và giới hạn body.
- `status()` chỉ trả `channel`, `enabled`, `configured`, `max_body_chars`; không
  trả sender/recipient.
- `configure_local(sender_email, app_password, recipient_email)` validate và
  ghi file local an toàn.
- `send_test()` gửi subject/body cố định, không chứa dữ liệu SIEM.
- `send_report(job)` tạo `EmailMessage`, thiết lập `From`, `To`, `Subject`,
  `Date`, `Message-ID`, body text rồi gửi qua `SMTP_SSL`.
- Cho phép inject SMTP factory trong unit test để không mở kết nối mạng thật.

Email validation MVP:

- Chỉ nhận một mailbox ASCII, tối đa 254 ký tự.
- Từ chối CR/LF, dấu phẩy, display name, chuỗi có nhiều hơn một `@` hoặc local/
  domain rỗng.
- Không cho header do người dùng nhập ngoài ba địa chỉ/subject prefix đã validate.
- `subject_prefix` từ YAML phải từ chối CR/LF và giới hạn độ dài.

### 6.3 Runtime và delivery router

Cập nhật `ai_module/dashboard_worker.py`:

- Khởi tạo `gmail_notifier` cùng `telegram_notifier`.
- Tạo registry `notifiers = {"telegram": ..., "gmail": ...}`.
- `_run_delivery()` lấy notifier theo `delivery["channel"]` rồi gọi
  `send_report(job)`; không còn hard-code Telegram.
- Thông báo log dùng từ `delivery`, không ghi exception body có thể chứa secret,
  SMTP response hoặc địa chỉ email.
- Sau khi job thành công, enqueue mọi channel hợp lệ khác `none`; kết quả phân
  tích vẫn độc lập với lỗi enqueue/gửi.
- Giữ một delivery worker tuần tự ở MVP để không thay đổi concurrency và thứ tự
  audit. Có thể tách pool sau khi đo tải thực tế.

Nên thêm exception nền dùng chung trong `notification_report.py` hoặc một module
nhỏ `notification_errors.py`. Exception của Telegram/Gmail kế thừa lớp chung để
worker phân loại lỗi mà vẫn giữ mã lỗi provider-specific.

### 6.4 API

Cập nhật `ai_module/dashboard.py`:

- `_resolve_delivery_channel()` nhận `none/telegram/gmail` và kiểm tra notifier
  tương ứng đang `enabled && configured`.
- `GET /api/notifications/status` trả cả `telegram` và `gmail` với dữ liệu an
  toàn.
- `POST /api/notifications/gmail/settings` yêu cầu `confirm: true`, validate JSON
  size/origin và không phản chiếu credential/destination.
- `POST /api/notifications/gmail/test` yêu cầu `confirm: true`; thành công trả
  `202`, lỗi chỉ trả mã an toàn.
- Giữ `POST /api/jobs/<id>/delivery` dùng chung với `channel: "gmail"`.
- Không đưa Gmail vào `/api/dependencies`, vì endpoint đó được poll thường xuyên
  và không nên đăng nhập SMTP định kỳ. Kiểm tra kết nối chỉ chạy khi người dùng
  bấm `Gửi test Gmail`.

Payload lưu settings dự kiến:

```json
{
  "sender_email": "sender@example.com",
  "app_password": "<app-password>",
  "recipient_email": "recipient@example.com",
  "confirm": true
}
```

Response chỉ chứa trạng thái an toàn, ví dụ:

```json
{
  "status": "saved",
  "gmail": {
    "channel": "gmail",
    "enabled": true,
    "configured": true,
    "max_body_chars": 20000
  }
}
```

## 7. Migration SQLite schema v5 lên v6

Tăng `SCHEMA_VERSION` từ `5` lên `6` trong `dashboard_store.py` và cập nhật:

- `DELIVERY_CHANNELS = {"none", "telegram", "gmail"}`.
- `jobs.delivery_channel CHECK(... IN ('none','telegram','gmail'))`.
- `schedule.delivery_channel CHECK(... IN ('none','telegram','gmail'))`.
- `report_deliveries.channel CHECK(... IN ('telegram','gmail'))`.
- Giữ `UNIQUE(job_id, channel)` để một job có thể có tối đa một audit row cho
  mỗi provider; retry dùng lại row đó.

SQLite không sửa trực tiếp `CHECK`, vì vậy migration phải rebuild ba table trong
một transaction chuyên dụng:

1. Tắt foreign-key enforcement trên connection migration trước `BEGIN`.
2. Tạo table v6 với đầy đủ column/default/check/index tương đương schema hiện
   tại.
3. Copy toàn bộ row và giữ nguyên ID, timestamp, delivery status và attempt.
4. Kiểm tra số row nguồn/đích trước khi swap.
5. Drop table cũ, rename table v6 về tên chuẩn và tạo lại index.
6. Set `PRAGMA user_version=6`, commit, bật lại foreign key.
7. Chạy `PRAGMA foreign_key_check`; nếu có lỗi thì dừng startup với thông báo
   an toàn, không tiếp tục chạy trên DB hỏng.

Phải có test migration từ một fixture v5 đã chứa job, lịch, review, Telegram
delivery và foreign-key child rows. Test xác nhận dữ liệu cũ còn nguyên, Telegram
vẫn retry được và row Gmail mới insert được.

`get_job_detail()` nên trả thêm `deliveries` là danh sách theo channel, đồng thời
giữ trường `delivery` là bản ghi mới nhất trong một phiên bản chuyển tiếp để
frontend/consumer cũ không bị vỡ ngay.

## 8. Phân loại lỗi và retry

Mã lỗi chỉ chứa ký tự an toàn và tối đa 80 ký tự. Dự kiến:

| Tình huống | Mã lỗi | Trạng thái |
|---|---|---|
| Thiếu/tắt cấu hình | `gmail_configuration` | `failed` |
| App Password hoặc account bị từ chối | `gmail_auth_failed` | `failed` |
| Sender/recipient không hợp lệ hoặc bị từ chối trước DATA | `gmail_recipient_refused` | `failed` |
| Lỗi TLS/chứng thư | `gmail_tls_error` | `failed` |
| Timeout/mất kết nối trong lúc gửi | `gmail_timeout` / `gmail_network_error` | `uncertain` |
| SMTP response không xác định sau khi bắt đầu gửi | `gmail_smtp_error` | `uncertain` |
| Provider chấp nhận thư | không có | `sent` |

Không auto-retry lỗi `uncertain`, vì Gmail có thể đã nhận thư trước khi kết nối
bị ngắt. Người vận hành retry thủ công và xác nhận nguy cơ trùng. Chính sách tối
đa ba attempt hiện tại được giữ nguyên.

Không đưa exception text của `smtplib` vào log/API/SQLite vì response có thể
chứa địa chỉ email hoặc chi tiết server. Chỉ log job ID, delivery ID, channel và
mã lỗi đã chuẩn hóa.

## 9. Thay đổi frontend

Cập nhật `ai_module/web/index.html`:

- Thêm option `Gmail` vào hai delivery dropdown.
- Thêm card Gmail status/settings/test.
- Thêm dialog với input email gửi, password và email nhận; password dùng
  `type="password"`, `autocomplete="new-password"`, không prefill.

Cập nhật `ai_module/web/app.js`:

- Đổi `loadTelegramStatus()` thành `loadNotificationStatus()` hoặc thêm hàm
  Gmail song song nhưng chỉ gọi một lần endpoint status.
- Implement mở/đóng/reset form Gmail, lưu settings và gửi test.
- Tạo action `Gửi Gmail` cho job hoàn tất.
- Render delivery theo channel và dùng nhãn retry tổng quát, không hard-code
  `Retry Telegram`.
- Render danh sách `deliveries` nếu API đã có; giữ fallback sang `delivery` cho
  dữ liệu/API cũ.
- Khi poll job/schedule/status, không set lại giá trị form lịch nếu form đang
  dirty hoặc người dùng chưa bấm lưu.

Cập nhật `styles.css` bằng class dùng chung như `.notification-settings-form`
thay vì nhân đôi toàn bộ style Telegram; kiểm tra layout desktop và mobile.

## 10. Kiểm thử

### 10.1 Unit test Gmail

Tạo `tests/test_gmail_notifier.py` với SMTP fake, không dùng mạng thật:

- Parse config mặc định và override hợp lệ.
- Reject env path, env key, timeout, body limit và subject prefix không hợp lệ.
- Validate sender/recipient và chống CRLF/header injection.
- Đọc biến môi trường ưu tiên hơn file local.
- Ghi file local atomic; API status không lộ email/App Password.
- Chuẩn hóa App Password có khoảng trắng.
- Test email là nội dung tĩnh.
- Report chỉ chứa allow-list, bị giới hạn kích thước và không chứa raw log, IP,
  email, token, prompt hoặc reasoning.
- Tạo đúng header, body, Message-ID và payload hash ổn định.
- Map auth, recipient refusal, TLS, timeout và disconnect sang mã/trạng thái đúng.
- Không có secret trong `str(exception)`, log hoặc kết quả trả về.

### 10.2 Store/worker/API

Cập nhật các test hiện có:

- Migration v5 -> v6 bảo toàn dữ liệu và foreign key.
- `gmail` hợp lệ trong job, schedule và delivery; giá trị lạ vẫn bị từ chối.
- Worker route đúng notifier theo channel và một lỗi Gmail không làm chết worker.
- Job `succeeded/partial` tự enqueue Gmail; job rỗng/failed/cancelled không gửi.
- Recovery `sending -> uncertain` áp dụng cho cả hai provider.
- Unique theo `(job_id, channel)` ngăn enqueue trùng cùng provider nhưng vẫn cho
  phép một row Telegram và một row Gmail khi gửi thủ công.
- Settings/test API yêu cầu origin và `confirm`, không phản chiếu secret/address.
- Job/schedule chọn Gmail bị từ chối khi chưa cấu hình.

### 10.3 UI và regression

- Kiểm tra đủ ID/option/nút/dialog Gmail và endpoint JavaScript.
- Kiểm tra model cùng kênh delivery đang chỉnh không bị polling ghi đè.
- `node --check ai_module/web/app.js`.
- `python -m compileall ai_module scripts`.
- Chạy toàn bộ `pytest` và không giảm số test Telegram hiện có.
- Quét diff/repository để chắc App Password hoặc địa chỉ thật không bị commit.
- Kiểm tra responsive card/dialog trên desktop và mobile.

### 10.4 Smoke test thủ công

Sau khi unit/regression pass:

1. Tạo App Password dùng riêng cho môi trường test.
2. Lưu bằng dashboard, xác nhận status `enabled/configured` mà không hiện địa chỉ.
3. Gửi test cố định và kiểm tra Inbox/Spam.
4. Chạy một job nhỏ với `Gmail`, xác nhận delivery chuyển `pending -> sending -> sent`.
5. Đối chiếu thư không có raw log/IP/email/secret và hash audit đã được lưu.
6. Restart dashboard, xác nhận cấu hình được nạp lại và delivery đã `sent` không
   bị gửi lại.
7. Thu hồi App Password test nếu không dùng tiếp.

Live smoke test là bước có side effect và chỉ chạy khi người vận hành xác nhận
địa chỉ nhận. Automated test tuyệt đối không gửi email thật.

## 11. Thứ tự triển khai

### Giai đoạn 1 - Nền tảng và migration

- Tách payload/redaction dùng chung.
- Viết migration schema v6 và test fixture v5.
- Mở rộng delivery DTO thành danh sách theo channel.

Điều kiện qua giai đoạn: toàn bộ test Telegram cũ pass và DB v5 nâng cấp không
mất dữ liệu.

### Giai đoạn 2 - Gmail provider

- Implement config, local env, formatter, SMTP_SSL và error mapping.
- Hoàn thiện unit test với SMTP fake.

Điều kiện qua giai đoạn: không cần mạng thật, mọi nhánh auth/TLS/timeout/refusal
được kiểm thử và không lộ secret.

### Giai đoạn 3 - Runtime và API

- Thêm notifier registry, generic delivery routing, status/settings/test API.
- Mở Gmail cho job thủ công, lịch tự động và manual delivery.

Điều kiện qua giai đoạn: API/worker/store integration test pass, Telegram không
regression.

### Giai đoạn 4 - Dashboard

- Thêm dropdown/card/dialog/action/audit Gmail.
- Bảo vệ form lịch khỏi polling overwrite.
- Kiểm tra desktop/mobile và accessibility cơ bản.

### Giai đoạn 5 - Tài liệu và vận hành

- Tạo `docs/gmail.md` hướng dẫn bật 2-Step Verification, tạo/revoke App Password,
  nhập cấu hình, gửi test, xử lý Spam và các mã lỗi.
- Cập nhật `README.md`, `CHANGELOG.md`, `HANDOFF.md`, `config.example.yaml`,
  `.gitignore` và file env example.
- Có thể thêm `scripts/gmail_setup.py` để kiểm tra cấu hình/gửi test tĩnh; helper
  không bao giờ in App Password hoặc địa chỉ đầy đủ.

### Giai đoạn 6 - Xác minh live và bàn giao

- Chạy full regression, secret scan và smoke test đã được xác nhận.
- Restart dashboard, kiểm tra `/api/status` và `/api/notifications/status`.
- Gửi một report test, ghi nhận delivery ID/trạng thái nhưng không ghi credential
  vào tài liệu bàn giao.

## 12. Tiêu chí hoàn thành

- Người dùng chọn được `Không gửi`, `Telegram bot` hoặc `Gmail` cho job và lịch.
- Gmail chưa cấu hình không thể được chọn để tạo job/lưu lịch.
- Cấu hình Gmail được lưu local, không cần restart, không bị trả lại qua API/UI.
- Test Gmail gửi nội dung tĩnh an toàn; report Gmail gửi đủ trường phân tích
  trong allow-list, Alert map HTML và bản text fallback đã redact.
- Delivery Gmail có audit, hash, attempt, retry thủ công và recovery `uncertain`.
- Telegram cũ tiếp tục hoạt động và dữ liệu schema v5 được bảo toàn.
- Polling dashboard không đổi model/kênh đang được chỉnh.
- Full test suite, compile check, JavaScript syntax check và secret scan đều pass.
- Tài liệu vận hành nêu rõ App Password, ý nghĩa trạng thái `sent`, cách revoke và
  xử lý lỗi.

## 13. Ngoài phạm vi MVP

- Nhận lệnh hoặc email inbound.
- Gmail API/OAuth 2.0 và refresh token.
- Gửi đồng thời Telegram + Gmail trong cùng lựa chọn tự động.
- Nhiều recipient, CC/BCC, group alias hoặc recipient theo từng schedule.
- File JSON/PDF đính kèm, ảnh chụp dashboard hoặc raw alert.
- Auto-retry theo backoff, theo dõi bounce/delivery receipt và thống kê mở thư.

Các mục này chỉ nên triển khai sau khi MVP được kiểm thử với tài khoản Gmail/
Workspace thực tế và có yêu cầu vận hành rõ ràng.
