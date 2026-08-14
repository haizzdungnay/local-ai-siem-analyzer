# Kế hoạch xây dựng trang mô phỏng tấn công và kiểm thử Wazuh/AI

> **Ràng buộc bắt buộc:** Tài liệu này chỉ mô tả kiểm thử phòng thủ bằng fixture/marker bounded trong lab cô lập. Không cung cấp payload hay hướng dẫn nhắm tới hệ thống ngoài lab. Hai model Terra và Luna chỉ thiết kế, triển khai bounded task, kiểm định và đọc bằng chứng; không được tự mở rộng target hoặc tự quyết định chạy tấn công.

**Phiên bản kế hoạch:** `security-test-plan-v2`

**Orchestrator/owner:** agent điều phối (root) và người vận hành được ủy quyền

**Model phối hợp:** `gpt-5.6-terra` (Terra) và `gpt-5.6-luna` (Luna)

**Nguyên tắc source of truth:** manifest, state/evidence store và Wazuh Indexer; output AI không phải ground truth.

## Trạng thái triển khai 2026-08-12

- Đã có trang `/security-tests`, link từ dashboard, catalog 18 scenario, confirmation dialog, polling trạng thái và terminal chỉ đọc cho command/output/script preview của từng lượt chạy. Private-key path không được hiển thị và không có ô nhập lệnh.
- Runner hiện chỉ nhận `scenario_id` allowlist, cố định Kali `.30` và DVWA `.20`, chạy một lượt tại một thời điểm, không nhận command/URL/target/payload từ browser.
- Timebox đã áp dụng: SSH connect tối đa 5 giây, mỗi request tối đa 2 giây, script tự dừng sau 18 giây và process runner tối đa 20 giây.
- Smoke test đã chạy tuần tự cả 18 scenario qua API; tất cả có `exit_code=0`. Đây chỉ là bằng chứng request được gửi, không phải bằng chứng exploit thành công.
- Wazuh Indexer trong cửa sổ smoke ghi nhận 4 alert từ `.30` trên agent `.20`: `31104` x1 (traversal-shaped path), `31105` x2 (XSS-shaped requests) và `31101` x1 (API 404). Đồng hồ Kali chậm khoảng 65 giây so với host dashboard, nên chưa thể gán các alert này cho một scenario cụ thể. Chưa có correlation `run_id` và chưa có rule/telemetry riêng cho toàn bộ 18 scenario, vì vậy kết quả Wazuh hiện là `partial` và không được dùng để kết luận phát hiện đủ 18 loại.
- Các hạng mục còn lại: lưu run/evidence vào SQLite, correlation `run_id`, query Wazuh theo cửa sổ từng run, cleanup có kiểm chứng cho scenario stateful, và hiển thị kết quả Execution/Telemetry/Wazuh/AI riêng trên page.

## 1. Mục tiêu

Tạo một trang riêng trong dashboard local để người vận hành có thể chạy các kịch bản tấn công mẫu có kiểm soát vào DVWA trên Victim Ubuntu, sau đó theo dõi toàn bộ chuỗi:

```text
Trang kiểm thử trên Host .1
        |
        v
Bộ điều phối chỉ cho phép kịch bản cố định
        |
        +--> Kali .30 tạo lưu lượng --> DVWA/Victim .20
                                      |
                                      v
                           Apache/DVWA/ModSecurity log
                                      |
                                      v
                              Wazuh agent .20
                                      |
                                      v
                           Wazuh Indexer/SIEM .10
                                      |
                                      v
                        AI local phân tích trên Host .1
                                      |
                                      v
                   So sánh với kết quả mong đợi và báo PASS/FAIL
```

Mục tiêu cuối cùng không chỉ là xác nhận request đã tới DVWA, mà phải phân biệt rõ bốn lớp kết quả:

1. Kịch bản đã chạy thành công hay chưa.
2. Hệ thống đích đã sinh telemetry/log phù hợp hay chưa.
3. Wazuh đã tạo đúng alert mong đợi hay chưa.
4. AI đã diễn giải đúng loại tấn công, dựa trên bằng chứng và không khẳng định quá mức hay chưa.

## 2. Phạm vi và nguyên tắc an toàn

- Chỉ chạy trong mạng lab host-only `192.168.100.0/24`.
- Target web duy nhất là DVWA trên `192.168.100.20`; nguồn tạo lưu lượng mặc định là Kali `192.168.100.30`.
- Trang kiểm thử chỉ bind loopback cùng dashboard hiện tại, không công khai ra LAN/Internet.
- Tính năng mặc định tắt và chỉ hoạt động khi cấu hình local đặt `security_test.enabled: true`.
- API không nhận command, script, URL, target IP, payload hoặc đường dẫn tùy ý từ browser. Browser chỉ gửi `scenario_id` nằm trong allowlist.
- Mỗi kịch bản có giới hạn request, timeout, một lượt chạy tại một thời điểm và không tự retry tấn công.
- Preflight phải kiểm tra feature flag, route/interface, source IP `.30`, target `.20`, mạng host-only và egress deny; bất kỳ sai lệch nào đều **fail closed**.
- Runner chỉ gọi executable/script đã allowlist (kèm hash), working directory và environment tối thiểu; không ghép chuỗi shell từ dữ liệu browser.
- Có global kill switch, watchdog cleanup, per-run deadline, request/token/output quota và lock toàn cục; chỉ retry thao tác đọc trạng thái/query với giới hạn, tuyệt đối không retry attack step.
- Không cho chạy khi snapshot/recovery marker hoặc cleanup của run trước chưa hoàn tất. Nếu route/target đổi giữa chừng, dừng bounded step, cleanup rồi chuyển `failed`.
- Không gửi telemetry, browser beacon hoặc dữ liệu AI ra ngoài lab; sink chỉ nhận event code nằm trong allowlist.
- Chỉ dùng tài khoản, dữ liệu và file giả dành riêng cho lab. Không dùng mật khẩu thật, dữ liệu cá nhân hoặc secret production.
- Command Injection chỉ chạy lệnh marker vô hại. SQL Injection chỉ đọc bộ dữ liệu seed. File Upload chỉ dùng file marker trơ, không dùng malware thật. Open Redirect chỉ chuyển tới sink nội bộ trong lab.
- Các kịch bản có thay đổi trạng thái như Stored XSS, CSRF, File Upload và Authorisation Bypass phải có bước seed trước khi chạy và cleanup sau khi chạy.
- Không dùng Nikto trong nút “Chạy tất cả”; scan có thể tạo hàng nghìn alert và chỉ được giữ thành thao tác riêng có xác nhận rõ ràng nếu bổ sung sau.
- Tạo snapshot VM trước lần kiểm thử live đầu tiên và trước khi thay đổi DVWA, Apache, ModSecurity hoặc Wazuh rules.

## 3. Phạm vi giao diện

### 3.1 Điều hướng

- Thêm nút **Kiểm thử bảo mật** trên dashboard chính.
- Nút mở trang riêng tại `/security-tests`.
- Trang mới dùng chung ngôn ngữ và visual system của dashboard, nhưng tách `test.html`, `test.js` và phần style riêng để không làm màn hình phân tích hiện tại quá tải.
- Có nút quay lại dashboard và liên kết trực tiếp tới job AI được tạo từ một lượt kiểm thử.

### 3.2 Thành phần trên trang

1. **Trạng thái lab**: Host runner, Kali, Victim/DVWA, Wazuh agent, Indexer và Ollama.
2. **Cảnh báo phạm vi**: hiển thị cố định nguồn `.30`, đích `.20`, SIEM `.10` và nhãn “Lab cô lập”.
3. **Danh sách kịch bản**: mỗi module là một card có mô tả, nguồn telemetry, mức tác động, thời gian dự kiến và nút **Chạy kiểm thử**.
4. **Bộ lọc**: tất cả, xác thực, injection, browser/client, session, access control, file và API.
5. **Nút chạy bộ an toàn**: chỉ chạy tuần tự các kịch bản đã được đánh dấu `safe_suite: true`; không chạy song song.
6. **Hộp xác nhận**: hiển thị chính xác scenario, target, request cap, dữ liệu sẽ thay đổi và cách cleanup trước khi cho chạy.
7. **Tiến trình live**: `queued -> preflight -> seeding -> attacking -> waiting_ingest -> querying_wazuh -> analyzing_ai -> cleanup -> completed`.
8. **Kết quả bốn lớp**: Execution, Telemetry, Wazuh và AI; không gộp thành một dấu PASS duy nhất làm mất nguyên nhân lỗi.
9. **Bằng chứng**: UTC start/end, opaque `run_id`, HTTP status, Wazuh rule ID/level/description, agent, thời gian ingest, AI job ID và lý do PASS/FAIL đã sanitize.
10. **Lịch sử**: lọc theo scenario, trạng thái và thời gian; cho phép xuất JSON/CSV đã redact.
11. **Trạng thái vận hành**: hiển thị feature flag, lần preflight gần nhất, lý do card bị khóa (dependency, telemetry contract, cleanup hoặc active run) và snapshot ID đã được kiểm chứng.
12. **Khả năng phục hồi**: khi mất polling hiển thị `connection_lost`/dữ liệu có thể cũ, không tự khởi động lại scenario; chỉ cho retry sau reconcile.
13. **Accessibility**: dialog có focus trap, thao tác bàn phím, `aria-live` cho phase và màu sắc không phải tín hiệu duy nhất.
14. **Bằng chứng mở rộng**: cho phép mở riêng Execution/Telemetry/Wazuh/AI; export phải ghi phạm vi redact, phiên bản manifest/ruleset/model và không làm bảng raw log tràn màn hình.

### 3.3 Trạng thái kết quả

| Trạng thái | Ý nghĩa |
|---|---|
| `passed` | Cả execution, telemetry, Wazuh và AI đều đạt tiêu chí |
| `partial` | Request/log có nhưng Wazuh hoặc AI chưa đạt |
| `failed` | Kịch bản lỗi, sai target, timeout, thiếu cleanup hoặc không có bằng chứng bắt buộc |
| `skipped` | Thiếu dependency đã biết, ví dụ ModSecurity hoặc browser runner chưa sẵn sàng |
| `cancelled` | Chỉ hủy được khi đang chờ; nếu đã bắt đầu thì runner phải kết thúc bounded step và cleanup |
| `needs_review` | Bằng chứng mâu thuẫn, AI không đủ rõ hoặc có mismatch chưa được adjudicate |
| `blocked` | Bị chặn bởi safety/dependency/approval; chỉ tiếp tục sau quyết định mới, không tự resume |
| `interrupted` | Process/restart làm gián đoạn; phải reconcile và cleanup trước khi có kết quả cuối |

Quy tắc precedence: `cleanup_failed`, safety violation, sai target hoặc vượt cap làm kết quả tổng thể tối đa là `failed`; `needs_review` không được tính là PASS. Báo cáo phải tách số lượng và lý do của từng trạng thái, không thay bằng một tỷ lệ PASS duy nhất.

## 4. Danh mục 18 kịch bản

Các rule ID trong bảng là hợp đồng logic, chưa phải số Wazuh cố định. Số rule custom chỉ được chốt sau khi kiểm kê để tránh trùng rule hiện có. Rule chuẩn đã thấy trong lab như `5503`, `5760`, `2502`, `31104`, `31105`, `31101` và `31151` vẫn được tái sử dụng khi phù hợp.

| # | Scenario ID | Module | Loại tấn công | Cách mô phỏng an toàn | Telemetry chính | Kết quả mong đợi |
|---:|---|---|---|---|---|---|
| 1 | `brute-force` | Brute Force | Dò mật khẩu | Từ Kali chạy tối đa 20 lần đăng nhập SSH sai bằng credential giả cố định | `auth.log`, Wazuh SSH rules | Có failed-auth và correlation khi đủ ngưỡng; AI gọi đúng brute force/credential attack |
| 2 | `command-injection` | Command Injection | Chèn lệnh hệ thống | Gửi input cố định tới DVWA; lệnh chỉ ghi marker theo `run_id` trong thư mục test | Apache, ModSecurity, app audit, FIM test dir | Có dấu hiệu command injection; không thay đổi file hệ thống; AI không nói đã chiếm máy nếu chỉ có attempt |
| 3 | `csrf` | CSRF | Giả mạo yêu cầu | Browser automation dùng tài khoản lab và form thay đổi dữ liệu giả, thiếu/sai anti-CSRF token theo case cố định | App audit, Apache, ModSecurity | Wazuh nhận request bất thường hoặc sự kiện validation; AI nhận diện CSRF attempt và nêu giới hạn bằng chứng |
| 4 | `file-inclusion` | File Inclusion | LFI/RFI | Chỉ include fixture vô hại trong thư mục lab; RFI chỉ gọi payload server nội bộ | Apache, ModSecurity, app audit | Có traversal/include signature; không đọc `/etc/passwd` hay tài nguyên ngoài lab |
| 5 | `file-upload` | File Upload | Upload file độc hại | Upload file marker trơ với double extension/MIME mismatch vào thư mục upload cô lập | ModSecurity, app audit, FIM upload dir | Wazuh cảnh báo upload đáng ngờ; cleanup xóa marker; AI không gọi marker là malware đã thực thi |
| 6 | `insecure-captcha` | Insecure CAPTCHA | CAPTCHA yếu | Replay/bypass một challenge dành riêng cho tài khoản lab với số lần giới hạn | App audit, Apache | Có sự kiện CAPTCHA bypass/replay; AI mô tả kiểm soát yếu thay vì khẳng định compromise |
| 7 | `sql-injection` | SQL Injection | Tiêm SQL | Query cố định chỉ đọc bản ghi seed không nhạy cảm, không dùng stacked destructive query | ModSecurity, DB/app audit, Apache | Có SQLi signature/validation event; AI nhận diện SQL injection và dẫn đúng evidence |
| 8 | `sql-injection-blind` | SQL Injection (Blind) | Tiêm SQL mù | Cặp truy vấn boolean/time-bounded vào dữ liệu seed; giới hạn tổng request và độ trễ | ModSecurity, app audit, Apache timing | Có mẫu blind SQLi; AI phân biệt được blind SQLi hoặc ghi rõ chưa đủ bằng chứng |
| 9 | `weak-session-ids` | Weak Session IDs | Session ID yếu | Thu số lượng nhỏ session ID lab rồi kiểm tra collision/predictability offline | App/session audit và kết quả detector | Wazuh nhận vulnerability signal từ app audit; không thu cookie người dùng thật |
| 10 | `xss-dom` | XSS (DOM) | XSS phía DOM | Playwright mở URL marker cố định; thành công chỉ đặt thuộc tính test hoặc gửi beacon nội bộ | Browser beacon, CSP report, Apache | Có bằng chứng execution phía browser trong lab; AI gọi đúng DOM XSS |
| 11 | `xss-reflected` | XSS (Reflected) | XSS phản chiếu | Marker cố định được phản chiếu và xác nhận qua browser beacon nội bộ | ModSecurity, Apache, browser beacon | Có reflected input và execution marker; AI phân biệt với Stored XSS |
| 12 | `xss-stored` | XSS (Stored) | XSS lưu trữ | Tạo comment seed chứa marker, mở lại bằng browser test rồi xóa bản ghi | App/DB audit, ModSecurity, browser beacon | Có create-read-execute-cleanup; AI nhận diện persisted/stored behavior |
| 13 | `csp-bypass` | CSP Bypass | Vượt Content-Security-Policy | Dùng trang lab có CSP yếu và marker vô hại, không exfiltrate dữ liệu | CSP report endpoint, browser beacon | Ghi nhận policy/bypass path; AI nêu cấu hình CSP liên quan |
| 14 | `javascript-attacks` | JavaScript Attacks | Tấn công logic JS phía client | Sửa giá trị/logic client của dữ liệu giả rồi gửi lên server test | App audit, Apache | Server ghi nhận client-side tampering; AI nêu thiếu server-side validation |
| 15 | `authorisation-bypass` | Authorisation Bypass | Vượt phân quyền | Tài khoản lab quyền thấp truy cập object/admin fixture không nhạy cảm | App authorization audit, Apache | Có denied/bypass attempt và user role; AI phân biệt authentication với authorization |
| 16 | `open-http-redirect` | Open HTTP Redirect | Chuyển hướng mở | Redirect chỉ tới sink nội bộ trên Kali, URL đích cố định | Apache/app audit, sink access log | Có untrusted redirect parameter và redirect chain; không gọi Internet |
| 17 | `cryptography` | Cryptography | Mã hóa yếu | Endpoint lab trả artifact giả dùng thuật toán/cấu hình yếu; đánh giá offline, không dùng secret thật | App crypto audit và detector result | Có weak-crypto signal; AI chỉ kết luận về artifact test |
| 18 | `api` | API | Lỗ hổng API | Chạy tập nhỏ gồm missing auth, object access, method tampering và bounded rate check trên record giả | API gateway/app audit, Apache | Wazuh bắt đúng nhánh API; UI hiển thị subcase nào PASS/FAIL |

## 5. Telemetry và Wazuh

### 5.1 Nguồn log

Wazuh không tự nhìn thấy đầy đủ nội dung ứng dụng chỉ từ Apache access log. Đặc biệt, CSRF, CAPTCHA, quyền truy cập, session yếu, crypto yếu và nhiều POST body không thể được đánh giá chính xác nếu chỉ dựa vào URL/status code. Cần cấu hình tối thiểu:

- Apache access/error log hiện có.
- Một Apache test access log riêng có ghi opaque header `X-SIEM-Test-Run-ID`, không ghi scenario name hoặc secret.
- ModSecurity + OWASP CRS audit log cho signature web, cấu hình chỉ trong lab và giới hạn phần body cần thiết.
- DVWA/test-hook audit log dạng JSON cho sự kiện validation, authorization, session, CAPTCHA, redirect, API và cleanup.
- FIM chỉ theo dõi các thư mục test riêng cho command marker và upload marker.
- CSP report/browser beacon endpoint chỉ nhận `run_id` và event code allowlisted, không nhận JavaScript hoặc nội dung tùy ý.

### 5.2 Schema log ứng dụng đề xuất

```json
{
  "timestamp": "2026-08-12T09:30:00Z",
  "run_id": "opaque-uuid",
  "event_code": "input_validation_failed",
  "action": "profile_update",
  "outcome": "blocked",
  "source_ip": "192.168.100.30",
  "actor": "lab-low-user",
  "http_method": "POST",
  "http_status": 403,
  "test_marker": true
}
```

Không ghi `scenario_id`, tên tấn công hoặc expected result vào log đầu vào của AI. Ground truth được giữ riêng trong database của runner để tránh AI chỉ sao chép đáp án.

Tách tuyệt đối `raw evidence` nội bộ khỏi `display evidence`. UI, export và ngữ cảnh gửi AI chỉ nhận allowlist field đã redact; raw request/response body, cookie, `Authorization`, CSRF token, password, private key, file content, URL query có secret và stack trace có path không được persist hoặc export. `run_id` là opaque correlation ID, không phải secret/quyền truy cập.

Mỗi evidence hiển thị theo `EvidenceBundle v1` cần có `evidence_id`, loại nguồn, timestamp UTC, content hash, redaction version, retention deadline và reference opaque tới alert/log gốc. Redaction phải được kiểm thử trên nested JSON, exception, CSV, export và AI prompt bằng secret giả ở nhiều vị trí. AI chỉ nhận evidence đã sanitize, có size cap và không bao giờ nhận ground truth, expected rule hoặc credential.

### 5.3 Wazuh decoder/rule

- Thêm decoder cho JSON audit log và trường `run_id`, `event_code`, `outcome`, `source_ip`.
- Kiểm kê rule custom hiện tại rồi cấp một dải ID riêng, có tài liệu mapping từ logical detection ID sang numeric rule ID.
- Rule mô tả sự kiện quan sát được, ví dụ “repeated authentication failures” hoặc “web input matched SQLi pattern”; không ghi “attack succeeded” nếu telemetry chỉ chứng minh attempt.
- Thêm correlation có giới hạn cho brute force, blind SQLi, API rate và repeated web errors.
- Mỗi scenario có baseline request bình thường để kiểm tra false positive.
- Test rule bằng `wazuh-logtest` trước, sau đó mới chạy E2E trên Indexer.
- Lưu reference tới alert/index document thay vì copy raw log; mọi thao tác xem/export evidence được audit local.

## 6. Correlation và tiêu chí đánh giá AI

Mỗi lượt chạy tạo một UUID ngẫu nhiên và ghi các mốc `start_utc`, `attack_end_utc`, `ingest_deadline_utc`, `analysis_end_utc`. Runner chỉ query alert trong cửa sổ của lượt đó, kết hợp agent, source IP và `run_id` nếu log hỗ trợ.

```text
Ground truth riêng của runner
        | expected category/rules
        v
Kết quả execution --> raw telemetry --> Wazuh alert --> AI output
        |                 |                 |              |
        +-----------------+-----------------+--------------+
                           so sánh độc lập
```

### 6.1 Điều kiện PASS theo lớp

- **Execution PASS**: runner trả đúng exit code, request cap không bị vượt, target đúng và bounded step hoàn tất.
- **Telemetry PASS**: có log hoặc marker bắt buộc mang đúng `run_id` trong khoảng thời gian chạy.
- **Wazuh PASS**: có ít nhất một rule nằm trong `expected_any`, không xuất hiện rule thuộc `forbidden`, agent/source/time khớp và ingest không quá deadline mặc định 120 giây.
- **AI PASS**: loại tấn công khớp alias cho phép, summary/root cause dẫn được rule/evidence đã có, mức chắc chắn phù hợp và không tuyên bố exploit thành công khi log chỉ cho thấy attempt.

### 6.2 Chấm AI

- Dùng matcher xác định theo manifest alias, không gọi chính model đang được chấm để tự chấm nó.
- Chấm riêng `attack_type_match`, `evidence_grounded`, `success_claim_correct`, `severity_reasonable` và `recommended_steps_relevant`.
- Cho phép trạng thái `needs_review` khi ngôn ngữ AI không đủ rõ để matcher kết luận.
- Analyst có thể override kèm note; không sửa output gốc.
- Báo cáo tổng hợp gồm detection rate của Wazuh, AI type accuracy, false-negative theo module, false-positive của baseline và p50/p95 ingest latency.

## 7. Backend và API

### 7.1 Thành phần đề xuất

- `security_test_catalog`: manifest 18 scenario, dependency, risk, timeout, expected telemetry/rules và cleanup.
- `security_test_runner`: consumer serial chuyên biệt cho preflight, seed, execute và cleanup; có global lock, SSH/Playwright executor allowlisted, deadline và watchdog cleanup.
- `security_test_evaluator`: query Indexer, liên kết AI job, so expected/actual và tạo kết quả bốn lớp.
- `security_test_store`: migration/tables SQLite `security_runs`, `security_run_events`, `security_evidence` và review; event append-only, không lưu credential/raw payload.
- Remote runner trên Kali chỉ nhận scenario ID allowlisted và luôn khóa target `.20`.

`security_test_runner` phải tách khỏi `dashboard_worker`. `dashboard_worker` hiện chỉ xử lý job phân tích alert (`fetching_alerts -> preparing_analysis -> calling_ollama -> saving_result`), vì vậy không được pha shell/SSH/Playwright control plane vào worker này. Khi security run tới phase `analyzing_ai`, runner tạo job AI hiện có với `job_type: security_test_analysis`, custom UTC window và lưu `security_runs.ai_job_id`; dashboard worker tiếp tục fetch Indexer và gọi `analysis_service`/Ollama như thường lệ. UI liên kết hai job qua ID nhưng giữ phase semantics riêng.

### 7.2 API tối thiểu

| Method | Endpoint | Mục đích |
|---|---|---|
| `GET` | `/api/security-tests/catalog` | Danh sách 18 scenario và khả năng chạy hiện tại |
| `GET` | `/api/security-tests/status` | Preflight của Kali, Victim, Wazuh, Indexer, Ollama và browser runner |
| `POST` | `/api/security-tests/runs` | Tạo một run từ `scenario_id` allowlisted và `confirm: true` |
| `GET` | `/api/security-tests/runs` | Lịch sử có phân trang/filter |
| `GET` | `/api/security-tests/runs/<id>` | Tiến trình, kết quả và evidence đã redact |
| `POST` | `/api/security-tests/runs/<id>/cancel` | Hủy run đang queued/waiting theo quy tắc an toàn |
| `POST` | `/api/security-tests/suites/safe` | Chạy tuần tự safe suite sau xác nhận |
| `GET` | `/api/security-tests/runs/<id>/export` | Xuất báo cáo JSON/CSV đã sanitize |

Request tạo run chỉ chấp nhận dữ liệu tương đương:

```json
{
  "scenario_id": "sql-injection",
  "confirm": true,
  "model": "qwen2.5:7b"
}
```

`model` là tùy chọn nhưng phải khớp chính xác allowlist server-side; khi bỏ qua,
runner dùng model mặc định. Không có trường `language`, `target`, `command`,
`payload`, `url`, `username`, `password` hoặc `script_path`.

### 7.3 Cấu hình local

- Target, SSH identity path, DVWA lab account, timeout và feature flag nằm trong config local đã gitignore hoặc secret manager.
- API response không trả lại SSH path, cookie, password, ModSecurity body hoặc exception có endpoint/credential.
- Kiểm tra same-origin, content type, request size và confirmation tương tự các mutation API hiện tại.
- Giới hạn một active run; safe suite cũng là một queue tuần tự.
- Dashboard restart không được làm mất run terminal; run dở dang được đánh dấu `interrupted` và cleanup/reconcile khi khởi động lại.

### 7.4 Kiến trúc multi-agent Terra + Luna

Mô hình này là **phân vai xây dựng và kiểm định kế hoạch**, không phải hai model tự do chạy attack. Orchestrator là nơi duy nhất tạo task, cấp ownership, chấp nhận artifact và cho phép promotion qua gate.

| Vai trò | Trách nhiệm bắt buộc | Không được làm |
|---|---|---|
| **Terra** | Lead architect/reasoner: inventory hệ thống, chốt invariant an toàn, manifest/schema, threat model, state machine, telemetry/AI contract, acceptance criteria; review artifact, adjudicate mismatch, quyết định promote/hold/escalate | Không chạy payload trực tiếp, không coi AI output là ground truth, không bỏ qua quality gate |
| **Luna** | Bounded implementer/validator: nhận một task nhỏ có ownership rõ; tạo catalog, fixture, runner module, decoder/rule fixture, adapter/API, evaluator hoặc UI; chạy test fake/lab được phê duyệt và trả evidence | Không mở rộng scope/target, không sửa ground truth, không bypass guardrail, không tự chuyển terminal state hoặc tự enable scenario |
| **Orchestrator** | Cấp task, khóa ownership, kiểm tra schema/digest, quản lý queue, ghi quyết định và gọi human approval khi cần | Không cho hai task cùng sửa một file/migration/schema hoặc cho stateful run chạy song song |
| **Human operator** | Xác nhận snapshot, feature flag, stateful/custom-rule change và live E2E promotion | Không ủy quyền target/payload tùy ý qua UI/API |

Mỗi task Terra giao Luna phải ghi rõ: mục tiêu, input artifact, output artifact, file/area ownership, risk class, test command, cleanup/recovery implication, manifest version và điều kiện handoff. Artifact thiếu schema version, producer, timestamp UTC hoặc content digest bị từ chối.

### 7.5 State machine, ownership và concurrency

Security run có phase riêng, append-only trong `security_run_events`:

```text
queued -> preflight -> seeding? -> attacking -> waiting_ingest
       -> querying_wazuh -> analyzing_ai -> cleanup -> completed
```

- Mọi event có `run_id`, actor (`runner`, `system`, `terra`, `luna`, `human`), UTC timestamp, manifest digest, prompt/model digest khi áp dụng và phase result đã sanitize.
- Chỉ `runner`/`system` đổi execution phase; evaluator ghi điểm các lớp; Terra chỉ approve/reject/route; Luna chỉ tạo artifact hoặc evidence trong task được giao.
- Cancel là cooperative: `queued`/`waiting_ingest` có thể hủy ngay; `attacking` kết thúc bounded step rồi cleanup. Không auto-retry attack sau cancel, timeout hoặc restart.
- Idempotency key là `run_id + phase`; restart chuyển run sang `interrupted`, reconcile/cleanup trước khi resume. Cleanup failure chuyển `failed` hoặc `needs_review`, không thể `passed`.
- Chỉ một active security run. Chỉ chạy song song test fake/stateless không dùng chung DB, account, session, file marker, upload directory, correlation window, source/target hoặc snapshot/rule reload. Scenario browser/stateful, migration, Wazuh rule reload và snapshot/restore phải serial.

### 7.6 Artifact và handoff contract

| Artifact | Trường tối thiểu | Quy tắc |
|---|---|---|
| `ScenarioManifest v1` | `schema_version`, `scenario_id`, `target_fixed`, `source_fixed`, `request_cap`, `timeout_s`, `dependencies`, `seed`, `execute_ref`, `cleanup_ref`, `telemetry_contract`, `expected_any`, `forbidden`, `ai_aliases`, `safe_suite`, `manifest_sha256` | Không chứa target/command/payload/URL tùy ý; 18 ID duy nhất |
| `RunEnvelope v1` | `run_id`, `scenario_id`, `manifest_sha256`, `start_utc`, `attack_end_utc`, `ingest_deadline_utc`, `analysis_end_utc`, `model`, `language`, `feature_flags` | Không chứa secret; ID opaque và UTC boundary bắt buộc |
| `EvidenceBundle v1` | execution outcome, request count/status, telemetry refs/hash, Wazuh rule refs, AI job/output hash/provenance, cleanup status | Chỉ refs/hash và display fields đã redact; cấm raw log/body/cookie/credential |
| `EvaluationResult v1` | điểm `execution`, `telemetry`, `wazuh`, `ai`; overall status; mismatch code; analyst note | Mỗi lớp độc lập; lưu producer, timestamp, schema/content digest |

Ground truth chỉ ở runner store riêng. Manifest phải phân loại scenario `safe_suite`/`manual_only`, `stateless`/`stateful`, `cli`/`browser`, `read_only`/`state_changing`, cần telemetry bắt buộc/tùy chọn và có/không cần snapshot restore.

### 7.7 Escalation và fail-closed

Chuyển run sang `blocked` hoặc `needs_review`, đồng thời báo Terra/human, khi có target/source lệch `.20`/`.30`, feature flag sai, dependency không xác định, cap/timeout sắp vượt, thiếu `run_id`, forbidden rule, cleanup lỗi, Ollama unavailable hoặc AI output không schema/không grounded. Luna không có quyền bypass các điều kiện này.

- **P0 - safety:** wrong target, arbitrary command, egress ngoài lab hoặc vượt cap. Dừng ngay, cleanup/watchdog, ghi incident note và chỉ mở lại sau human approval.
- **P1 - integrity:** cleanup/telemetry mismatch, clock boundary không tin cậy, missing evidence hoặc restart giữa stateful run. Không promote suite.
- **P2 - quality:** AI uncertainty, latency cao hoặc taxonomy mismatch. Đặt `partial`/`needs_review`, giữ evidence để Terra quyết định.

Terra có thể rollback manifest/rule và yêu cầu human approval cho scenario stateful hoặc custom Wazuh rule, nhưng không được tự nới guardrail.

## 8. Lộ trình triển khai

### Giai đoạn 0 - Chốt hợp đồng kiểm thử

- Xác nhận DVWA trên `.20`, Wazuh version, Apache log path, mức security DVWA và cách đăng nhập bằng tài khoản lab.
- Kiểm kê decoder/rule hiện có và chọn dải ID custom không xung đột.
- Tạo manifest cho 18 scenario gồm precondition, request cap, timeout, seed, execute, cleanup, expected telemetry, expected rule và AI alias.
- Chốt safe suite; mặc định loại các scenario stateful/browser chưa có cleanup đáng tin cậy.
- **Terra** thực hiện inventory read-only, threat model, transition table và chốt `ScenarioManifest v1`/`RunEnvelope v1`.
- **Luna** nhận task bounded để nhập 18 catalog entries và viết validator; không được sửa ground truth hoặc bật scenario.

**Hoàn thành khi:** manifest được validate tự động và không scenario nào có target/payload tùy ý.

**Gate A - Terra design:** schema/manifest lint, property test transition, target allowlist, feature flag OFF mặc định và threat-model review đều đạt.

### Giai đoạn 1 - Dựng telemetry trước khi dựng nút chạy

- Bổ sung test access log mang opaque `run_id`.
- Cấu hình Wazuh agent đọc Apache, ModSecurity và app audit JSON.
- Bổ sung decoder/rule và fixture log cho từng logical detection.
- Chạy baseline và `wazuh-logtest`, xác nhận không lộ scenario ground truth cho AI.
- **Luna** triển khai fixture app-audit JSON, decoder/rule fixture, redaction test và correlation `run_id`; Terra review event contract và false-positive baseline.

**Hoàn thành khi:** mỗi scenario có ít nhất một nguồn log quan sát được hoặc được đánh dấu SKIP với dependency cụ thể.

**Gate C - Telemetry:** fixture decoder/rule và `wazuh-logtest` pass; event schema, correlation, baseline và forbidden-rule checks pass.

### Giai đoạn 2 - Xây runner an toàn

- Tái sử dụng `ssh-bruteforce.sh` và các mode bounded của `web-attack.sh` nơi phù hợp.
- Tách các scenario mới thành script/module nhỏ, tham số cố định và có cleanup idempotent.
- Dùng Playwright cho DOM XSS, reflected/stored XSS, CSRF, CSP và JavaScript logic.
- Thêm preflight, serial queue, per-step timeout, UTC boundary và evidence manifest.
- **Luna** xây fake executor trước, sau đó mới adapter SSH/Playwright bounded; Terra kiểm tra shell boundary, hash allowlist, idempotent cleanup và kill switch.

**Hoàn thành khi:** chạy CLI từng scenario tạo cùng một schema kết quả và luôn cleanup được khi step lỗi.

**Gate B - Luna unit/static:** shell/JS syntax, 18 ID duy nhất, request/size limits, redaction và fake executor chứng minh browser input không đi vào subprocess args.

### Giai đoạn 3 - Xây backend orchestration

- Thêm store migration, catalog/status/run/detail/cancel/export API.
- Liên kết run với custom-window AI job hiện có, không tạo một pipeline AI thứ hai.
- Query Indexer theo UTC window và correlation fields; lưu alert reference đã redact.
- Thêm evaluator bốn lớp và analyst review.
- **Luna** triển khai migration/API/store/evaluator/UI adapter theo ownership đã cấp; Terra review mapping với `dashboard_worker`, `dashboard_store`, `analysis_service` và recovery semantics.

**Hoàn thành khi:** integration test dùng fake SSH/Indexer/Ollama chứng minh luồng success, no-alert, timeout, interrupted và cleanup failure.

**Gate D - Integration:** fake SSH/Indexer/Ollama pass cho success, no-alert, timeout, AI unavailable, cleanup failure, duplicate submission và restart; không có attack retry ngoài ý muốn.

### Giai đoạn 4 - Xây trang `/security-tests`

- Tạo danh sách 18 card, filter, preflight panel và confirmation dialog.
- Poll phase thật, không dùng progress giả.
- Hiển thị kết quả từng lớp, alert evidence, AI result, mismatch reason và link tới dashboard job.
- Bổ sung lịch sử, safe suite và export.
- Kiểm tra desktop/mobile, keyboard focus, screen reader label và escaped untrusted text.

**Hoàn thành khi:** người dùng có thể chạy một scenario từ nút, theo dõi tới kết quả và hiểu chính xác lớp nào PASS/FAIL.

Luna phải bổ sung test cho double-click, mất polling (`connection_lost`), focus trap, `aria-live`, viewport hẹp, HTML trong evidence và export redaction. Terra duyệt wording confirmation, lý do disabled và không để badge tổng che khuất lớp lỗi.

### Giai đoạn 5 - E2E lần lượt theo nhóm

1. Brute Force và web signature có sẵn để chứng minh framework.
2. SQL Injection, Blind SQLi, File Inclusion, Command Injection và Reflected XSS.
3. CSRF, File Upload, CAPTCHA, Weak Session IDs, Stored XSS và Authorisation Bypass.
4. DOM XSS, CSP Bypass, JavaScript Attacks, Open Redirect, Cryptography và API.

Không mở toàn bộ 18 nút ở trạng thái enabled cùng lúc. Chỉ enable scenario sau khi telemetry, Wazuh rule, cleanup và acceptance test của chính scenario đó đã PASS.

**Gate E - Lab smoke:** preflight mọi dependency, chỉ chạy ba MVP scenario đầu tiên theo thứ tự serial, chờ ingest tối đa 120 giây, đối chiếu trực tiếp Indexer bằng `run_id`/agent/source IP; Terra ký duyệt trước khi mở nhóm kế tiếp.

### Giai đoạn 6 - Tài liệu và vận hành

- Cập nhật manual test với dependency, snapshot, cấu hình log, rule mapping và troubleshooting.
- Ghi rõ output AI chỉ là tư vấn, không phải bằng chứng exploit thành công.
- Tạo runbook cleanup/recovery và retention cho test history.
- Ghi version của scenario manifest, Wazuh ruleset, model và prompt trong mỗi export để tái lập kết quả.
- **Gate F - Release:** unit/API/UI, `compileall`, `node --check`, secret scan, `git diff --check`, export schema/redaction snapshot và rollback/snapshot verification đều đạt.

### 8.1 Phân rã task và vòng lặp Terra

Orchestrator phân rã theo thứ tự, mỗi task có một owner duy nhất:

1. Terra inventory dashboard/Wazuh, chốt manifest/schema, state transition và threat model (read-only).
2. Luna xây catalog 18 scenario, dependency/preflight/risk/cap/timeout/seed/execute/cleanup/expected/forbidden/AI aliases và validator unit tests.
3. Luna xây telemetry contract, app JSON audit, Apache/ModSecurity/FIM/browser-beacon fixtures, decoder/rule fixture và `wazuh-logtest`.
4. Luna xây runner bounded với fake executor, allowlisted SSH/Playwright, evidence bundle và cleanup idempotent.
5. Luna xây backend adapter/store migration/API/recovery và test fake SSH/Indexer/Ollama.
6. Luna xây evaluator/UI/history/export và UI tests.
7. Terra chạy integration review, MVP smoke, so expected/actual và quyết định promote/hold/escalate.

Vòng lặp quyết định của Terra là:

```text
inventory -> model invariants -> decompose -> assign Luna task
         -> validate artifact/schema -> run lowest-risk gate
         -> compare expected/actual -> promote | hold | escalate
         -> record decision
```

Rationale chỉ ghi ngắn gọn dựa trên evidence (không lưu chain-of-thought), kèm manifest/model/prompt digest và reviewer. Luna bàn giao diff/commit, test command, fixture/evidence, known gaps và content digest; không tự sửa file ngoài ownership. Nếu phát hiện thay đổi bất ngờ trong vùng agent khác sở hữu, dừng và yêu cầu handoff, không revert.

## 9. Kế hoạch kiểm thử phần mềm

### 9.1 Unit test

- Catalog có đúng 18 ID duy nhất và schema hợp lệ.
- Không scenario nào nhận target/command/payload tùy ý.
- Validator từ chối model ngoài allowlist, thiếu confirmation, JSON quá lớn và scenario không tồn tại.
- State machine chỉ cho transition hợp lệ.
- Evaluator xử lý đúng expected-any, forbidden rule, missing telemetry, timeout và AI uncertainty.
- Redaction loại credential, cookie, Authorization header, raw POST body và private key path.

### 9.2 API/integration test

- Feature flag tắt thì không thể tạo run.
- Một active run làm run thứ hai vào queue hoặc bị từ chối theo policy đã chốt.
- Fake remote executor không bao giờ nhận input shell do browser cung cấp.
- Indexer timeout tạo `partial/failed` đúng lớp, không tự chạy lại attack.
- AI unavailable vẫn giữ evidence Wazuh và báo AI SKIP/FAIL riêng.
- Cleanup failure luôn hiển thị nổi bật và ngăn run tổng thể thành `passed`.
- Restart/recovery không chạy lại tấn công ngoài ý muốn.

### 9.3 UI test

- Hiện đủ 18 card, đúng tiếng Việt và đúng trạng thái enabled/disabled.
- Confirmation hiển thị target/request cap/cleanup trước khi POST.
- Double click không tạo hai run.
- Progress, cancel, safe suite, history, filter, export và link AI job hoạt động.
- Nội dung log/AI chứa HTML chỉ hiển thị như text, không thực thi XSS trên chính dashboard.
- Layout hoạt động ở desktop và mobile.

### 9.4 Lab E2E

- Chạy baseline trước và sau từng nhóm.
- Chạy từng scenario, chờ ingest tối đa 120 giây rồi mới chạy scenario tiếp theo.
- Đối chiếu trực tiếp Indexer rule/time/source/run ID, không chỉ nhìn dashboard.
- Xác minh dữ liệu seed, file marker, comment Stored XSS, upload và session test đã cleanup.
- Lưu bảng PASS/FAIL/SKIP, rule thực tế, latency và AI mismatch sau mỗi run.

### 9.5 Validation, negative test và release gate

- Contract test cho catalog, `RunEnvelope`, phase event, `EvidenceBundle` và export schema; mọi artifact phải có schema/content digest.
- Property/fuzz test API với field dư, kiểu dữ liệu sai, Unicode/HTML, JSON lớn, duplicate request và replay confirmation.
- Negative test bắt buộc: target ngoài `.20`, source ngoài `.30`, scenario ngoài allowlist, command/payload/URL tùy ý, thiếu feature flag, egress mở và executable hash sai đều phải bị từ chối trước execute.
- Seed/cleanup phải idempotent và được gọi khi timeout, cancel, exception, mất SSH, restart hoặc crash; cleanup failure phải làm tổng thể `failed`/`needs_review`.
- Test clock skew và UTC boundary để không ghép alert của run khác; query trễ, duplicate alert, forbidden rule và thiếu `run_id` phải được đánh giá riêng.
- Test AI unavailable, output sai schema, hallucinated success, evidence mâu thuẫn và `needs_review`; AI không được tự nâng kết quả lên PASS.
- Mỗi release chỉ enable scenario sau khi unit + API + UI + fake integration + lab E2E của scenario đó đạt gate tương ứng.
- Ghi reproducibility bundle: manifest hash, ruleset version, model/prompt version, dependency versions và snapshot ID.

### 9.6 Ma trận kiểm thử và handoff

Ma trận chuẩn cần có các cột:

`scenario_id | precondition | execution_oracle | telemetry_source/event | expected_any | forbidden | cleanup_check | ai_checks | dependency | layer | result | evidence_id`

Mỗi scenario phải được gắn nhãn `safe_suite`/`manual_only`, `stateless`/`stateful`, `cli`/`browser`, `read_only`/`state_changing`, telemetry bắt buộc/tùy chọn và yêu cầu snapshot/restore. Ma trận chung phải bao gồm happy path, wrong target, missing dependency, timeout, no telemetry, delayed ingest, forbidden alert, AI unavailable, cleanup failure, restart recovery và duplicate submission.

Handoff Terra/Luna dùng mẫu tối thiểu:

```yaml
task_id: ST-000
owner: luna
input_artifacts: [ScenarioManifest-v1]
output_artifacts: [EvidenceBundle-v1, test-report]
files_owned: [path/to/module]
risk: P1
commands: ["python -m pytest ..."]
known_gaps: []
content_sha256: "..."
ready_for_review: true
```

Terra chỉ promote khi artifact schema hợp lệ, test evidence tái lập được và không có P0/P1 chưa giải quyết. Luna không được tự thay đổi expected result để làm bài test PASS.

## 10. Tiêu chí hoàn thành toàn bộ

- Trang `/security-tests` có đủ 18 module và chỉ scenario đã sẵn sàng mới có thể chạy.
- Không có đường đi từ input browser tới arbitrary shell, target ngoài lab hoặc payload tùy ý.
- Mỗi run có correlation ID, UTC window, request cap, timeout, cleanup và audit trail.
- Mỗi module có baseline, telemetry contract, Wazuh expected rule và tiêu chí AI riêng.
- Kết quả hiển thị riêng execution/telemetry/Wazuh/AI, kèm lý do mismatch có thể kiểm chứng.
- Tất cả unit/API/UI tests pass; mỗi scenario enabled có ít nhất một lab E2E PASS đã ghi evidence.
- Không để lại file/comment/account/session seed sau test; không lưu hoặc xuất secret/raw sensitive log.
- Safe suite chạy tuần tự, không chứa scan volume lớn và không tự retry attack.
- Báo cáo cuối cho biết Wazuh bắt đúng bao nhiêu scenario, AI nhận diện đúng bao nhiêu scenario, false positive/false negative và latency ingest.
- Mọi minh họa chỉ dùng fixture/marker bounded trong lab cô lập; không dùng tài liệu này để nhắm mục tiêu ngoài lab.

## 11. Thứ tự MVP đề xuất

MVP đầu tiên chỉ cần chứng minh trọn luồng với ba scenario đại diện:

1. `brute-force`: tái sử dụng script và Wazuh rule đang có.
2. `sql-injection`: tái sử dụng web signature bounded, bổ sung correlation ID và telemetry rõ ràng.
3. `xss-reflected`: kết hợp ModSecurity/Wazuh với browser beacon để chứng minh cả request và thực thi phía browser.

Sau khi ba scenario này đi hết luồng `nút -> attack -> log -> Wazuh -> AI -> PASS/FAIL -> cleanup`, mới mở rộng theo Giai đoạn 5. Cách này kiểm tra được kiến trúc chung trước khi đầu tư vào các module stateful và browser phức tạp.
