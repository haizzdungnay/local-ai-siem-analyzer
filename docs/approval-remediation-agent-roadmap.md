# Kế hoạch agent điều tra và khắc phục có phê duyệt

Ngày chốt: **2026-11-16** (Asia/Saigon). Baseline: `main@7628921f2ba871d9f8b29499f68a293819647a56`.

Trạng thái: **ĐÃ THỐNG NHẤT HƯỚNG THIẾT KẾ / CHƯA TRIỂN KHAI**. Yêu cầu hiện tại là lập kế hoạch và commit vào `main`; không cấp quyền cho phần mềm thực thi hành động trên lab. Mọi mục R0–R6 bên dưới đều chưa nghiệm thu trong tài liệu này.

Tài liệu triển khai bổ sung: [hướng dẫn giải quyết 17 issue R0–R6](approval-remediation-implementation-guide.md), gồm dependency, điểm sửa trong code, phương án, kiểm thử và điều kiện đóng issue; theo dõi tại [Epic #10](https://github.com/haizzdungnay/local-ai-siem-analyzer/issues/10). Hướng dẫn cũng đối chiếu phần phối hợp #23 và review playbook #29.

## 1. Mục tiêu và quyết định phạm vi

Mở rộng mô-đun AI local thành vòng xử lý: yêu cầu của người vận hành → điều tra có bằng chứng → đề xuất kế hoạch → duyệt hai bước qua Telegram hoặc trang web từ email → thực thi có giới hạn → kiểm chứng → báo cáo và hoàn tác.

- Làm agent điều tra chỉ đọc trước, sau đó bổ sung executor khắc phục có phê duyệt.
- Telegram là kênh tương tác MVP; email thông báo và dẫn tới trang duyệt có xác thực ở giai đoạn tiếp theo.
- Hai bước duyệt: **Duyệt kế hoạch** rồi **Xác nhận thực thi** trên cùng phiên bản và nội dung. Hai lần bấm không được coi là hai yếu tố xác thực.
- Mỗi thay đổi có ý nghĩa về hành động, đích, tham số, quyền, ảnh hưởng hoặc hoàn tác phải tạo phiên bản mới và xin duyệt lại.
- LLM đề xuất action ID và tham số có cấu trúc. Executor chỉ nhận hành động từ registry do code quản lý; không chạy shell/script do model hay alert sinh ra.
- MVP thực thi duy nhất `block_source_ip_temporary` trên một victim Linux lab; thời hạn mặc định 300 giây, trần MVP 600 giây. Thu thập bằng chứng là quyền đọc riêng, không phải hành động khắc phục.
- Khóa tài khoản, cô lập máy, sửa cấu hình thật, xóa file, restart dịch vụ và nhiều máy cùng lúc nằm ngoài MVP; chỉ mở sau nghiệm thu riêng.
- Giữ phân biệt **containment tạm thời** với **khắc phục nguyên nhân gốc**. Chặn IP thành công không chứng minh đã loại bỏ xâm nhập.

Quyết định này mở một giai đoạn có ghi mới, sau quyết định agent chỉ đọc trong HANDOFF ngày 07/11. Runtime hiện tại vẫn giữ hành vi cũ cho tới khi các gate triển khai đạt. Không thay đổi model mặc định, rule, cổng hay trạng thái lab trong commit kế hoạch.

## 2. Hiện trạng đã đối chiếu với code

| Thành phần | Đang có tại baseline | Cần bổ sung |
|---|---|---|
| Nguồn bằng chứng | `reader.py`, Wazuh Indexer/OpenSearch `:9200` | Truy vấn điều tra cố định, ngân sách và evidence snapshot |
| Phân tích | `analysis_service.py`, `llm.py`, playbook exact lookup cho từng alert | Kế hoạch máy đọc được và tích hợp phân tích cửa sổ |
| Playbook | 28 bản draft; 3 bản có signals | Review trên lab, điều kiện bằng chứng và action mapping |
| Trạng thái | `dashboard_store.py`, SQLite schema v9, job/review/delivery | Bảng request/plan/approval/execution riêng, migration cộng thêm |
| Telegram | `telegram_notifier.py`: gửi report/test, chưa nhận callback | Poller nhận update, binding người duyệt, xác nhận hai bước |
| Gmail | `gmail_notifier.py`: SMTP outbound | Email kế hoạch và link tới trang duyệt; không đọc email trả lời |
| Web | Flask/Waitress loopback, Host/Origin checks | Danh tính operator, session, CSRF, re-authentication và approval UI |
| Thực thi | Chưa có executor khắc phục | Adapter Wazuh Active Response được giới hạn và kiểm thử |

Wazuh Manager API `:55000` nếu dùng để dispatch Active Response là đường điều khiển riêng; alert vẫn đọc từ Indexer `:9200`. Phải xác minh phiên bản Wazuh, API, script và quyền tối thiểu trên lab trước khi chốt adapter; tài liệu này không giả định endpoint/rollback đã chạy được.

CI cho bản sửa `71787ec` đã được upstream ghi nhận xanh 4/4 matrix. Các lỗi correctness, SFT leakage và thiết kế phép thử B/C chưa vì thế được coi là đã sửa. SFT leakage là gate trước huấn luyện; việc này không thay thế gate an toàn executor.

## 3. Luồng sử dụng đã chốt

1. Operator chọn cảnh báo/job và bấm **Yêu cầu điều tra và lập kế hoạch**. Tự động phát hiện cảnh báo chỉ được tạo thông báo/đề xuất theo cấu hình; không tự cấp quyền ghi.
2. Agent chạy công cụ chỉ đọc trong scope request: đúng agent, khoảng thời gian và số truy vấn. Thiếu bằng chứng thì nêu thiếu hoặc yêu cầu xác minh, không bịa kết quả.
3. Server dựng bản kế hoạch bất biến, phân loại rủi ro bằng policy, gửi tóm tắt đã giảm dữ liệu qua kênh đăng ký.
4. Operator chọn **Duyệt kế hoạch**. Server ghi nhận bước xem/duyệt thứ nhất; chưa có quyền thực thi. Tạo challenge riêng cho lần xác nhận cuối.
5. Hiện lại đối tượng, hành động, thời hạn, ảnh hưởng, điều kiện dừng và hoàn tác. Operator bấm **Xác nhận thực thi**; hành động rủi ro cao cần xác thực bổ sung qua trang web.
6. Backend xác minh người duyệt, quyền, challenge, plan hash, thời hạn và precondition. Chỉ sau đó mới atomically ghi approval và tạo execution job.
7. Trước từng bước, executor kiểm tra lại phạm vi và trạng thái đích. Đúng kế hoạch thì chạy; có thay đổi vượt phạm vi thì dừng phần ghi, lập phiên bản mới và lặp lại bước 3–5.
8. Kiểm chứng tác động bằng dữ liệu hệ thống đáng tin cậy; gửi kết quả, trạng thái cleanup và phần còn chưa giải quyết. Nếu không xác minh được, ghi `unverified`, không báo thành công.

Thông báo có nút **Xem kế hoạch / Duyệt kế hoạch / Từ chối**. Lượt hai dùng nút **Xác nhận thực thi / Quay lại / Hủy**. Không bắt operator duyệt từng bước đã nằm trong cùng kế hoạch còn hiệu lực, trừ checkpoint được policy chỉ định trước.

## 4. Nội dung kế hoạch và hợp đồng quyền

Server lưu ít nhất:

- `plan_id`, `version`, `request_id`, `job_id`, thời điểm tạo và phiên bản policy.
- Evidence reference có identity, cửa sổ thời gian, hash, thời điểm thu thập và thông tin coverage/partial. Nội dung log là untrusted data.
- Actor model/provider/prompt/playbook provenance; không dùng confidence của model làm điều kiện duy nhất cấp quyền.
- Danh sách step: `step_id`, `action_id`, script version/digest, target agent identity, tham số đã chuẩn hóa, precondition, expected effect, risk, quyền tối thiểu, timeout, retry policy, verifier và rollback.
- Phạm vi được phép, tài sản/IP quản trị được bảo vệ, tổng số đích/bước, giới hạn tác động, checkpoint và thời hạn bắt đầu thực thi.
- `plan_sha256` từ canonical server-side representation của toàn bộ nội dung có ý nghĩa thực thi, evidence references và policy/script versions. Thay đổi cách trình bày thuần túy không tạo quyền mới.

Giá trị thiết kế ban đầu: tối đa 6 truy vấn đọc/request, 30 giây/truy vấn, 3 bước ghi/kế hoạch và 1 đích. Phê duyệt/challenge có hạn 10 phút; execution authorization có deadline tuyệt đối 15 phút kể từ xác nhận cuối. Đây là policy dự kiến, phải đo và tinh chỉnh có version ở R1–R2.

Trước mỗi bước ghi, xác minh evidence còn đủ mới theo action policy (MVP tối đa 60 giây kể từ lần preflight cuối), target identity và state fingerprint. Hết deadline thì dừng bước mới và xin duyệt kế hoạch cập nhật. Cleanup đã được duyệt trong kế hoạch vẫn phải chạy đến khi hoàn tất hoặc được báo lỗi rõ ràng.

Registry ánh xạ action ID tới script/capability cố định. Model không được chọn executable, endpoint, command string hoặc credential. Backend tự ánh xạ target từ inventory và kiểm tra policy; giá trị alert không được trực tiếp biến thành quyền quản trị.

## 5. Trạng thái, chống chạy lặp và khôi phục

| Entity | Trạng thái dự kiến | Điều kiện chuyển chính |
|---|---|---|
| Request | `requested`, `investigating`, `needs_evidence`, `planned`, `cancelled` | Scope đọc hợp lệ, công cụ có ngân sách |
| Plan | `draft`, `awaiting_review`, `awaiting_confirmation`, `approved`, `rejected`, `expired`, `superseded` | Theo đúng hai bước; bản bị thay thế không dùng lại |
| Execution | `queued`, `preflight`, `executing`, `verifying`, `succeeded`, `failed`, `paused_for_reapproval`, `cancelled`, `uncertain` | Final gate trên server trước mỗi tác động |
| Rollback | `not_needed`, `scheduled`, `running`, `verified`, `failed`, `uncertain` | Theo quyền cleanup cụ thể đã duyệt |

- Approval một lần gắn với plan version/hash, operator identity, channel, risk scope và deadline; không lưu bearer/challenge thô vào audit/export.
- Trong một transaction SQLite: compare-and-set trạng thái, tiêu thụ challenge, ghi audit và enqueue execution. Unique constraint chặn hai kênh tạo hai job cho cùng approval.
- Poller lưu update offset cùng việc ghi inbox event bền vững; callback trùng/out-of-order được deduplicate theo provider event identity và kiểm tra trạng thái hiện tại.
- Mỗi step có idempotency key và journal trước/sau dispatch. Không tuyên bố exactly-once cho tác động ngoài DB: mất response sau dispatch là `uncertain`, phải reconcile trạng thái thực trước khi retry.
- Crash/restart không tự cấp quyền hoặc tự chạy lại bước chưa rõ kết quả. Job chưa dispatch chỉ được tiếp tục sau kiểm tra approval/deadline/precondition còn hợp lệ.
- Khóa thực thi theo tài sản/action resource để hai kế hoạch không sửa cùng firewall rule đồng thời. Kiểm thử cả hai worker và hai kênh duyệt cạnh tranh.
- Từ chối, thu hồi, hết hạn và emergency stop chặn mọi bước ghi chưa bắt đầu. Emergency stop không hứa đảo ngược tác động đang diễn ra; hiển thị rõ trạng thái và tiếp tục cleanup đã được cho phép.
- Lưu UTC; UI hiển thị Asia/Saigon. Đồng hồ bất thường hoặc không thể kiểm tra thời hạn thì không dispatch bước mới.

## 6. Khi nào cần xin duyệt lại

| Thay đổi/sự kiện | Quyết định bắt buộc |
|---|---|
| Bước kế tiếp đúng plan/hash, precondition và deadline | Tiếp tục; không hỏi lại dư thừa |
| Thêm bước, đổi action/script/policy version hoặc tăng quyền | Bản mới, duyệt lại hai bước |
| Đổi máy/IP/user/file đích, kéo dài thời hạn, tăng số đích | Bản mới, duyệt lại hai bước |
| Precondition đổi hoặc evidence thiếu/cũ/partial ngoài giới hạn action | Dừng ghi, điều tra lại; tái xác minh hoặc gửi kế hoạch mới |
| Một bước thất bại, model muốn dùng phương án khác | Không fallback tùy ý; kế hoạch mới |
| Retry đúng action | Chỉ theo retry policy đã duyệt, còn hạn và đã reconcile; không retry mù khi uncertain |
| Khóa tài khoản, cô lập máy, cấu hình dịch vụ quan trọng | Ngoài MVP; tương lai cần re-authentication và policy riêng |
| Hoàn tác đúng resource/handle đã tạo, đã ghi trong plan | Được thực hiện theo quyền cleanup đã duyệt |
| Hoàn tác cần sửa thêm tài nguyên hoặc vượt phạm vi cũ | Dừng phần mở rộng và xin duyệt riêng |

Policy tính risk từ capability, asset criticality, phạm vi, khả năng đảo ngược và tác động vận hành. Nhãn rủi ro từ LLM chỉ là đầu vào tham khảo. Không thể hạ risk bằng thao tác client hoặc bằng chọn kênh Telegram thay cho web.

## 7. Telegram, email và danh tính người duyệt

### Telegram MVP

- Poller outbound long polling qua Bot API; không mở inbound listener vào dashboard. Phải kiểm tra bot chưa có webhook xung đột trước khi cấu hình poller.
- Một consumer chủ động cho bot, leadership/lease và backoff có giới hạn. Tách inbox approval khỏi delivery queue hiện có để gửi report không làm mất callback.
- Pairing do operator đăng nhập trên host bắt đầu, mã ngẫu nhiên ngắn hạn một lần, host xác nhận Telegram numeric user ID/private chat trước khi kích hoạt. Không tự cấp quyền vì người đó biết bot username, chat ID hoặc mã bị forward.
- Callback chỉ chứa opaque handle ngắn đủ giới hạn Bot API; server tra dữ liệu thật. Không chứa command, credential hoặc toàn bộ plan.
- Kiểm tra `from.id`, private chat binding, quyền action, message/plan version, handle và thời hạn ở cả hai lượt. Không dùng display name/username làm identity; không duyệt trong group MVP.
- Cập nhật message thành đã duyệt/từ chối/hết hạn để giảm bấm nhầm; server vẫn từ chối callback cũ dù chỉnh message thất bại.
- Hành động cần step-up phải mở authenticated web approval; hai callback Telegram liên tiếp không thay cho MFA.

### Email và trang duyệt

- Dùng notifier SMTP hiện có để gửi bản tóm tắt đã giảm dữ liệu và nút **Xem kế hoạch**. Không xử lý trả lời mail như cấp quyền.
- `GET` link chỉ hiển thị trang; không duyệt, không consume challenge và không chạy tác động. Preview/link scanner không làm đổi trạng thái.
- Link chỉ mang handle không cấp quyền; người mở phải đăng nhập đúng operator. POST duyệt/xác nhận/hủy phải có session, CSRF và kiểm quyền server-side.
- Session phải hết hạn, cookie an toàn theo transport, logout/revocation và re-authentication cho action policy yêu cầu. Không tái sử dụng bot credential làm operator login secret.
- Người nhận mail và Telegram user binding là cấu hình riêng; gửi mail/report thành công không chứng minh người nhận có quyền thực thi.
- MVP web giữ loopback. Duyệt từ điện thoại qua link chỉ nghiệm thu sau khi có đường truy cập riêng có xác thực và TLS phù hợp; không đổi bind/public tunnel chỉ để link dùng được. Bổ sung bảo vệ mọi endpoint nhạy cảm có thể tiếp cận, gồm cả settings cũ.

### Nội dung outbound và lỗi kênh

- Chỉ gửi thông tin operator cần quyết định: mã kế hoạch, loại hành động, alias tài sản, bằng chứng đã tóm tắt, ảnh hưởng, thời hạn, rollback. Không gửi raw log, mật khẩu gõ nhầm, prompt, private reasoning hoặc khóa quản trị.
- Cả hai kênh dùng cùng approval service/state. Chuyển tiếp message/link không mang theo quyền; hai kênh cùng bấm chỉ một execution được tạo.
- Kênh mất kết nối: giữ pending và cho operator xem trên dashboard; quá hạn thì expire. Không phản hồi không bao giờ có nghĩa đồng ý; không tự fallback sang kênh yếu hơn.
- Cấu hình pairing/revocation và secret storage tiếp tục theo cơ chế local bảo vệ file; redaction phải được kiểm trên message, callback error, URL và audit.

## 8. Executor MVP, kiểm chứng và hoàn tác

`block_source_ip_temporary` chỉ hoạt động trong inventory lab đã đăng ký, với identity agent cố định và IPv4 hợp lệ. Policy từ chối địa chỉ/phạm vi của manager, host quản trị, gateway, DNS cần thiết, loopback, multicast/broadcast và các tài sản được bảo vệ; inventory/policy không do model chỉnh.

Trước dispatch: xác minh agent identity/trạng thái, nguồn IP từ evidence, scope được duyệt, kết nối quản trị dự phòng, trạng thái firewall hiện tại và khả năng rollback. NAT/shared source phải được nêu trong ảnh hưởng; nếu không xác định được tác động thì không đủ điều kiện thực thi MVP.

- Ưu tiên adapter Wazuh Active Response; kiểm phiên bản, quyền dispatch và script stateful trên lab. Không dùng tùy chọn thực thi trên mọi agent.
- Script được triển khai/version hóa trước, kiểm integrity và chỉ có capability đã định nghĩa. Không cung cấp generic SSH/root shell cho LLM.
- Tạo rule có ownership/handle riêng; nếu đã có rule tương tự của người khác thì không nhận quyền sở hữu hoặc xóa nó. TTL gắn với resource đã tạo, không reset do callback trùng.
- Bằng chứng thành công: dispatch receipt chỉ là đã nhận yêu cầu; cần kiểm tra rule đúng trên endpoint và probe kiểm soát đúng luồng bị chặn, đồng thời đường quản trị vẫn hoạt động. Alert giảm không đủ chứng minh chặn thành công.
- Sau 300 giây mặc định: gỡ đúng rule thuộc execution và kiểm tra đã gỡ. Cleanup cần tồn tại bền vững và hoạt động khi LLM/dashboard dừng; nghiệm thu cả crash của thành phần thực thi. Không bảo đảm TTL chỉ bằng một thread/sleep trong Flask.
- Mất liên lạc hoặc cleanup lỗi: `uncertain`/`rollback_failed`, cảnh báo qua kênh còn hoạt động, cung cấp runbook phục hồi thủ công; không báo đã khôi phục khi chưa kiểm chứng.
- Từng bước có expected effect, verifier, giới hạn thời gian và phân loại kết quả. Báo cáo phân biệt `dispatched`, `effect_verified`, `rollback_verified` và incident còn cần điều tra.

## 9. Thành phần, persistence và API dự kiến

Các tên dưới đây là thiết kế đề xuất, chưa phải file/endpoint hiện có:

| Thành phần dự kiến | Trách nhiệm |
|---|---|
| `ai_module/investigation_service.py` | Tool registry chỉ đọc, query budget và evidence snapshots |
| `ai_module/remediation_planner.py` | Chuyển đề xuất LLM thành plan schema, kiểm evidence/action mapping |
| `ai_module/approval_service.py` | Identity, hai lượt duyệt, policy, hash, expiry, revoke và enqueue |
| `ai_module/remediation_store.py` | Migration cộng thêm và transaction/journal; dùng cùng SQLite lifecycle |
| `ai_module/remediation_worker.py` | Preflight, execution lease, reconcile, verifier và cleanup |
| `ai_module/telegram_approval.py` | Poller/pairing/callback adapter, không tự thực thi |
| `ai_module/remediation_actions/` | Registry và adapter/script contract đã review |
| `ai_module/blueprints/approvals.py` | Authenticated UI/API cho plan và quyết định |

Bảng dự kiến: `remediation_requests`, `remediation_plans`, `plan_steps`, `approval_challenges`, `plan_approvals`, `action_executions`, `action_events`, `approval_inbox`, `approval_outbox`, `operator_channel_bindings`. Thêm unique constraints cho callback identity, approval enqueue và step idempotency. Chỉ lưu digest của challenge, không credential thực thi.

Recheck schema trước triển khai: baseline là v9 nhưng gateway cũng dự kiến migration; không hardcode cả hai nhánh cùng v10. Backup/restore và đọc dữ liệu job/report cũ phải pass. Retention không xóa approval/journal/cleanup chưa kết thúc; lưu alias và evidence reference theo export policy, hạn chế nội dung nhạy cảm.

API dự kiến: `POST /api/remediation/requests`, `GET /api/remediation/plans/<id>`, `POST .../review`, `POST .../confirm`, `POST .../reject`, `POST .../revoke`, `GET .../executions`, `POST .../stop`, `POST .../rollback`. GET không mutation. Channel adapter gọi cùng service; browser không tự quyết trạng thái bằng tham số `confirm: true` đơn lẻ.

Cờ cấu hình tương lai: `remediation.enabled: false` mặc định; tách `mode: dry_run|approved_execution`, action/target allowlist, approver binding và policy version. Production activation cần operator bật rõ ràng sau gate; cả dry-run phải hiển thị là mô phỏng, không được dùng làm evidence thao tác thật.

## 10. Lộ trình triển khai và gate nghiệm thu

| Giai đoạn | Việc thực hiện | Gate bắt buộc |
|---|---|---|
| **R0 — Chốt baseline** | Rà lại CI, lỗi severity/nhánh chưa xác minh, response Indexer partial, timeline và retrieval; review playbook pilot và freeze protocol | CI xanh; correctness findings có regression hoặc quyết định phạm vi rõ; chưa bật executor |
| **R1 — Agent điều tra** | Tool chỉ đọc cố định, evidence/coverage/partial, request scope, budget; kết nối playbook với luồng window | Held-out attack/benign; không đoán query chưa chạy; prompt injection không đổi tool/đích/ngân sách |
| **R2 — Approval core và dry-run** | Plan schema, policy/action registry, migration, operator auth/session/CSRF, hai bước xác nhận, expiry/revoke và journal | Mock executor: không có tác động trước xác nhận cuối; đổi hash/đích/role/replay/race đều bị chặn |
| **R3 — Telegram tương tác** | Pairing trên host, poller, inbox/outbox, review/confirm/reject/expire, trạng thái đồng bộ dashboard | Sai user/chat, forward, update trùng/cũ, mất mạng/restart và hai kênh cạnh tranh đều không vượt quyền |
| **R4 — Một hành động lab thật** | Deploy adapter/script version hóa; block IP tạm, preflight, ownership, effect verifier và cleanup | Dry-run đạt trước; operator bật scope lab; demo duyệt thật, block thật, bảo toàn quản trị, un-block thật và crash recovery |
| **R5 — Email và duyệt web** | Email link, authenticated page, risk step-up; đường truy cập riêng nếu cần mobile | Link scanner/GET không cấp quyền; CSRF/session/user/hash/expiry được kiểm; không mở endpoint cũ thiếu auth |
| **R6 — Đánh giá và phát hành** | Thử đối chứng, runbook, báo cáo, kill switch, restore test; quyết định có mở action khác không | Replay độc lập, reviewer xác nhận, CI đầy đủ, lỗi/giới hạn ghi factual; không mặc định mở action mới |

Thứ tự bắt buộc: R0 → R1 → R2 → R3 → R4; R5 triển khai trên nền R2 và hoàn thành trước khi nghiệm thu email approval. R6 chốt phạm vi đã hoàn thành. Không chờ toàn bộ gateway hoặc QLoRA để làm R1–R3; dùng Ollama hiện tại và giữ cùng hợp đồng quyền khi thay model/provider.

## 11. Kiểm thử và đánh giá khoa học

Kiểm thử tập trung vào hành vi biên và quyền thực thi, không chỉ sự hiện diện của nút:

1. Trước xác nhận cuối, sau từ chối/hết hạn/thu hồi hoặc khi sai identity: **0 dispatch**.
2. Đổi target, TTL, script, policy, evidence snapshot hoặc thêm step sau review: phê duyệt cũ không được dùng.
3. Hai callback song song, Telegram + web, webhook/poll update replay: một execution record; external uncertain được reconcile, không nhân đôi tác động.
4. Callback giả danh, forwarded link, GET preview, CSRF, session cũ, pairing code đoán/lặp và role downgrade: bị từ chối có audit an toàn.
5. Log/username/URL chứa prompt injection, model trả shell/action lạ, source là tài sản bảo vệ: policy chặn; không lộ raw content ra notification.
6. Evidence partial/timeout, target offline/đổi identity, state drift, pre-existing firewall rule, IP dùng chung: không thực thi ngoài điều kiện được duyệt.
7. Crash trước/sau dispatch, mất response, DB busy, poller/worker restart, đồng hồ lệch và hết hạn giữa các step: trạng thái trung thực, không tự cấp quyền lại.
8. Kill switch, rollback collision, cleanup scheduler offline: giữ ownership, ghi uncertain/failed và có phục hồi thủ công; không báo thành công giả.
9. Backward compatibility: job/schedule/export/delivery cũ vẫn hoạt động; feature disabled không có listener/dispatch mới.

Thiết kế đối chứng: (A) người vận hành điều tra/thực thi thủ công, (B) AI chỉ đề xuất, (C) AI điều tra + thực thi có duyệt. Giữ cùng kịch bản, cùng action catalog và cùng tập giữ riêng; phân biệt phần do LLM quyết định với template/regex/policy.

Đo recommendation correctness/grounding, wrong-target/unauthorized-dispatch rate, verified-effect success, rollback success/time, ảnh hưởng hoạt động hợp lệ, analyst active time, approval wait, execution latency và tỷ lệ abstain/reapproval. Báo số mẫu, số lỗi, uncertainty và p50/p95 theo giai đoạn; không gộp thời gian chờ người duyệt thành latency model.

Human labels phải được review độc lập; tách train/val/test theo scenario/campaign, không dùng held-out để sửa playbook/policy rồi báo là test độc lập. Sửa SFT leakage đã ghi trong HANDOFF trước mọi lượt train. `eval/user_study_protocol.py` hiện có số liệu mô phỏng: không dùng làm kết quả người dùng thật. Adapter QLoRA mới là nhánh đối chứng riêng, không phải điều kiện cấp quyền executor.

## 12. Định nghĩa hoàn thành MVP và công việc đầu tiên

MVP hoàn thành khi một reviewer chạy lại được vòng **SSH brute-force lab → truy vấn xác minh → kế hoạch block IP 300 giây → Telegram duyệt hai bước → preflight → tác động được kiểm chứng → cleanup được kiểm chứng → báo cáo**, cùng các ca từ chối, expiry, sai người, đổi kế hoạch, duplicate và crash. Demo phải phân biệt đã containment với đã giải quyết incident.

Email approval được nghiệm thu riêng ở R5. Restart dịch vụ, khôi phục file, khóa tài khoản và cô lập máy cần action design/review/test mới; không kế thừa quyền từ việc block IP. Tự khắc phục không cần người duyệt là ngoài phạm vi kế hoạch này.

Việc bắt đầu sau commit tài liệu: R0 rà lại findings trên HEAD mới; R1 đặc tả query/tool và evidence contract; R2 chỉ dùng mock executor. Mỗi PR triển khai cập nhật CHANGELOG/HANDOFF, có baseline SHA, kiểm thử, phạm vi và rollback. Không gửi mail/Telegram, gọi Manager API, thay cấu hình lab hoặc deploy script chỉ vì kế hoạch này đã được commit.

## Tham chiếu

- [Kế hoạch sản phẩm](product-roadmap.md), [research roadmap](thesis-ai-siem-research-roadmap.md), [Hybrid AI Gateway](hybrid-ai-gateway-roadmap.md).
- [OWASP Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html).
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- [OWASP Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).
- [Telegram Bot API](https://core.telegram.org/bots/api): kiểm tra callback/update/long-polling theo API đang triển khai.
- [Wazuh Active Response configuration](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html) và [custom scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html): đối chiếu với phiên bản lab trước R4.
