# Product roadmap — Local AI SIEM Analyzer

Ngày khảo sát: 2026-08-05 (Asia/Saigon).

## Định vị

Dự án là console phân tích SOC chạy local cho Wazuh: đọc alert từ Indexer, gom nhóm,
gọi Ollama, lưu provenance và hỗ trợ analyst kiểm tra kết quả. Dự án không thay thế
Wazuh, không tự remediation và không được mở ra LAN/Internet khi chưa có auth/TLS/RBAC.

## Đối chiếu sản phẩm tương tự

| Nguồn chính thức | Pattern hữu ích | Áp dụng trong dự án |
|---|---|---|
| [Wazuh Dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/index.html) | Search/filter/pivot dữ liệu security | Filter theo rule, agent, nguồn, thời gian |
| [Security Onion Alerts](https://docs.securityonion.net/en/2.4/alerts.html) | Group alert, drill-down và escalate sang case | Group/pivot và case-lite theo job |
| [Security Onion Cases](https://docs.securityonion.net/en/2.4/cases.html) | Status, severity, tags, comments, history | Review event bất biến cho analyst local |
| [OpenSearch Security Analytics](https://docs.opensearch.org/latest/security-analytics/) | Detector, finding, correlation và threat intelligence | Dùng job/group làm finding; correlation để phase sau |
| [OpenSearch Findings](https://docs.opensearch.org/latest/security-analytics/usage/findings/) | Count/time/severity, refresh và danh sách finding | Freshness, filter và timeline hiện có |
| [OpenSearch Alerting](https://docs.opensearch.org/latest/observing-your-data/alerting/index/) | Monitor, trigger, action/notification | Giữ tách khỏi LLM; notification để phase sau |

Các dự án tham khảo có phạm vi enterprise lớn hơn. Pattern được chọn chỉ gồm phần
tăng khả năng kiểm toán và xử lý alert local, không sao chép multi-tenant/RBAC/PCAP.

## Release hiện tại

- SOC contract VI/EN, structured evidence trace và provenance không chứa raw prompt/CoT.
- Job lifecycle thật, aggregate-only cho cửa sổ lớn, timeline và JSON report v2/v1.
- Data minimization: không persist sample log; raw document chỉ tải lại theo reference.
- Analyst case-lite: status, severity override, tags, note và immutable review history.
- Search/filter/pivot phía client; freshness và dependency/queue/database health.
- Retention thủ công, chỉ xóa terminal jobs theo policy cấu hình và explicit confirmation.
- Production WSGI loopback, endpoint allowlist và CI release gates đa nền tảng.

## Sau release

- Correlation nhiều finding/window, asset criticality và threat-intel enrichment có cache.
- Notification/ticket outbound với allowlist, idempotency và audit; không cho LLM tự action.
- Auth/RBAC/OIDC, TLS và audit actor trước khi hỗ trợ remote hoặc nhiều analyst.
- PCAP/network pivot chỉ khi lab có nguồn dữ liệu và retention policy phù hợp.
- Dependency lock/SBOM/SCA và signed release artifact.

## Không triển khai trong scope local hiện tại

- Auto-block IP, chạy command hoặc thay đổi Wazuh từ output LLM.
- Hiển thị hoặc lưu private chain-of-thought/ngôn ngữ suy luận nội bộ.
- Bind `0.0.0.0`, reverse proxy công khai hoặc multi-tenant không xác thực.
- Nhúng PCAP/raw log hàng loạt vào SQLite hay JSON report.

## Điều kiện hoàn thành release

1. Migration giữ nguyên dữ liệu từ schema cũ; retention không đụng active job.
2. Full tests, compile, JavaScript/shell syntax và diff checks là CI merge gates.
3. Live VI/EN có provenance/hash/language compliance; fallback không persist raw output.
4. Dashboard chỉ listen loopback bằng production WSGI server.
5. `CHANGELOG.md` cập nhật trước `HANDOFF.md`; PR xanh mới được merge vào `main`.
