# Start — khởi chạy thủ công

Hướng dẫn chạy dashboard AI local trên máy Windows host bằng `Star.py`.

## Quy tắc cố định

`Star.py` luôn bật Security Tests: sau khi đọc `ai_module/config.yaml`, launcher ép
`cfg["security_tests"]["enabled"] = True`. Giá trị này **không đổi theo `enabled` trong config**
và không có tham số dòng lệnh để tắt. Không sửa dòng này trong `Star.py`.

Launcher gộp (merge) vào khối `security_tests` hiện có thay vì thay cả khối bằng
`{"enabled": True}`, vì runner cần `attacker_host`, `victim_host`, `ssh_identity_path`… từ
`config.yaml`; thiếu chúng runner báo disabled. Khối `security_tests` vẫn phải có đủ các khóa này.

## Điều kiện

- Python 3.12 và dependency: `pip install -r ai_module/requirements.txt`.
- `ai_module/config.yaml` đã tạo từ `config.example.yaml` (gitignored; chứa credential Indexer và
  `security_tests.*`; không commit).
- Wazuh Indexer `:9200` trên máy SIEM đang chạy.
- Ollama đã cài, có model `qwen2.5:7b` (Security Tests dùng làm mặc định).
- Lab Kali `.30` và victim `.20` bật, SSH key nằm ở `security_tests.ssh_identity_path`.

## Chạy

Từ thư mục gốc repo (PowerShell hoặc Git Bash):

```powershell
python Star.py
```

Dashboard: <http://127.0.0.1:8765>; trang Security Tests: <http://127.0.0.1:8765/security-tests>.
Launcher dùng lại Ollama đang chạy, hoặc tự bật `ollama serve` (loopback) và tắt nó khi thoát.
Dòng `Wazuh Indexer: ok` nghĩa là Indexer truy cập được. Cảnh báo `verify_ssl=false` là bình thường
trong lab cô lập.

## Kiểm tra Security Tests đã bật

```powershell
curl.exe -s http://127.0.0.1:8765/api/security-tests/catalog
```

Kết quả phải có `"enabled":true`. Kịch bản nào chưa có telemetry contract đã kiểm chứng sẽ hiện
`enabled:false` với lý do `Telemetry contract has not been verified...`; đó là cổng an toàn của
runner, không phải do tắt `security_tests`.

## Dừng / chạy lại

`Ctrl+C` trong terminal đang chạy `Star.py`. Nếu lỗi `Cannot bind dashboard to 127.0.0.1:8765`
thì còn một phiên cũ giữ cổng:

```powershell
netstat -ano | findstr ":8765" | findstr LISTENING
taskkill /PID <pid> /F
python Star.py
```

## Xử lý lỗi nhanh

| Triệu chứng | Cách xử lý |
|---|---|
| `Missing ai_module/config.yaml` | Copy từ `config.example.yaml`, điền credential. |
| `Ollama is required` | Cài Ollama và thêm vào `PATH`, hoặc tự chạy `ollama serve`. |
| Catalog `enabled:false`, reason liên quan IP/key | Kiểm tra `attacker_host`, `victim_host`, `ssh_identity_path` trong `config.yaml`. |
| `Wazuh Indexer` không `ok` | Kiểm tra máy SIEM `.10` và `wazuh_indexer.*` trong config. |

Xem thêm: `README.md` (mục Dashboard AI local), `docs/manual-test.md`.
