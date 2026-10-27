# Vận hành hệ thống Lab — Khởi động, chạy dịch vụ và kiểm tra

Tài liệu dùng **mỗi lần bật lab** sau khi hạ tầng đã dựng xong. Dựng lab từ đầu: [`setup.md`](setup.md). Mạng/IP: [`network.md`](network.md). Kiểm thử đầy đủ từng kịch bản: [`manual-test.md`](manual-test.md).

> Không ghi mật khẩu vào file này. Credential để ở trình quản lý mật khẩu hoặc `ai_module/config.yaml` (gitignored).

## 0. Tóm tắt nhanh

| Thứ tự | Máy | IP Host-only | User SSH | Dịch vụ phải chạy |
|---|---|---|---|---|
| 1 | Host Windows | `192.168.100.1` | local | VMware, Ollama, `ai_module` dashboard |
| 2 | SIEM Ubuntu | `192.168.100.10` | `wazuh` | Docker: `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard` |
| 3 | Victim Ubuntu | `192.168.100.20` | `trnguyn` | `ssh`, `apache2`, `mariadb`, `wazuh-agent` |
| 4 | Attacker Kali | `192.168.100.30` | `kali` | Không có service; cần mạng + tool `hydra`, `nikto`, `curl` |
| 5 | Victim Windows (tùy chọn) | `192.168.100.40` | VMware console | `WazuhSvc` |

**Nguyên tắc thứ tự:** SIEM lên trước và phải ổn định (Indexer sẵn sàng) rồi mới bật agent. Agent bật trước SIEM vẫn tự kết nối lại, nhưng log trong khoảng chờ có thể bị trễ và khó đối chiếu thời gian khi test.

| Port | Dịch vụ | Dùng để |
|---|---|---|
| `443` | Wazuh Dashboard | Giao diện web `https://192.168.100.10` |
| `9200` | Wazuh Indexer | Nơi lưu alert — `ai_module` đọc alert từ đây |
| `55000` | Wazuh Manager API | Chỉ dùng quản trị, không chứa alert |
| `1514/1515` | Manager | Agent gửi log / đăng ký agent |
| `11434` | Ollama (Host) | LLM local |
| `8765` | AI dashboard (Host) | `http://127.0.0.1:8765` — chỉ loopback |

---

## 1. Host Windows — chuẩn bị

1. Mở **VMware Workstation**.
2. Kiểm tra card VMnet1 của host (chỉ cần làm khi đổi máy/cài lại VMware):
   ```powershell
   ipconfig
   ```
   `VMware Network Adapter VMnet1` phải có `192.168.100.1`.
3. Kiểm tra Ollama đang chạy và đủ model:
   ```powershell
   ollama list
   ```
   Phải có `qwen2.5:7b`, `nomic-embed-text` (và các model khác theo `config.yaml`). Nếu lỗi kết nối → mở app Ollama hoặc chạy `ollama serve` ở cửa sổ riêng.

---

## 2. SIEM `.10` — bật và chạy Wazuh

**Bật VM SIEM**, đợi màn hình login. Đăng nhập console hoặc SSH từ Host:

```powershell
ssh wazuh@192.168.100.10
```

### 2.1 Kiểm tra nền tảng trước khi chạy Docker

```bash
ip -4 addr show            # card Host-only phải có 192.168.100.10
df -h /                    # disk phải < 90%
sysctl vm.max_map_count    # phải = 262144 (Indexer/OpenSearch bắt buộc)
```

Nếu `vm.max_map_count` khác `262144`:
```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf   # giữ sau reboot
```

> Vì sao: Indexer (OpenSearch) dùng mmap rất nhiều; thiếu giá trị này container Indexer sẽ crash-loop và Dashboard không lên.

### 2.2 Chạy stack Wazuh

Container có `restart: always` nên thường **tự lên** sau khi Docker khởi động. Vẫn kiểm tra và chạy lại cho chắc:

```bash
cd ~/wazuh-docker/single-node
docker compose up -d
```

**Chờ 2–3 phút** để Indexer khởi tạo xong, sau đó:

```bash
docker compose ps
```

✅ Cả 3 container `Up`, không có trạng thái `Restarting`.

```bash
ss -ltn | grep -E ':(443|9200|55000|1514|1515)\b'
```

✅ Cả 5 port đang `LISTEN`.

---

## 3. Victim Ubuntu `.20` — dịch vụ

**Bật VM Victim** (sau khi SIEM đã ổn định). SSH từ Host:

```powershell
ssh trnguyn@192.168.100.20
```

```bash
ip -4 addr show                          # phải có 192.168.100.20
systemctl is-active ssh apache2 mariadb wazuh-agent
```

✅ Cả 4 dòng đều `active`. Dịch vụ nào `inactive`:

```bash
sudo systemctl start <tên_service>
sudo systemctl enable <tên_service>      # tự chạy ở lần boot sau
```

Kiểm tra agent đã kết nối Manager:

```bash
sudo grep -i "connected to the server" /var/ossec/logs/ossec.log | tail -3
```

✅ Thấy dòng `Connected to the server ([192.168.100.10]:1514/tcp)` với thời gian gần nhất.

---

## 4. Kali `.30`

**Bật VM Kali**, đăng nhập.

```bash
ip -4 addr show                          # phải có 192.168.100.30
ping -c 2 192.168.100.20                 # tới Victim
command -v hydra nikto curl              # đủ 3 đường dẫn
```

Nếu card Host-only mất IP: GUI NetworkManager → card Host-only → IPv4 **Manual** `192.168.100.30/24`, không gateway.

---

## 5. Victim Windows `.40` (chỉ khi test nhánh Windows)

Trong VM, mở **PowerShell (Run as administrator)**:

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress
Get-Service WazuhSvc
```

✅ Có `192.168.100.40`, `WazuhSvc` = `Running`. Nếu `Stopped`: `Start-Service WazuhSvc`.

---

## 6. Host — chạy AI module

```powershell
Set-Location <đường_dẫn_repo>\local-ai-siem-analyzer
python ai_module/dashboard.py
```

✅ Terminal báo phục vụ trên `127.0.0.1:8765`. Mở `http://127.0.0.1:8765`. Giữ cửa sổ terminal này mở — scheduler chỉ chạy khi process còn sống.

---

## 7. Kiểm tra dịch vụ (sau khi bật đủ)

Làm theo thứ tự từ tầng thấp lên cao; tầng dưới fail thì không cần kiểm tầng trên.

### 7.1 Mạng (từ Host, PowerShell)

```powershell
Test-Connection 192.168.100.10 -Count 2
Test-Connection 192.168.100.20 -Count 2
Test-Connection 192.168.100.30 -Count 2
Test-NetConnection 192.168.100.10 -Port 9200
Test-NetConnection 192.168.100.10 -Port 443
```

✅ Ping phản hồi; `TcpTestSucceeded : True` cho 9200 và 443.

### 7.2 Indexer có dữ liệu và khỏe

```powershell
curl.exe -k -u "admin:<INDEXER_PASSWORD>" "https://192.168.100.10:9200/_cluster/health?pretty"
```

✅ `"status" : "green"` hoặc `"yellow"` (single-node bình thường là yellow).
❌ `401` → sai credential. Timeout → quay lại mục 2.

> Nhập password trực tiếp lúc chạy, không lưu lệnh có password vào script hay lịch sử commit. Cách nhập an toàn bằng `Read-Host -AsSecureString` xem `manual-test.md` mục 1.

### 7.3 Wazuh Dashboard và agent

Mở `https://192.168.100.10` → đăng nhập → **Agents**.

✅ Victim Ubuntu: **Active**. Windows `.40`: Active nếu đang bật.
❌ `Disconnected` → kiểm tra mục 3 (`wazuh-agent`, IP, ping tới `.10`).

### 7.4 Smoke test end-to-end (an toàn, không tấn công)

Dùng FIM marker để xác nhận cả chuỗi **agent → Manager → Indexer → AI**:

```powershell
ssh trnguyn@192.168.100.20 "printf 'ops-check\n' | sudo tee -a /opt/wazuh-fim-lab/manual-marker.txt >/dev/null"
```

Đợi ~60 giây → Wazuh Dashboard → **Threat Hunting / Security Events**, lọc `rule.id: 550 or 554`.

✅ Có alert với path `/opt/wazuh-fim-lab/manual-marker.txt` → chuỗi thu log hoạt động.

Sau đó trên AI dashboard (`http://127.0.0.1:8765`): chọn preset **5 phút** → **Đưa vào hàng đợi**.

✅ Job đi qua `fetching_alerts → calling_ollama → completed` và có kết quả phân tích.

### 7.5 Bảng tick nhanh

| Hạng mục | Lệnh/nơi kiểm | OK |
|---|---|---|
| VMnet1 host `.1` | `ipconfig` | ☐ |
| SIEM disk < 90%, `max_map_count` | `df -h /`, `sysctl` | ☐ |
| 3 container Wazuh Up | `docker compose ps` | ☐ |
| Port 443/9200/55000 | `ss -ltn` / `Test-NetConnection` | ☐ |
| Indexer health | `_cluster/health` | ☐ |
| Victim services active | `systemctl is-active` | ☐ |
| Agent Active | Wazuh Dashboard → Agents | ☐ |
| Kali mạng + tool | `ping`, `command -v` | ☐ |
| Ollama + model | `ollama list` | ☐ |
| AI dashboard | `http://127.0.0.1:8765` | ☐ |
| Smoke test FIM → AI | rule 550/554 + job completed | ☐ |

---

## 8. Tắt hệ thống

Ngược thứ tự bật:

1. Host: `Ctrl+C` để dừng AI dashboard.
2. Kali, Victim Windows, Victim Ubuntu: shut down trong OS (`sudo shutdown now`).
3. SIEM — dừng Docker trước để Indexer ghi xong dữ liệu:
   ```bash
   cd ~/wazuh-docker/single-node
   docker compose stop
   sudo shutdown now
   ```
4. **Không dùng Suspend** nếu sắp chuyển VM sang máy khác (trạng thái suspend gắn với CPU máy cũ).
5. Trước khi chạy kịch bản tấn công mới: chụp **snapshot** để revert khi cần.

> Không dùng `docker compose down -v` hoặc xóa volume Indexer khi vận hành bình thường — sẽ mất toàn bộ alert đã lưu.

---

## 9. Lỗi thường gặp khi khởi động

| Triệu chứng | Nguyên nhân hay gặp | Xử lý |
|---|---|---|
| VM có IP nhưng không ping được máy khác | VMware gắn card sai vSwitch | `network.md` → Troubleshooting vSwitch (đổi tạm Bridged → đổi lại → Power Off/On) |
| Card Host-only mất IP sau reboot | cloud-init ghi đè netplan | `network.md` → Fix cloud-init |
| Container Indexer `Restarting` | `vm.max_map_count` thấp hoặc disk đầy | Mục 2.1; `df -h /` |
| Container Up nhưng 9200/443 timeout | Disk đầy (cache Vulnerability Detector) hoặc Docker bridge treo | `network.md` → Troubleshooting Dashboard timeout; `sudo systemctl restart docker` |
| Dashboard báo 500 sau khi đổi password | Cookie session cũ | Đăng nhập bằng tab ẩn danh |
| Agent `Disconnected` | `wazuh-agent` chưa chạy hoặc mạng Victim lỗi | Mục 3 |
| AI job failed ở `calling_ollama` | Ollama chưa chạy / thiếu model | `ollama list`, `ollama pull <model>` |
| AI job failed ở `fetching_alerts` | Indexer down hoặc sai credential trong `config.yaml` | Mục 7.2 |
