# Hướng dẫn dựng Lab từ đầu

## Yêu cầu
- VMware Workstation (Pro/Player)
- ISO: Ubuntu Server 22.04+, Kali Linux
- Docker + Docker Compose trên máy SIEM
- Ollama trên máy thật (host Windows)
- Python 3.10+ trên host

## Bước 1 — Tạo VM trong VMware

| VM | OS | RAM | Disk | Card mạng |
|---|---|---|---|---|
| SIEM | Ubuntu Server (no-GUI) | 6 GB | 40 GB | NAT + Host-only |
| Victim | Ubuntu Server (no-GUI) | 2 GB | 20 GB | NAT + Host-only |
| Attacker | Kali Linux | 2–3 GB | 20 GB | NAT + Host-only |

Cài OS bình thường. Khi chọn disk size: thin provisioned (để tiết kiệm).

## Bước 2 — Set mạng
Xem chi tiết tại [`network.md`](network.md). Tóm tắt:
1. VMware Virtual Network Editor → VMnet1 Host-only, tắt DHCP, subnet `192.168.100.0/24`.
2. Copy file netplan tương ứng từ `infra/netplan/` vào `/etc/netplan/01-lab.yaml`.
3. `sudo netplan apply`.
4. Ping test thông mạng.
5. **Bắt buộc:** tắt cloud-init ghi đè netplan trên mỗi máy Ubuntu (xem mục "Fix bắt buộc" trong `network.md`), nếu không IP tĩnh sẽ mất sau mỗi lần reboot.

## Bước 3 — Cài Docker trên SIEM
```bash
# Trên máy SIEM (.10)
sudo apt update && sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
# logout + login lại
```

## Bước 4 — Dựng Wazuh
```bash
# Trên SIEM (.10)
sudo bash scripts/setup/install-wazuh.sh
```
Đợi ~2–3 phút. Kiểm tra: `docker compose ps` → 3 container running. Mở `https://192.168.100.10` (admin/SecretPassword — ĐỔI NGAY).

## Bước 4.5 — Đổi mật khẩu admin mặc định (Docker deployment)

⚠️ **KHÔNG** dùng `wazuh-passwords-tool.sh` để đổi password admin — script đó chỉ dành cho cài đặt bare-metal, không hoạt động đúng với Docker deployment và sẽ gây lỗi `401 Unauthorized` giữa Filebeat và Indexer.

Với Docker, làm theo đúng các bước sau:

**1. Sinh hash cho password mới**
```bash
docker run --rm -ti wazuh/wazuh-indexer:4.9.0 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```
Nhập password mới khi được hỏi, copy lại chuỗi hash trả về (dạng `$2y$12$...`).

Yêu cầu password: 8-64 ký tự, có ít nhất 1 chữ hoa, 1 chữ thường, 1 số, và 1 ký tự trong `.*+?-`.

**2. Cập nhật hash vào `internal_users.yml`**
```bash
cd ~/wazuh-docker/single-node
nano config/wazuh_indexer/internal_users.yml
```
Tìm block `admin:`, thay giá trị `hash:` bằng hash mới.

**3. Cập nhật password plaintext vào `docker-compose.yml`**
```bash
nano docker-compose.yml
```
Thay **tất cả** chỗ xuất hiện `SecretPassword` → password mới (cả service `wazuh.manager` và `wazuh.dashboard`, biến `INDEXER_PASSWORD`).

**4. Reset lại stack để áp dụng đồng bộ**
```bash
docker compose down
docker volume rm single-node_wazuh-indexer-data
docker compose up -d
```
> Lệnh `volume rm` xóa dữ liệu Indexer hiện có để nó khởi tạo lại từ đầu và đọc đúng config mới. Chấp nhận được cho môi trường lab.

**5. Kiểm tra password mới hoạt động**
```bash
docker exec -it single-node-wazuh.indexer-1 curl -s -k -o /dev/null -w "%{http_code}\n" -u 'admin:<password_mới>' https://localhost:9200
```
Kỳ vọng: `200`. Kiểm tra Filebeat đồng bộ đúng chưa:
```bash
docker logs single-node-wazuh.manager-1 --tail 20 | grep -i indexer
```

**6. Đăng nhập Dashboard bằng tab ẩn danh / incognito** lần đầu sau khi đổi password — tránh lỗi `500 Internal Server Error` do cookie session cũ.

## Bước 5 — Cài agent trên Victim
```bash
# Trên Victim (.20)
sudo bash scripts/setup/install-agent.sh 192.168.100.10
```
Kiểm tra trên Dashboard: Agents → thấy agent Active.

## Bước 6 — Bật thu log bổ sung trên Victim
Sửa `/var/ossec/etc/ossec.conf` trên Victim, thêm:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
```
Restart agent: `sudo systemctl restart wazuh-agent`.

FIM mặc định đã giám sát `/etc` — không cần thêm.

## Bước 7 — Cài Ollama + AI module trên Host
```powershell
# PowerShell trên máy thật (Windows)
winget install Ollama
ollama pull qwen2.5:3b
ollama pull qwen2.5:7b

cd ai_module
pip install -r requirements.txt
cp config.example.yaml config.yaml   # sửa IP Wazuh, API key
python main.py --demo                 # test với alert mẫu
```

## Bước 8 — Sinh cảnh báo thử
Xem [`attacks.md`](attacks.md). Nhanh nhất:

## Bước 9 — Windows Victim Setup (mở rộng)

VM Windows 10/11, IP tĩnh Host-only `192.168.100.40`, RAM ≥4GB.

### Set IP tĩnh
Windows không dùng netplan — set qua giao diện:
```
Settings → Network & Internet → Ethernet → chọn đúng card Host-only
IPv4: 192.168.100.40 / 255.255.255.0
KHÔNG đặt Default Gateway (để card NAT lo, tránh 2 default route đá nhau — giống nguyên tắc áp dụng cho Ubuntu)
```

### Cài Wazuh agent

⚠️ **Bắt buộc chạy PowerShell/CMD với quyền Administrator** — nếu không sẽ gặp lỗi:
```
Error 1925. You do not have sufficient privileges to complete this installation
for all users of the machine. Log on as administrator and then retry this installation.
```
Dù account hiện tại đã thuộc nhóm Administrators, UAC vẫn chặn nếu terminal không được elevate. Mở PowerShell bằng chuột phải → **"Run as administrator"**.

⚠️ **Bắt buộc khớp version agent với Manager** — Manager lab đang chạy `4.9.0`. Agent version chênh quá xa (ví dụ `4.14.6`) có rủi ro mất tương thích dữ liệu/field. Tải đúng bản:
```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "wazuh-agent-4.9.0-1.msi"
```

Cài:
```powershell
msiexec.exe /i wazuh-agent-4.9.0-1.msi /q WAZUH_MANAGER="192.168.100.10"
```

Khởi động service:
```powershell
NET START WazuhSvc
```

Verify:
```powershell
sc query WazuhSvc
```
Phải thấy `STATE: RUNNING`.

Kiểm tra trên Dashboard: **Agents** → agent tên máy Windows (hostname) → trạng thái **Active**.

### Nếu không copy-paste được giữa host và VM
Cài/reinstall **VMware Tools**: `VM → Install VMware Tools` → chạy `setup64.exe` trong ổ CD ảo vừa mount → cài xong restart VM → bật `VM → Settings → Options → Guest Isolation` → tick **Enable copy and paste** + **Enable drag and drop** → Power Off/Power On lại VM để áp dụng.

### Lưu ý: Windows Home không hỗ trợ nhận kết nối RDP
Windows 10/11 **Home** chỉ dùng RDP làm client (kết nối ra), không nhận kết nối RDP vào (cần bản Pro/Enterprise). Với lab, dùng trực tiếp cửa sổ VMware Workstation console để thao tác — không cần RDP.
```bash
# Từ Kali (.30)
bash scripts/attacks/ssh-bruteforce.sh 192.168.100.20
```
Kiểm tra Dashboard → có alert rule **5503** (PAM login failed — quan sát thực tế trên bản 4.9.0) là lab chạy đúng.
