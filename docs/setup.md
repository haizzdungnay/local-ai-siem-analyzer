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
```bash
# Từ Kali (.30)
bash scripts/attacks/ssh-bruteforce.sh 192.168.100.20
```
Kiểm tra Dashboard → có alert rule **5503** (PAM login failed — quan sát thực tế trên bản 4.9.0) là lab chạy đúng.
