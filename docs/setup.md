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
Kiểm tra Dashboard → có alert rule 5710/5712 là lab chạy đúng.
