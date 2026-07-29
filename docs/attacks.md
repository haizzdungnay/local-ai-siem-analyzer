# Kịch bản sinh cảnh báo

Mỗi kịch bản tạo alert Wazuh cụ thể. Script nằm trong `scripts/attacks/`. Quy trình copy script, timing, query rule và cleanup theo từng máy: [`manual-test.md`](manual-test.md).

Alert được tìm trong Wazuh Indexer bằng `POST https://192.168.100.10:9200/wazuh-alerts-*/_search`. Port `55000` là Manager API quản trị, không phải kho alert.

## 1. SSH Brute-force
**Script:** `scripts/attacks/ssh-bruteforce.sh`
**Chạy từ:** Kali (.30)
**Đánh vào:** Victim (.20)
**Rule Wazuh thực tế trên lab 4.9.0:**
- 5503: PAM user login failed
- 5760: sshd authentication failed
- 2502: nhiều lần nhập sai mật khẩu (correlation, level 10)

Script chỉ gửi số lần xác thực sai đã giới hạn; không quét toàn bộ wordlist. `5710/5712` có thể xuất hiện ở ruleset/cấu hình khác.

```bash
bash scripts/attacks/ssh-bruteforce.sh 192.168.100.20
```

## 2. Web Attack (nikto / SQLi / XSS)
**Script:** `scripts/attacks/web-attack.sh`
**Chạy từ:** Kali (.30)
**Yêu cầu:** Apache + DVWA cài trên Victim
**Rule Wazuh dự kiến:** 31xxx
**Rule Wazuh thực tế:** 31101 (Web server 400 error code) + 31151 (Multiple web server 400 error codes — correlation rule)

```bash
bash scripts/attacks/web-attack.sh 192.168.100.20
```

Cài DVWA trên Victim:
```bash
sudo apt install -y apache2 mariadb-server php php-mysqli php-gd
cd /var/www/html && sudo git clone https://github.com/digininja/DVWA.git
sudo cp DVWA/config/config.inc.php.dist DVWA/config/config.inc.php
# Sửa db_password trong config.inc.php, tạo DB, truy cập http://<victim-ip>/DVWA/setup.php
```

## 3. FIM (File Integrity Monitoring)
**Script:** `scripts/attacks/fim-trigger.sh`
**Chạy trên:** Victim (.20) — KHÔNG phải từ Kali
**Rule Wazuh dự kiến:** 550/554 theo thao tác modify/add.

Script chỉ tạo và sửa `/opt/wazuh-fim-lab/controlled-marker.txt`; không sửa `/etc/shadow`, `/etc/hosts` hoặc tài khoản hệ thống.

Thêm directory riêng vào block `<syscheck>` trong `/var/ossec/etc/ossec.conf`:
```xml
<directories realtime="yes">/opt/wazuh-fim-lab</directories>
```
Restart agent sau khi sửa: `sudo systemctl restart wazuh-agent`.

```bash
sudo bash scripts/attacks/fim-trigger.sh
```

## 4. Nmap Recon (thủ công)
```bash
# Từ Kali
nmap -sS -sV -O 192.168.100.20
nmap -A 192.168.100.0/24
```

## Bảng tổng hợp

| Kịch bản | Từ | Đến | Rule | Mục đích |
|---|---|---|---|---|
| SSH failed auth | Kali .30 | Victim .20 | 5503/5760/2502 | Auth failure |
| Web attack | Kali .30 | Victim .20 | 31101/31151 | Web request anomaly |
| FIM | Victim .20 | (local) | 550/554 | File integrity |
| Nmap | Kali .30 | Victim .20 | tuỳ | Recon |
