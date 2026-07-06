# Kịch bản sinh cảnh báo

Mỗi kịch bản tạo alert Wazuh cụ thể. Script nằm trong `scripts/attacks/`.

## 1. SSH Brute-force
**Script:** `scripts/attacks/ssh-bruteforce.sh`
**Chạy từ:** Kali (.30)
**Đánh vào:** Victim (.20)
**Rule Wazuh dự kiến:**
- 5710: sshd auth failure
- 5712: SSHD brute-force (nhiều lần liên tiếp)

```bash
bash scripts/attacks/ssh-bruteforce.sh 192.168.100.20
```

## 2. Web Attack (nikto / SQLi / XSS)
**Script:** `scripts/attacks/web-attack.sh`
**Chạy từ:** Kali (.30)
**Yêu cầu:** Apache + DVWA cài trên Victim
**Rule Wazuh dự kiến:** 31xxx (web attack rules)

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
**Rule Wazuh dự kiến:**
- 550: file modified
- 554: file added/deleted

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
| SSH brute | Kali .30 | Victim .20 | 5710/5712 | Auth failure |
| Web attack | Kali .30 | Victim .20 | 31xxx | Web vuln |
| FIM | Victim .20 | (local) | 550/554 | File integrity |
| Nmap | Kali .30 | Victim .20 | tuỳ | Recon |
