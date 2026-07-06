#!/usr/bin/env bash
# Kích hoạt FIM (File Integrity Monitoring) — rule Wazuh 550/554.
# Chạy TRÊN MÁY VICTIM: sudo bash fim-trigger.sh
# Wazuh agent phải đang giám sát /etc (mặc định đã có).
set -euo pipefail

echo "[*] Tạo thay đổi file quan trọng để kích FIM..."

# Thêm comment vô hại vào /etc/hosts (dễ revert)
cp /etc/hosts /etc/hosts.bak
echo "# fim-test $(date +%s)" >> /etc/hosts
echo "    [+] Sửa /etc/hosts"

# Tạo user test rồi xoá
useradd fim_testuser 2>/dev/null && echo "    [+] Tạo user fim_testuser" || true
userdel fim_testuser 2>/dev/null && echo "    [+] Xoá user fim_testuser" || true

# Sửa permission file nhạy cảm
chmod 644 /etc/shadow && echo "    [+] Đổi perm /etc/shadow (644 — BẤT THƯỜNG)" || true
chmod 640 /etc/shadow && echo "    [+] Revert /etc/shadow (640)"

# Revert hosts
mv /etc/hosts.bak /etc/hosts

echo "[✓] Đợi ~30s cho syscheck quét lại, rồi kiểm tra alert FIM trên Dashboard."
echo "    Rule dự kiến: 550 (file modified), 554 (file added/deleted)"
