#!/usr/bin/env bash
# Tạo failed SSH auth có giới hạn cho Victim lab — rule Wazuh 5503.
# Chạy từ Kali: bash ssh-bruteforce.sh <VICTIM_IP> [USER] [IGNORED] [ATTEMPTS]
set -euo pipefail

TARGET="${1:-192.168.100.20}"
USER="${2:-root}"
ATTEMPTS="${4:-20}"
BAD_PASSWORD="${BAD_PASSWORD:-wazuh-lab-invalid-password-2026}"

[[ "$TARGET" == "192.168.100.20" ]] || { echo "!! Chỉ cho phép Victim lab 192.168.100.20"; exit 1; }
[[ "$ATTEMPTS" =~ ^[1-9][0-9]?$ ]] || { echo "!! ATTEMPTS phải là số 1..99"; exit 1; }
command -v hydra >/dev/null || { echo "!! Chưa có hydra. apt install hydra"; exit 1; }

echo "[*] Tạo $ATTEMPTS failed SSH auth → $TARGET (user: $USER)"
echo "[*] Rule Wazuh dự kiến: 5503 (PAM: User login failed)"

for ((i = 1; i <= ATTEMPTS; i++)); do
  output=$(hydra -l "$USER" -p "$BAD_PASSWORD" -t 1 -W 3 "ssh://$TARGET" 2>&1) || {
    echo "!! Hydra/network lỗi ở attempt $i" >&2
    printf '%s\n' "$output" >&2
    exit 1
  }
  if ! grep -q '0 valid password found' <<<"$output"; then
    echo "!! Hydra báo credential hợp lệ; dừng tại attempt $i" >&2
    exit 1
  fi
done

unset BAD_PASSWORD

# ponytail: fixed invalid credential + lab IP ceiling; use dedicated test harness for broader attack evaluation.

printf '[✓] Xong %s attempt. Kiểm tra alert trên Wazuh Dashboard/Indexer.\n' "$ATTEMPTS"
exit 0
