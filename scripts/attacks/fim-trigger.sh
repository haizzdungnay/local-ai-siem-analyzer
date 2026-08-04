#!/usr/bin/env bash
# Kích hoạt FIM trên file test riêng — rule Wazuh 550/554.
# Chạy TRÊN MÁY VICTIM: sudo bash fim-trigger.sh
set -euo pipefail

TEST_DIR="/opt/wazuh-fim-lab"
TEST_FILE="$TEST_DIR/controlled-marker.txt"
[[ "$(id -u)" -eq 0 ]] || { echo "!! Chạy script bằng root" >&2; exit 1; }
mkdir -p "$TEST_DIR"
chmod 750 "$TEST_DIR"

cleanup() {
  rm -f "$TEST_FILE"
}
trap cleanup EXIT INT TERM

echo "[*] Tạo thay đổi file test FIM: $TEST_FILE"
printf 'baseline %s\n' "$(date +%s)" > "$TEST_FILE"
printf 'changed %s\n' "$(date +%s)" >> "$TEST_FILE"
echo "    [+] Tạo và sửa file test"

echo "[✓] File giữ tới khi alert được thu; cleanup khi script thoát."
echo "    Rule dự kiến: 550 (file modified), 554 (file added/deleted)"
