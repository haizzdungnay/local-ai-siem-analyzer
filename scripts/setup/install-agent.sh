#!/usr/bin/env bash
# Cài Wazuh agent trên máy Victim, trỏ về SIEM manager.
# Chạy: sudo bash install-agent.sh <MANAGER_IP>   (mặc định 192.168.100.10)
set -euo pipefail

MANAGER_IP="${1:-192.168.100.10}"
WAZUH_VERSION="${WAZUH_VERSION:-4.9.0}"   # ponytail: khớp version manager

echo "[*] Cài Wazuh agent, trỏ manager = $MANAGER_IP"
command -v curl >/dev/null || apt-get update && apt-get install -y curl gnupg

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list

apt-get update
WAZUH_MANAGER="$MANAGER_IP" apt-get install -y "wazuh-agent=${WAZUH_VERSION}-1"

systemctl daemon-reload
systemctl enable --now wazuh-agent

echo "[✓] Agent chạy. Kiểm tra trạng thái: systemctl status wazuh-agent"
echo "    Trên Dashboard SIEM sẽ thấy agent chuyển 'Active' sau ~30s."
echo "    Bật thu log bổ sung (SSH/Apache/FIM): xem docs/setup.md"
