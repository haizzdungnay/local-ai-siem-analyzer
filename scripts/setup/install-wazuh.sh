#!/usr/bin/env bash
# Dựng Wazuh all-in-one (single-node) bằng Docker trên máy SIEM (192.168.100.10).
# Chạy: sudo bash install-wazuh.sh
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-v4.9.0}"   # ponytail: pin version; đổi khi nâng cấp
WORKDIR="${WORKDIR:-$HOME/wazuh-docker}"

echo "[*] Kiểm tra Docker..."
command -v docker >/dev/null || { echo "!! Chưa có Docker. Cài: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "!! Thiếu docker compose plugin."; exit 1; }

echo "[*] Tăng vm.max_map_count (Indexer/OpenSearch cần)..."
sysctl -w vm.max_map_count=262144
grep -q 'vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf

echo "[*] Clone wazuh-docker ($WAZUH_VERSION)..."
[ -d "$WORKDIR" ] || git clone https://github.com/wazuh/wazuh-docker.git -b "$WAZUH_VERSION" "$WORKDIR"
cd "$WORKDIR/single-node"

echo "[*] Sinh certificates..."
docker compose -f generate-indexer-certs.yml run --rm generator

echo "[*] Khởi động Wazuh (indexer + manager + dashboard)..."
docker compose up -d

cat <<EOF

[✓] Wazuh đang khởi động. Kiểm tra:
    docker compose ps
    docker compose logs -f wazuh.manager

    Dashboard : https://192.168.100.10        (mặc định admin / SecretPassword — ĐỔI NGAY)
    API       : https://192.168.100.10:55000

Bước tiếp: sang máy Victim chạy scripts/setup/install-agent.sh 192.168.100.10
EOF
