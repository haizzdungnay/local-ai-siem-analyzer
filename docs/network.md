# Cấu hình mạng Lab

## Tổng quan
Mỗi VM gắn **2 card mạng** trong VMware:
- **Card 1 — NAT (VMnet8):** ra internet, DHCP tự cấp. Dùng cập nhật, cài tool.
- **Card 2 — Host-only (VMnet1):** mạng lab nội bộ, IP tĩnh. Giao tiếp giữa 3 VM + host.

## Bảng IP

| Máy | Host-only IP | NAT | RAM |
|---|---|---|---|
| Host (máy thật) | 192.168.100.1 | — | 32GB tổng |
| SIEM Wazuh | 192.168.100.10 | DHCP | 6 GB |
| Victim Ubuntu | 192.168.100.20 | DHCP | 2 GB |
| Attacker Kali | 192.168.100.30 | DHCP | 2–3 GB |
| Victim Windows (sau) | 192.168.100.40 | DHCP | 4 GB |

## Cấu hình VMware (1 lần)
1. Edit → Virtual Network Editor (chạy quyền admin).
2. **VMnet1 (Host-only):** tắt "Use local DHCP service". Subnet: `192.168.100.0`, mask `255.255.255.0`.
3. **VMnet8 (NAT):** giữ mặc định.
4. Mỗi VM → Settings → Add Network Adapter: 1 NAT + 1 Custom (VMnet1).

## Đặt IP tĩnh
File mẫu nằm trong `infra/netplan/`. Copy vào VM tại `/etc/netplan/01-lab.yaml` rồi `sudo netplan apply`.

Lưu ý quan trọng:
- Card Host-only **KHÔNG đặt gateway** → tránh 2 default route đá nhau. Default route để NAT lo.
- Tên card (`ens33`, `ens34`) có thể khác trên máy anh. Chạy `ip a` để xem đúng tên.
- Kali dùng NetworkManager: GUI → chọn card Host-only → Manual → IP `192.168.100.30/24`.

## Kiểm tra (theo thứ tự)
```bash
# Từ Victim
ping 192.168.100.10    # → SIEM

# Từ Attacker
ping 192.168.100.20    # → Victim

# Từ Host (CMD Windows)
ping 192.168.100.10    # → SIEM
curl -k https://192.168.100.10:55000   # → Wazuh API

# Mọi VM
ping 8.8.8.8           # → internet qua NAT
```
