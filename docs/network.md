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
| Victim Windows | 192.168.100.40 | DHCP | 4 GB |

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

## ⚠️ Fix bắt buộc: tắt cloud-init ghi đè netplan (Ubuntu Server)

Ubuntu Server dùng **cloud-init**, mặc định sẽ tự sinh lại `/etc/netplan/50-cloud-init.yaml` và ghi đè cấu hình IP tĩnh về DHCP-only **mỗi lần VM reboot**. Nếu không fix, IP tĩnh sẽ mất sau mỗi lần khởi động lại.

Làm **1 lần duy nhất** trên mỗi máy Ubuntu (SIEM, Victim):

```bash
sudo nano /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```
Nội dung:
```yaml
network: {config: disabled}
```

Sau đó xóa file netplan do cloud-init sinh (nếu tồn tại) để tránh xung đột:
```bash
sudo rm -f /etc/netplan/50-cloud-init.yaml
sudo netplan apply
```

**Lưu ý:** chỉ giữ **đúng 1 file** netplan trong `/etc/netplan/` (ví dụ `01-lab.yaml`). Nhiều file cùng tồn tại có thể đọc theo thứ tự alphabet và đá nhau, gây trạng thái mạng "IP đúng nhưng không route được".

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

## Troubleshooting: máy thấy được chính nó nhưng không ping thông các máy khác

Nếu 1 VM tự ping được chính nó (`ip a` báo IP đúng dải `192.168.100.0/24`) nhưng **không ping được** 2 máy còn lại — trong khi 2 máy kia vẫn thấy nhau bình thường — nguyên nhân thường là **VMware gán nhầm virtual switch** cho card mạng của riêng VM đó (hay gặp khi đổi Network Adapter trong Settings lúc VM đang chạy).

Cách fix:
1. Vào **VM → Settings → Network Adapter** (card đang lỗi)
2. Đổi tạm sang **Bridged** → **Apply**
3. Đổi lại đúng loại ban đầu (**NAT** hoặc **Custom: VMnet1**) → **Apply**
4. **Power Off** hẳn VM (không phải `reboot` trong OS) → **Power On** lại
5. Test ping lại — bước Power Off/Power On là bắt buộc để VMware re-bind card vào đúng vSwitch.

## Troubleshooting: Dashboard/Indexer timeout dù container báo "Up"

Nếu truy cập `https://192.168.100.10` bị timeout/không kết nối được, nhưng `docker compose ps` báo cả 3 container `Up X ngày` bình thường, và `ping 192.168.100.10` vẫn thông (loại trừ lỗi mạng tầng ngoài) — nguyên nhân thường nằm ở disk đầy trên SIEM, đôi khi kéo theo Docker bridge network bị hỏng theo.

Cách chẩn đoán theo thứ tự:
```bash
# 1. Test TLS trực tiếp trên SIEM (loại trừ mạng ngoài)
curl -k -v https://localhost:9200 2>&1 | tail -20
# Nếu thấy "Connection reset by peer" ngay giữa TLS handshake → tiếp bước 2

# 2. Kiểm tra disk
df -h /
# Nếu ≥90% → đây là nghi phạm chính

# 3. Tìm thư mục chiếm dung lượng trong queue Manager
docker exec single-node-wazuh.manager-1 sh -c 'du -sh /var/ossec/queue/* 2>/dev/null | sort -rh'
```

Nguyên nhân thường gặp là module Vulnerability Detector (`queue/vd_updater` + `queue/vd`) tự tải/cập nhật CVE database định kỳ, không có cơ chế dọn phiên bản cũ — có thể chiếm hàng chục GB sau vài ngày chạy.

Fix:
```bash
docker exec single-node-wazuh.manager-1 sh -c 'rm -rf /var/ossec/queue/vd_updater/* /var/ossec/queue/vd/*'
df -h /   # xác nhận đã giải phóng
```

Nếu dọn disk xong nhưng vẫn timeout, Docker bridge network có thể đã hỏng. Sau đợt I/O nặng do disk đầy, bridge network đôi khi bị treo dù container vẫn "Up" và tự trả lời OK ở `localhost` bên trong container. Dấu hiệu: `ping <container_IP>` từ host cũng fail (lấy container IP bằng `docker inspect <container> | grep IPAddress`).

Fix bằng cách restart Docker daemon để rebuild lại iptables + bridge:
```bash
sudo systemctl restart docker
```
Đợi 1-2 phút cho 3 container tự lên lại (nhờ `restart: always` policy), sau đó test lại `curl -k https://localhost:9200`.

Phòng ngừa lâu dài: cân nhắc tắt Vulnerability Detector nếu đề tài không cần tính năng scan lỗ hổng (`<vulnerability-detection><enabled>no</enabled></vulnerability-detection>` trong `ossec.conf` của Manager), tránh lặp lại sự cố disk đầy.

Có thể xác minh nguyên nhân bằng `tcpdump` trước khi fix:
```bash
sudo tcpdump -i <card> -n port 67 or port 68 -c 5
```
Nếu thấy gói DHCPDISCOVER liên tục gửi đi (interval 3s, 6s, 14s...) mà không có DHCPOFFER phản hồi → xác nhận vấn đề nằm ở VMware, không phải ở cấu hình Ubuntu.
