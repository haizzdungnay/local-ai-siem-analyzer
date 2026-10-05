# Thiết kế xử lý phát hiện review

**Ngày:** 2026-07-12  
**Branch:** `fix/review-findings-2026-07-12`

## Mục tiêu

Sửa các lỗi an toàn và tính tái dựng trong lab Wazuh mà không mở rộng sang GĐ3:

- FIM demo không sửa file nhạy cảm hay user hệ thống.
- Wazuh Docker dùng workdir ổn định khi installer chạy bằng root.
- Quy trình đổi mật khẩu không xóa dữ liệu Indexer mặc định.
- Rule SSH, sample và tài liệu thống nhất với Wazuh 4.9.0.
- Hướng dẫn DVWA đủ để tái dựng lab.
- Ghi thay đổi dưới mục `[Unreleased]`.

## Quyết định

### Wazuh root-managed

Dùng `/opt/wazuh-docker` làm workdir mặc định. Installer yêu cầu root; `WORKDIR` vẫn cho phép override nhưng phải là đường dẫn tuyệt đối. Docs dùng cùng đường dẫn và lệnh quản trị có `sudo`.

Không tự di chuyển hoặc đổi owner clone cũ. Người dùng muốn tái sử dụng clone khác phải truyền `WORKDIR` rõ ràng.

### FIM probe riêng

Dùng `/var/lib/wazuh-fim-test` làm thư mục probe. Victim cấu hình realtime monitoring riêng cho path này. Script chỉ tạo, sửa và xóa file tạm bằng `mktemp`; `trap` dọn file khi thành công, lỗi hoặc bị ngắt.

Script không được chứa thao tác với `/etc/shadow`, `/etc/passwd`, `/etc/hosts`, `useradd` hoặc `userdel`.

### Password rotation không phá dữ liệu

Luồng mặc định chỉ cập nhật credential đồng bộ, validate Compose và kiểm tra Indexer/Filebeat. Lệnh xóa volume bị đưa khỏi luồng mặc định.

Reset Indexer nằm trong mục riêng, có cảnh báo mất lịch sử alert, bước xác minh volume, backup trước khi xóa và yêu cầu xác nhận của operator. Không dùng `docker volume prune` hoặc `docker compose down -v`.

Kiểm tra API dùng prompt password tương tác thay vì nhúng password vào command line.

### Rule ID theo bằng chứng lab

Các tham chiếu hiện hành dùng rule SSH `5503` với ghi chú "quan sát trên Wazuh 4.9.0". `5710/5712` chỉ còn trong lịch sử changelog hoặc phần giải thích dự kiến cũ.

Sample alert SSH và ví dụ Python đổi sang `5503`; không đổi logic AI stub.

### DVWA tái dựng được

Docs dùng path và URL chữ thường `/var/www/html/dvwa` và `/dvwa`. Quy trình gồm package, clone, config, tạo DB/user, đồng bộ credential lab, setup UI, login, security level và kiểm tra Apache access log.

Không thêm secret thật. Credential lab chỉ là placeholder rõ ràng và phải khớp giữa MariaDB với `config.inc.php`.

## Hợp đồng triển khai chi tiết

### Installer

- Kiểm tra `EUID == 0`, `WORKDIR` là absolute path, khác `/`, không phải symlink trước mọi side effect.
- Mặc định `WORKDIR=/opt/wazuh-docker`; override chỉ qua biến môi trường rõ ràng.
- Nếu workdir tồn tại, yêu cầu có `.git` và `single-node`; nếu không, fail thay vì ghi đè.
- Ghi `vm.max_map_count=262144` vào `/etc/sysctl.d/99-wazuh.conf`, không append `/etc/sysctl.conf`.
- Không thêm environment override cho privilege, sysctl path hoặc FIM path vào production scripts. Test hành vi root chạy trong disposable Docker container Ubuntu; test non-root chạy subprocess bình thường trên host và chỉ xác minh fail-fast trước side effect.
- Container test mount repo read-only và dùng filesystem riêng; fake `git`, `docker`, `sysctl` chỉ nằm trong container. Host `/etc` không thể bị ghi.
- `README.md`, `docs/setup.md` và output script cùng dùng `/opt/wazuh-docker/single-node`.

### FIM

- Script dùng hằng số `/var/lib/wazuh-fim-test`; không nhận path override từ môi trường hay CLI.
- Production yêu cầu root.
- Script tạo directory `0750`, probe `0600`, giữ directory sau run và chỉ dọn probe của chính process.
- Trap xử lý `EXIT`, `INT`, `TERM`.
- Cleanup test chạy trong disposable Ubuntu container. Fake `sleep` xác nhận probe đã tồn tại rồi: case failure trả exit khác 0; case signal tự gửi `INT` hoặc `TERM` vào parent. Sau mỗi case, container assertion xác nhận không còn `probe.*`.
- Docs thêm entry trong `<syscheck>`: `<directories realtime="yes">/var/lib/wazuh-fim-test</directories>`; giữ monitoring `/etc` nếu đã có nhưng không mô tả nó là điều kiện đủ cho demo.

### Password/reset

Luồng mặc định tuyệt đối không chứa `docker volume rm`, `docker volume prune` hoặc `docker compose down -v`. Procedure:

1. `cd /opt/wazuh-docker/single-node`; ghi thời điểm `ROTATION_STARTED=$(date --iso-8601=seconds)`.
2. Backup ba file tracked bởi upstream nhưng chứa credential local: `internal_users.yml`, `docker-compose.yml`, `wazuh_dashboard.yml` nếu file cuối tồn tại; backup vào `/root/wazuh-password-backup/` mode `0700`.
3. Sinh hash bằng image Indexer đúng `4.9.0`; cập nhật riêng block `admin.hash` trong `config/wazuh_indexer/internal_users.yml`.
4. Cập nhật đúng hai biến `INDEXER_PASSWORD` của `wazuh.manager` và `wazuh.dashboard` trong `docker-compose.yml`; không replace chuỗi toàn file ngoài hai consumer đã xác định.
5. Chạy `docker compose config --quiet`. Nếu fail, restore file backup và abort trước restart.
6. Chạy `docker compose down` rồi `docker compose up -d`; không xóa volume.
7. Nếu stack không healthy, restore ba file backup và restart lại stack bằng credential cũ.
8. Indexer `9200` phải trả HTTP `200` bằng `docker compose exec -it wazuh.indexer curl -sk -o /dev/null -w '%{http_code}\n' -u admin https://localhost:9200`; curl prompt password, password không nằm trong argument.
9. Chạy `docker compose logs --since "$ROTATION_STARTED" wazuh.manager | grep -Ei '401 Unauthorized|indexer.*(error|failed)'`; pass khi không có match mới.
10. Dashboard login kiểm tra thủ công; không tuyên bố pass khi chưa có lab.

Mục `Reset Indexer data — phá dữ liệu, không thuộc password rotation` tách riêng và yêu cầu operator gõ chính xác `RESET INDEXER DATA`. Procedure:

1. Lấy Compose project từ label của container `wazuh.indexer`; volume đích là volume mount tại container path `/var/lib/wazuh-indexer` và phải có labels `com.docker.compose.project=<project>` cùng `com.docker.compose.volume=wazuh-indexer-data`.
2. `docker volume inspect` phải xác nhận cả hai label; nếu không, abort.
3. Dừng stack bằng `docker compose down`.
4. Tạo `/opt/wazuh-backups` root-owned mode `0700`.
5. Backup read-only: `docker run --rm --mount source="$INDEXER_VOLUME",target=/from,readonly --mount type=bind,source=/opt/wazuh-backups,target=/to alpine tar -czf /to/indexer-data-backup.tgz -C /from .`.
6. Kiểm tra archive tồn tại, khác rỗng và lưu `sha256sum` trước confirmation.
7. Nếu confirmation sai hoặc bước nào fail, abort trước `docker volume rm "$INDEXER_VOLUME"`.
8. Sau reset, `docker compose up -d`, kiểm tra Indexer `200`, Filebeat không `401`, và alert mới xuất hiện.
9. Rollback: stop stack, tạo lại volume cùng tên/labels qua Compose, restore bằng `docker run --rm --mount source="$INDEXER_VOLUME",target=/to --mount type=bind,source=/opt/wazuh-backups,target=/from,readonly alpine sh -c 'cd /to && tar -xzf /from/indexer-data-backup.tgz'`, rồi start và chạy lại health checks.

### Rule/sample

- `eval/samples/alert-ssh-bruteforce.json` phải đồng bộ `rule.id=5503`, description `PAM: User login failed` và metadata thực có trong sample; không gắn metadata brute-force không được quan sát.
- Allowlist `5710/5712`: chỉ các release lịch sử `1.1.0` và `1.2.0` trong `CHANGELOG.md`. Không còn ở bất kỳ file hiện hành nào khác.
- Hai file Python chỉ đổi example/docstring, không đổi logic GĐ3.

### DVWA

- Docs bám dependency upstream DVWA cho Ubuntu/Debian: `git apache2 mariadb-server mariadb-client php php-mysqli php-gd libapache2-mod-php`; clone vào `/var/www/html/dvwa`; copy config.
- SQL cụ thể tạo database `dvwa`, user `dvwa@localhost`, password lab placeholder `DVWA_DB_PASSWORD`, grant `ALL` trên `dvwa.*`, rồi `FLUSH PRIVILEGES`.
- `config.inc.php` đặt `db_server=127.0.0.1`, `db_database=dvwa`, `db_user=dvwa`, `db_password` đúng cùng giá trị. Repo owner `root:root`; chỉ `hackable/uploads` và `config` được cấp group `www-data` với quyền ghi cần thiết, không dùng `chmod -R 777`.
- Mở `setup.php`, Create/Reset Database, login mặc định `admin/password`, đặt security `low`, kiểm tra `/var/log/apache2/access.log`.
- Cảnh báo DVWA cố ý chứa lỗ hổng: chỉ bind/truy cập trên host-only lab, không port-forward từ NAT và không expose internet.
- Mọi URL/path dùng chữ thường `/dvwa`.

## File dự kiến thay đổi và ownership

Worker hạ tầng sở hữu:

- `scripts/attacks/fim-trigger.sh`
- `scripts/setup/install-wazuh.sh`
- `tests/test_lab_scripts.py`

Worker tài liệu sở hữu:

- `scripts/attacks/ssh-bruteforce.sh`
- `README.md`
- `docs/setup.md`
- `docs/attacks.md`
- `KE_HOACH.md`
- `eval/samples/alert-ssh-bruteforce.json`
- `ai_module/extractor.py` (doc/example only)
- `ai_module/rag.py` (doc/example only)
- `CHANGELOG.md`

Main agent chỉ tích hợp và sửa finding review; không để hai worker cùng ghi một file.

## Kiểm thử

### Regression guard bắt buộc

Tạo `tests/test_lab_scripts.py` bằng `unittest` và stdlib. RED cases trước implementation:

- Installer non-root/relative `/`/symlink workdir fail trước fake command được gọi.
- Installer clone đúng destination và Compose chạy trong `single-node`.
- `SYSCTL_CONFIG` chỉ ghi fixture trong test; host `/etc` không bị chạm.
- FIM success, injected failure, `SIGINT`, `SIGTERM` đều xóa probe; fixture directory còn lại.
- FIM source không chứa `/etc/shadow`, `/etc/passwd`, `/etc/hosts`, `useradd`, `userdel`.
- Docs hiện hành dùng `/opt/wazuh-docker`, `/var/lib/wazuh-fim-test`, `/dvwa`, rule `5503`.
- Luồng password mặc định không chứa destructive volume commands; reset section có backup, inspect và confirmation.
- Markdown fences không escaped, fence count cân bằng; local Markdown links tới file tồn tại. Anchor ngoài scope.
- `[Unreleased]` đứng trước `1.2.0` và ghi đủ FIM, workdir, password, SSH, DVWA, Markdown; lịch sử release giữ nguyên.

### Static commands

- `python -m unittest discover -s tests -v`
- `git diff --check`
- `bash -n scripts/setup/*.sh scripts/attacks/*.sh`
- `python -m compileall -q ai_module`
- `python -m json.tool eval/samples/alert-ssh-bruteforce.json`

### Live lab

Không tuyên bố live test pass nếu không có Victim/Wazuh runtime. Báo rõ các bước chưa chạy:

- Alert FIM xuất hiện trong 60 giây.
- SSH sinh rule `5503`.
- DVWA dựng được từ Victim snapshot sạch.
- Password rotation giữ Indexer/Filebeat healthy.

## Multi-agent workflow

1. TDD agent xác định regression checks.
2. Worker hạ tầng sửa FIM và installer.
3. Worker tài liệu đồng bộ rules, DVWA, password flow và changelog.
4. Main agent tích hợp, tránh hai worker sửa cùng file.
5. Code reviewer, security reviewer và Python reviewer rà độc lập.
6. Sửa mọi CRITICAL/HIGH, chạy verification mới.
7. Commit bằng Conventional Commit và push branch lên `origin`.

## Tiêu chí hoàn tất

- Không còn thao tác nguy hiểm trong FIM script.
- Workdir installer nhất quán và tuyệt đối.
- Password flow mặc định không xóa volume.
- Rule hiện hành thống nhất `5503`.
- DVWA docs có thể làm theo từ máy sạch.
- Markdown render đúng.
- `CHANGELOG.md` có `[Unreleased]` trước `1.2.0`, ghi đủ sáu nhóm remediation và không rewrite lịch sử.
- Static/sandbox checks pass; live checks chưa chạy được ghi rõ.
- `README.md`, setup docs và script thống nhất `/opt/wazuh-docker`.
- Password flow mặc định không có lệnh phá dữ liệu; reset section có inspect, backup, checksum, confirmation và rollback procedure.
- DVWA chỉ được hướng dẫn trên host-only lab, không expose internet.
- Branch được push; không merge `main`, không tạo tag.
