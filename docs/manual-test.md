# Hướng dẫn kiểm thử thủ công toàn bộ project

Tài liệu này dành cho người kiểm thử thực tế. Làm theo đúng thứ tự. Mỗi block ghi rõ máy chạy, shell, lệnh, kết quả mong đợi, thời gian chờ và cách xử lý lỗi.

## 0. Phạm vi và sơ đồ máy

| Máy | IP Host-only | Tài khoản SSH | Vai trò |
|---|---|---|---|
| Host Windows | `192.168.100.1` | local | Repo, Python, Ollama, AI/eval |
| SIEM Ubuntu | `192.168.100.10` | `wazuh` | Wazuh Docker, Manager `55000`, Indexer `9200` |
| Victim Ubuntu | `192.168.100.20` | `trnguyn` | Wazuh agent, SSH, Apache/DVWA, FIM |
| Kali | `192.168.100.30` | `kali` | Sinh SSH/web traffic có giới hạn |
| Victim Windows | `192.168.100.40` | VMware console | Wazuh agent; Sysmon chưa xác nhận |

**Credential lab:** không ghi hoặc truyền mật khẩu qua runbook. Dùng SSH key hoặc secret manager/config gitignored do operator quản lý; chỉ định danh placeholder trong mọi bằng chứng và báo cáo.

Luồng cần chứng minh:

```text
Kali .30 → Victim .20 → Wazuh agent → SIEM .10 Indexer :9200
                                            ↓
Host .1 Python/RAG/Ollama ← đọc alert ──────┘
```

Chỉ chạy trên lab cô lập `192.168.100.0/24`. Không đổi target script sang hệ thống ngoài lab. Không in hoặc commit `ai_module/config.yaml`, password Indexer, SSH private key. Tạo VMware snapshot trước live test.

---

## 1. Chuẩn bị trên Host Windows `.1`

**Máy chạy:** Host Windows
**Shell:** PowerShell
**Thư mục:** `C:\Users\Tplab\local-ai-siem-analyzer`

```powershell
Set-Location C:\Users\Tplab\local-ai-siem-analyzer

git branch --show-current
git status --short
python --version
ollama list
```

**PASS khi:**

- Branch là `claude/lab-eval-checkpoint` hoặc branch review chứa các commit mới nhất.
- Python chạy được.
- `ollama list` có:
  - `qwen2.5:7b`
  - `CyberCrew/notmythos-8b`
  - `nomic-embed-text`
- `git status --short` không có file lạ ngoài danh sách đã biết.

Nếu thiếu model:

```powershell
ollama pull qwen2.5:7b
ollama pull CyberCrew/notmythos-8b
ollama pull nomic-embed-text
```

Kiểm tra kết nối bốn VM:

```powershell
Test-Connection 192.168.100.10 -Count 2
Test-Connection 192.168.100.20 -Count 2
Test-Connection 192.168.100.30 -Count 2
Test-Connection 192.168.100.40 -Count 2
```

**PASS khi:** mỗi máy phản hồi. Windows `.40` có thể tắt nếu không test nhánh Windows; ghi rõ SKIP, không ghi PASS.

Kiểm tra port SIEM:

```powershell
Test-NetConnection 192.168.100.10 -Port 9200
Test-NetConnection 192.168.100.10 -Port 55000
```

**PASS khi:** `TcpTestSucceeded : True` cho cả hai. Port `9200` là Indexer chứa alert; `55000` là Manager API quản trị.

Kiểm tra Indexer bằng placeholder password, không hardcode vào file:

```powershell
$IndexerPassword = Read-Host "Indexer password" -AsSecureString
$BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($IndexerPassword)
$PlainIndexerPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
curl.exe -k -u "admin:$PlainIndexerPassword" "https://192.168.100.10:9200/_cluster/health?pretty"
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
Remove-Variable IndexerPassword,PlainIndexerPassword,BSTR -ErrorAction SilentlyContinue
```

**PASS khi:** nhận JSON cluster health; `status` thường `green` hoặc `yellow` trên single-node. `401` nghĩa là credential sai. Timeout nghĩa là kiểm tra SIEM/Docker ở mục 2.

Cài dependency project:

```powershell
python -m pip install -r ai_module/requirements.txt
python -m pip install -r ai_module/requirements-dev.txt
```

Nếu chưa có config:

```powershell
Copy-Item ai_module/config.example.yaml ai_module/config.yaml
notepad ai_module/config.yaml
```

Điền credentials local. File này đã gitignore. Không gửi nội dung file vào báo cáo.

---

## 2. Kiểm tra SIEM Ubuntu `.10`

### 2.1 Kết nối

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" wazuh@192.168.100.10
```

Các lệnh tiếp theo chạy **trong SIEM Ubuntu**.

```bash
hostname
ip -4 addr
df -h /
ss -ltn | grep -E ':(9200|55000)\b'
```

**PASS khi:** hostname đúng SIEM, có IP `.10`, disk dưới 90%, cả `9200` và `55000` đang LISTEN.

### 2.2 Wazuh Docker

```bash
cd ~/wazuh-docker/single-node
docker compose ps
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

**PASS khi:** Manager, Indexer, Dashboard đều `Up`. Nếu vừa start, chờ 2–3 phút.

```bash
docker compose logs --tail 50 wazuh.manager
docker compose logs --tail 50 wazuh.indexer
```

Không được có crash loop liên tục. Một vài warning single-node không tự động là FAIL; ghi log lỗi cụ thể.

### 2.3 Kiểm tra agent từ Dashboard

Trên Host mở:

```text
https://192.168.100.10
```

Vào **Agents**. Mong đợi:

- Ubuntu Victim `.20`: Active.
- Windows Victim `.40`: Active nếu máy đang bật.

Sysmon chưa được xác nhận trong project; không đánh dấu Sysmon PASS chỉ vì WazuhSvc Active.

### 2.4 Troubleshooting SIEM

Nếu container Up nhưng port timeout:

```bash
curl -k -v https://localhost:9200 2>&1 | tail -20
df -h /
docker exec single-node-wazuh.manager-1 sh -c 'du -sh /var/ossec/queue/* 2>/dev/null | sort -rh | head'
```

Nếu disk ≥90% và `vd_updater`/`vd` chiếm bất thường, dừng test và xác nhận trước khi xóa cache. Không chạy wipe Indexer volume trong happy path.

Nếu disk ổn nhưng Docker bridge treo:

```bash
sudo systemctl restart docker
```

Chờ 1–2 phút, chạy lại `docker compose ps` và port checks.

Thoát SIEM:

```bash
exit
```

---

## 3. Kiểm tra Victim Ubuntu `.20`

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" trnguyn@192.168.100.20
```

Các lệnh tiếp theo chạy **trong Victim Ubuntu**.

### 3.1 Network và service

```bash
hostname
ip -4 addr
ping -c 2 192.168.100.10
systemctl is-active ssh
systemctl is-active apache2
systemctl is-active wazuh-agent
```

**PASS khi:** có `.20`; ping SIEM pass; `ssh`, `apache2`, `wazuh-agent` đều `active` cho full test.

### 3.2 Log collection

```bash
sudo grep -n '/var/log/auth.log' /var/ossec/etc/ossec.conf
sudo grep -n '/var/log/apache2/access.log' /var/ossec/etc/ossec.conf
sudo grep -n '<directories realtime="yes">/opt/wazuh-fim-lab</directories>' /var/ossec/etc/ossec.conf
```

**PASS khi:** thấy cả auth log, Apache access log và FIM marker directory.

Nếu FIM directory thiếu, sửa `/var/ossec/etc/ossec.conf` trong block `<syscheck>`:

```xml
<directories realtime="yes">/opt/wazuh-fim-lab</directories>
```

Sau đó:

```bash
sudo mkdir -p /opt/wazuh-fim-lab
sudo chmod 750 /opt/wazuh-fim-lab
sudo systemctl restart wazuh-agent
systemctl is-active wazuh-agent
```

**PASS khi:** agent trở lại `active`.

### 3.3 DVWA/Apache

```bash
curl -sS -o /dev/null -w 'Apache root: %{http_code}\n' http://127.0.0.1/
curl -sS -o /dev/null -w 'DVWA: %{http_code}\n' http://127.0.0.1/DVWA/
```

**PASS khi:** Apache trả HTTP response; DVWA thường `302` trước login.

Không có Apache: xem `docs/setup.md`. Không chạy web scenario cho tới khi access log tồn tại và agent thu log.

Thoát Victim trước khi sang Kali:

```bash
exit
```

---

## 4. Kiểm tra Kali `.30`

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" kali@192.168.100.30
```

Trong Kali:

```bash
hostname
ip -4 addr
ping -c 2 192.168.100.20
command -v hydra
command -v nikto
command -v curl
curl -sS -o /dev/null -w 'Victim HTTP: %{http_code}\n' http://192.168.100.20/DVWA/
```

**PASS khi:** có `.30`, ping `.20` pass, ba tool có path, Victim trả HTTP response.

Thiếu tool:

```bash
sudo apt update
sudo apt install -y hydra nikto curl
```

Thoát Kali để copy script từ Host:

```bash
exit
```

---

## 5. Scenario SSH failed-auth có giới hạn

### 5.1 Copy script

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
Set-Location C:\Users\Tplab\local-ai-siem-analyzer
scp -i "$env:USERPROFILE\.ssh\id_ed25519" .\scripts\attacks\ssh-bruteforce.sh kali@192.168.100.30:/tmp/ssh-bruteforce.sh
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" kali@192.168.100.30 "tr -d '\r' </tmp/ssh-bruteforce.sh >/tmp/ssh-bruteforce-lf.sh && mv /tmp/ssh-bruteforce-lf.sh /tmp/ssh-bruteforce.sh"
```

`tr -d '\r'` tránh lỗi `pipefail\r` khi Windows chuyển CRLF sang Kali.

### 5.2 Chạy

**Máy chạy:** Kali `.30`
**Shell:** Bash qua SSH từ Host

```powershell
Measure-Command {
  ssh -i "$env:USERPROFILE\.ssh\id_ed25519" kali@192.168.100.30 "bash /tmp/ssh-bruteforce.sh 192.168.100.20 trnguyn ignored 20"
}
```

**PASS khi:** script báo 20 failed attempts hoàn tất; không báo credential hợp lệ. Chỉ target `.20` được script chấp nhận.

Chờ Indexer ingest tối đa 120 giây. Không chạy lại ngay khi chưa query lượt trước.

### 5.3 Query alert

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
python ai_module/main.py --limit 10 --model qwen2.5:7b
```

Để kiểm chính xác rule qua Indexer, dùng Python project:

```powershell
$env:PYTHONPATH = "ai_module"
python -c "from reader import load_config,fetch_alerts_api; from collections import Counter; c=load_config('ai_module/config.yaml'); a=fetch_alerts_api(c,50); print(Counter(str(x.get('rule',{}).get('id','')) for x in a if str(x.get('data',{}).get('srcip',''))=='192.168.100.30'))"
Remove-Item Env:PYTHONPATH
```

**PASS khi:** có `5503` và/hoặc `5760`. Correlation `2502` có thể xuất hiện tùy cửa sổ rule. Không có correlation không làm single-event test FAIL.

---

## 6. Scenario web

### 6.1 Copy và normalize script

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
scp -i "$env:USERPROFILE\.ssh\id_ed25519" .\scripts\attacks\web-attack.sh kali@192.168.100.30:/tmp/web-attack.sh
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" kali@192.168.100.30 "tr -d '\r' </tmp/web-attack.sh >/tmp/web-attack-lf.sh && mv /tmp/web-attack-lf.sh /tmp/web-attack.sh"
```

### 6.2 Chạy bounded web test

Script chỉ chấp nhận Victim canonical `192.168.100.20`. Mỗi mode in `START_UTC`/`END_UTC` để tạo custom analysis window riêng:

```powershell
foreach ($Scenario in @("baseline", "error-burst", "signatures", "nikto")) {
  $Extra = if ($Scenario -eq "nikto") { "I_UNDERSTAND_NIKTO_ALERT_VOLUME" } else { "" }
  ssh -i "$env:USERPROFILE\.ssh\id_ed25519" kali@192.168.100.30 `
    "bash /tmp/web-attack.sh 192.168.100.20 $Scenario 6 $Extra"
  Start-Sleep -Seconds 120
}
```

Các mode:

- `baseline`: 3 request điều hướng bình thường; kỳ vọng không tạo attack alert.
- `error-burst`: 3–10 missing path, mặc định 6; dùng để kiểm `31101/31151`.
- `signatures`: đúng 3 request có dạng SQLi, XSS và traversal; không đăng nhập hoặc thay đổi dữ liệu DVWA.
- `nikto`: explicit-only, yêu cầu token `I_UNDERSTAND_NIKTO_ALERT_VOLUME`; scan dùng `-maxtime 45s` và hard wall-clock wrapper 50 giây (`kill-after` 5 giây). Live evidence cho thấy một lượt có thể tạo hơn 5.000 alert, nên không chạy lại khi chưa query/cleanup batch trước.
- `all`: chỉ chạy `baseline`, `error-burst`, `signatures`; Nikto bị loại khỏi default/`all` để tránh alert flood ngoài ý muốn.

Curl có thể trả `302`/`404`; đây là expected traffic, không chứng minh payload thực thi hoặc exploit thành công.

**PASS khi:** từng mode hoàn tất, in HTTP codes cùng UTC boundary và không vượt cap/thời gian trên.

### 6.3 Rule mong đợi

Chờ tối đa 120 giây, query như mục 5.3. Mong đợi:

- `31101`: web error request.
- `31151`: multiple web errors correlation.
- `31105`: XSS signature.

Có `31101` nhưng chưa có `31151`: chờ thêm ingest/correlation; không tăng request vô hạn.

### 6.4 Review phản hồi AI theo scenario

Sau thời gian ingest, chạy dashboard rồi tạo custom window từ 30 giây trước `START_UTC` tới 30 giây sau `END_UTC` của từng mode. Không gộp các mode nếu mục tiêu là so sánh phản hồi:

```powershell
python ai_module/dashboard.py
```

Mở `http://127.0.0.1:8765`, chọn **Tùy chỉnh**, model allowlist và kiểm tra:

- `baseline`: job có thể `succeeded` với 0 alert/0 AI result; không xem đây là lỗi.
- `error-burst`: AI phải mô tả repeated web errors/probing; không được khẳng định đã compromise.
- `signatures`: AI phải nhắc payload pattern đáng ngờ nếu alert có bằng chứng; không được nói SQLi/XSS đã thực thi chỉ từ access log.
- `nikto`: AI nên nhận diện scanning/recon từ nhiều web error/signature, kèm khuyến nghị đối chiếu source/timeline.
- Timeline, Top rules và table phải cùng phản ánh custom window; dưới detail cap, Full alert phải mở đúng reference. Trên cap, UI phải ghi `aggregate only` và không giả vờ có full-alert rows.

Ghi factual summary, severity, evidence đúng/sai và hallucination vào `HANDOFF.md`; không chép raw `_source`, hostname hoặc live identifier chưa sanitize vào tracked output.

### 6.5 Evidence live đã ghi ngày 2026-07-31

| Mode | Traffic/Indexer evidence | Dashboard/AI evidence | Đánh giá |
|---|---|---|---|
| `baseline` | `302/200/200`, 0 alert | Job `#4` succeeded, 0 alert/0 result | PASS empty-window, không gọi AI |
| `error-burst` | 6 × `404`, 6 × `31101`, không có `31151` ở cap 6 | Job `#5` succeeded, 1 group/1 result; AI low, summary/root cause yếu | Pipeline PASS, semantic FAIL |
| `signatures` | `31105` XSS attempt + `31104` common web attack | Job `#6` succeeded, 2 groups/1 result; AI low, MITRE mis-map | Evidence grounding FAIL |
| `nikto` full window (trước aggregate fallback) | 5,737 alert trong khoảng 16 giây | Job `#7` failed ở detail cap 2.000 | Historical safety finding; dùng để acceptance-test aggregate-only mới |
| `nikto` 1-second slice | 362 alert, 8 groups, nhiều rule 31xxx | Job `#8` succeeded 362/362; AI high, remediation liên quan nhưng root cause rỗng/MITRE còn over-map | Pipeline PASS, cần human review |

Kết luận của lượt này: dashboard đọc log thật; implementation mới giữ cap cho full detail nhưng phân tích cửa sổ lớn bằng aggregate-only. AI output vẫn là advisory và chưa đủ evidence-grounded để coi severity/MITRE là ground truth.

---

## 7. Scenario FIM an toàn

**Máy chạy:** Host Windows
**Shell:** PowerShell gọi Victim

Tạo marker, chờ baseline, sửa marker:

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" trnguyn@192.168.100.20 "sudo mkdir -p /opt/wazuh-fim-lab && sudo chmod 750 /opt/wazuh-fim-lab && printf 'baseline\n' | sudo tee /opt/wazuh-fim-lab/manual-marker.txt >/dev/null && sleep 20 && printf 'changed\n' | sudo tee -a /opt/wazuh-fim-lab/manual-marker.txt >/dev/null && sleep 20"
```

**PASS khi Indexer có:**

- `554`: file added.
- `550`: integrity checksum changed.

Không sửa `/etc/shadow`, `/etc/passwd`, `/etc/hosts`.

Query bằng `python ai_module/main.py --limit 10` hoặc Indexer helper như mục 5.3. Xác minh path `/opt/wazuh-fim-lab/manual-marker.txt`.

Cleanup chỉ sau khi đã capture đủ bằng chứng:

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" trnguyn@192.168.100.20 "sudo rm -f /opt/wazuh-fim-lab/manual-marker.txt"
```

Cleanup có thể sinh rule `553 File deleted`; ghi đây là cleanup artifact, không phải malicious event.

---

## 8. Windows Victim `.40`

**Máy chạy:** Windows Victim qua VMware console
**Shell:** PowerShell chạy Administrator

```powershell
Get-NetIPAddress -AddressFamily IPv4
Get-Service WazuhSvc
sc.exe query WazuhSvc
Test-Connection 192.168.100.10 -Count 2
```

**PASS khi:** card Host-only có `.40`, `WazuhSvc` Running, ping `.10` pass, Dashboard báo agent Active.

Nếu service chưa có, cài đúng version Manager:

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "wazuh-agent-4.9.0-1.msi"
msiexec.exe /i wazuh-agent-4.9.0-1.msi /q WAZUH_MANAGER="192.168.100.10"
NET START WazuhSvc
```

`Error 1925`: terminal chưa elevated. Mở PowerShell bằng **Run as administrator**.

Sysmon chưa có config/test canonical trong repo. Chỉ ghi `Windows agent PASS`; ghi `Sysmon SKIP/not verified`.

---

## 9. Kiểm thử AI pipeline trên Host

**Máy chạy:** Host Windows
**Shell:** PowerShell

### 9.1 Unit/integration mock

```powershell
Set-Location C:\Users\Tplab\local-ai-siem-analyzer
python -m compileall -q ai_module eval tests
$env:PYTHONPATH = "ai_module"
python -m pytest tests -q
Remove-Item Env:PYTHONPATH
```

**PASS hiện tại:** 26 tests trước khi thêm thay đổi mới; dùng số thực tế terminal làm bằng chứng.

### 9.2 Demo frozen samples

```powershell
python ai_module/main.py --demo --model qwen2.5:7b
python ai_module/main.py --demo --model qwen2.5:7b --language en
```

**PASS khi:** in extracted fields và JSON có đúng năm field legacy; output kèm provenance cho model, prompt version/hash, language và options khi gọi có provenance.

### 9.3 Live Indexer/RAG/Ollama

```powershell
Measure-Command {
  python ai_module/main.py --limit 5 --model qwen2.5:7b
}
```

**PASS khi:** đọc Indexer `.10:9200`, RAG không crash, Ollama trả JSON cho từng alert. `InsecureRequestWarning` có thể xuất hiện khi lab dùng self-signed cert; production cần CA verification.

Nếu lỗi `UnicodeEncodeError`, phải dùng version có `_configure_console_encoding()` hoặc chạy:

```powershell
$env:PYTHONIOENCODING = "utf-8"
python ai_module/main.py --limit 5 --model qwen2.5:7b
Remove-Item Env:PYTHONIOENCODING
```

---

## 10. Baseline 33 case RAG/no-RAG

Mỗi lần chạy prompt mới phải dùng một file kết quả riêng. Runner không ghi đè
`eval/results.csv` baseline lịch sử; provenance và language được ghi thêm vào
CSV mới.

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
$env:PYTHONIOENCODING = "utf-8"
Measure-Command {
  python eval/run_eval.py --model qwen2.5:7b --language vi --results eval/results-soc-contract-v1-vi-rag.csv
}
Measure-Command {
  python eval/run_eval.py --model qwen2.5:7b --language vi --no-rag --results eval/results-soc-contract-v1-vi-no-rag.csv
}
Remove-Item Env:PYTHONIOENCODING
```

**PASS khi:** mỗi lượt `[33/33]`, CSV có 33 row, không error. Không sửa prompt/config/extractor giữa hai lượt.

Tổng hợp:

```powershell
python eval/summarize_results.py eval/results-soc-contract-v1-vi-rag.csv eval/results-soc-contract-v1-vi-no-rag.csv
```

---

## 11. AI-only rubric scoring 66 output

AI scoring không thay human review. Judge model khác candidate nhưng vẫn là AI.

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
ollama show CyberCrew/notmythos-8b
$env:PYTHONIOENCODING = "utf-8"
Measure-Command {
  python eval/judge_results.py `
    --judge-model CyberCrew/notmythos-8b `
    --temperature 0 `
    --seed 20260729 `
    --results eval/results.csv eval/results-no-rag.csv `
    --output eval/ai-judgments-notmythos-8b.csv
}
Remove-Item Env:PYTHONIOENCODING
```

**PASS khi:** 66/66 judgment, không `ERROR`. Lệnh hỗ trợ resume: chạy lại sẽ in `resume` cho row hợp lệ, retry row lỗi.

Tổng hợp:

```powershell
python eval/summarize_results.py `
  eval/results.csv eval/results-no-rag.csv `
  --ai-judgments eval/ai-judgments-notmythos-8b.csv
```

Kiểm tra output phải ghi `judge_type=ai-rubric-judge` và limitation không phải human review.

---

## 12. Người thật chấm blind và đo thời gian

Mục này mới là manual human evaluation.

### 12.1 Chuẩn bị file riêng

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
Copy-Item eval/results.csv eval/results-human-rag.csv
Copy-Item eval/results-no-rag.csv eval/results-human-no-rag.csv
New-Item -ItemType Directory -Force eval/manual-analysis
```

Không chấm trực tiếp file baseline gốc.

### 12.2 Phân tích tay 33 case

Reviewer A chỉ mở `eval/cases/*.json`; không mở `expected`, results AI hoặc AI judgments.

Cho từng case:

```powershell
$Case = "ssh-5503-01"
$Timer = [Diagnostics.Stopwatch]::StartNew()
notepad "eval/cases/$Case.json"
```

Reviewer viết file `eval/manual-analysis/<case_id>.json` với đúng schema:

```json
{
  "case_id": "ssh-5503-01",
  "summary": "...",
  "root_cause": "...",
  "severity": "low|medium|high|critical",
  "mitre": "...",
  "next_steps": ["..."],
  "elapsed_s": 0,
  "analyst": "reviewer-a"
}
```

Sau khi viết xong:

```powershell
$Timer.Stop()
$Timer.Elapsed.TotalSeconds
```

Điền số giây vào `elapsed_s`. Lặp đủ 33 case. Không xem expected trước khi hoàn tất.

### 12.3 Chấm 66 AI output

Reviewer B đọc:

- `eval/rubric.md`
- `eval/expected/<case_id>.json`
- Candidate `output_json` trong hai bản copy CSV.

Điền 1–5 vào:

- `summary_score`
- `root_cause_score`
- `severity_score`
- `mitre_score`
- `next_steps_score`
- `reviewer`
- `notes`

Không copy điểm từ `ai-judgments-notmythos-8b.csv`. Nếu dùng AI score để tham khảo, phải ghi đây là assisted review, không blind human review.

Hai reviewer lệch >1 ở bất kỳ tiêu chí nào: thảo luận và ghi lý do adjudication trong `notes`.

Tổng hợp bản human:

```powershell
python eval/summarize_results.py eval/results-human-rag.csv eval/results-human-no-rag.csv
```

Chỉ kết luận manual-vs-AI time saving khi đủ 33 `elapsed_s` và semantic scores đã hoàn tất.

---

## 13. Dashboard AI local

**Máy chạy:** Host Windows
**Shell:** PowerShell
**URL:** `http://127.0.0.1:8765`

### 13.1 Start và health

```powershell
Set-Location C:\Users\Tplab\local-ai-siem-analyzer
python ai_module/dashboard.py
```

**PASS khi:** terminal báo Waitress phục vụ trên `127.0.0.1:8765`; browser mở được trang; Health hiển thị app/worker/RAG. Không đổi host thành `0.0.0.0`.

Model selector lấy giao của model đã cài (`Ollama /api/tags`) với `dashboard.allowed_models` trong config. Thiếu model thì pull rồi restart:

```powershell
ollama pull qwen2.5:3b
ollama pull qwen2.5:7b
```

### 13.2 Manual window

1. Chọn preset `5 phút`, model, ngôn ngữ AI (`Tiếng Việt` hoặc `English`) và bấm **Đưa vào hàng đợi**.
2. Job mới phải tự mở và hiện phase backend theo thứ tự phù hợp: `queued → fetching_alerts → preparing_analysis → calling_ollama → saving_result → completed`. Không bắt buộc nhìn thấy mọi phase nếu model/cửa sổ chạy nhanh; ứng dụng không cố tình delay để tạo loading giả.
3. Mở job và đối chiếu khoảng thời gian tuyệt đối, alert count, groups, model, language, mode và window summary. Kết quả mới phải hiện provenance `ollama`, requested/response model, output origin, wall latency, token metadata nếu Ollama cung cấp, thời điểm và SHA-256 phản hồi.
4. Trong **Dấu vết phân tích SOC**, kiểm `Sự kiện quan sát`, `Suy luận`, `Bất định`, `Giới hạn`, confidence dạng phần trăm `0-100`, ngôn ngữ yêu cầu/phản hồi, language compliance và prompt version. Đây là evidence/decision summary có thể audit, **không phải** chain-of-thought hoặc suy luận nội bộ model. Job lịch sử không có contract mới phải hiện `unknown_legacy`/không ghi nhận thay vì tự suy diễn metadata.
5. Kiểm timeline: mỗi cột là một time bucket; chọn bằng click/keyboard phải lọc danh sách alert và hiện đúng khoảng/count. **Phân tích bucket này** phải tạo batch con cùng model/language.
6. Với job dưới cap, mở **Full alert**; document phải có `_index`, `_id`, `_source` lấy lại từ Indexer.
7. Với job vượt cap, xác minh badge `aggregate only`, exact total/timeline/rule buckets có dữ liệu, alert detail rỗng có giải thích và warning nói không tải full log.
8. Thử custom range trong quá khứ. Range không timezone, tương lai hoặc dài hơn 24 giờ phải bị từ chối.

**PASS khi:** job không cắt âm thầm; trên cap không fail chỉ vì volume và không bulk raw log. `partial` phải có coverage/fallback warning; aggregate-only phải ghi mode/coverage rõ dù status có thể `succeeded`.

Đổi **Giao diện** giữa `Tối/Sáng`, reload trang và xác minh lựa chọn được giữ; desktop/mobile không tràn ngang, text/badge/chart vẫn dễ đọc.

### 13.3 JSON export và kiểm chứng nguồn AI

1. Chọn một job rồi bấm **Xuất JSON v2**; browser phải tải `wazuh-ai-job-<id>.json` với MIME `application/json`. Nút **JSON v1 (tương thích)** chỉ dùng khi consumer cũ cần endpoint `?schema=v1`.
2. Kiểm `schema_version=local-ai-siem-report/v2`, `job`, `analysis`, `analysis_sha256`, `assessment_basis`, `audit`, `coverage`, `warnings`, `metrics`, `timeline`, `groups` và `alert_references`. `audit` phải có model/options, prompt version/hash, ngôn ngữ yêu cầu/phản hồi và language compliance.
3. Với job mới gọi model thành công, `audit.model.evidence_status` phải là `recorded`, `provider=ollama`, `output_origin=ollama_model`; nếu phản hồi sai schema và app sinh fallback thì origin phải là `local_fallback`.
4. Job lịch sử tạo trước schema v3 không có provenance phải ghi `unknown_legacy`, không được suy diễn rằng metadata cũ đã chứng minh một model call.
5. Export không được có credential, raw `_source`, `full_log` hoặc `sample_log`. Alert references dùng để đối chiếu/lấy lại document từ Indexer phía server.

Provenance là audit metadata do ứng dụng ghi ngay sau `ollama.Client.chat`, không phải chữ ký mật mã hoặc bằng chứng chất lượng semantic. Luôn human-review severity, MITRE và remediation trước khi dùng vận hành.

### 13.4 Fixed schedule và restart recovery

1. Bật schedule `5 phút`, chọn model và ngôn ngữ AI.
2. Sinh bounded traffic theo mục 5–7.
3. Chờ hết window cộng `ingest_delay_seconds` mặc định 120 giây.
4. Xác minh chỉ có một scheduled job cho cùng cửa sổ.
5. Tắt app vài cửa sổ, chạy lại và kiểm job chạy bù tuần tự; tối đa `max_catchup_windows` mặc định 24. Phần cũ hơn phải tăng `Coverage gaps`, không bỏ âm thầm.
6. Nếu schedule `blocked`, sửa dependency rồi dùng Retry; chỉ Skip khi chủ ý chấp nhận một gap.

Runtime state:

```text
ai_module/dashboard_data/dashboard.db
```

File này chứa metadata alert/job và AI result local, không chứa credential hoặc raw `_source`; đã gitignore. Không xóa DB khi cần giữ audit/history.

### 13.5 Failure/security checks

- Tắt Ollama: model/job API phải báo unavailable/failed, không treo vô hạn.
- Tắt Indexer: job phải failed/blocked với lỗi đã sanitize; không lộ password.
- Model ngoài allowlist, arbitrary index/query DSL và cross-origin mutation phải bị từ chối hoặc bỏ qua an toàn.
- Alert/AI text chứa HTML phải hiện như text; browser không thực thi.
- AI chỉ advisory; không có route auto-remediation.

### 13.6 Analyst triage và maintenance local

1. Dùng filter lịch sử theo status, language, analysis mode và review; reload trang để xác nhận filter được lưu local trong browser. Dùng **Lọc rule/agent** từ detail để pivot nhanh vào lịch sử.
2. Với một job, lưu case-lite review gồm status, severity override hoặc `inherit`, tags phân cách bằng dấu phẩy và note. Mở lại job để xác nhận latest review và review history được hiển thị. Review chỉ là metadata local, không làm thay đổi alert Wazuh hay chạy remediation.
3. Kiểm panel dependency/queue/database. Mất dependency phải hiển thị lỗi đã sanitize, không credential.
4. Khi retention disabled, nút prune phải bị khóa. Khi enabled, xác nhận dialog rồi mới gọi prune; chỉ dữ liệu quá retention bị xóa. Không dùng prune để xóa evidence đang cần điều tra.

Không đưa vào scope localhost: multi-user assignment/RBAC, notification ra ngoài, PCAP pipeline, threat-intelligence enrichment, graph correlation hoặc auto-remediation. Các pattern tham khảo: Wazuh Dashboard, Security Onion Alerts/Cases và OpenSearch Security Analytics (URL tại README).

Dừng app bằng `Ctrl+C`. Scheduler chỉ chạy khi process dashboard đang chạy.

## 14. Cleanup và kiểm tra cuối

**Máy chạy:** Host Windows
**Shell:** PowerShell

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" kali@192.168.100.30 "rm -f /tmp/ssh-bruteforce.sh /tmp/web-attack.sh"
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" trnguyn@192.168.100.20 "rm -f /tmp/fim-trigger.sh; sudo rm -f /opt/wazuh-fim-lab/manual-marker.txt"
Remove-Variable IndexerPassword,PlainIndexerPassword,BSTR -ErrorAction SilentlyContinue
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue

git status --short
git diff --check
```

Không xóa `/opt/wazuh-fim-lab/modified-marker.txt` nếu đang giữ làm bằng chứng baseline. Nếu xóa, dự kiến sinh rule `553`.

Không stage:

```text
.claude/
ai_module/config.yaml
ai_module/*.bak
ai_module/create_rag_data.py
```

## 15. Bảng ghi PASS/FAIL

| Phase | Evidence | PASS/FAIL/SKIP | Ghi chú |
|---|---|---|---|
| Host network/models | PowerShell output | | |
| SIEM Docker/ports/disk | compose/ss/df | | |
| Ubuntu agent/log/FIM | systemctl/grep | | |
| Kali tools/network | command/ping/curl | | |
| SSH rules | `5503/5760`, optional `2502` | | |
| Web rules | `31101/31151/31105` | | |
| FIM rules | `554/550`, cleanup `553` | | |
| Windows agent | WazuhSvc + Dashboard | | Sysmon riêng |
| AI demo/live | JSON output | | |
| Baseline | 33+33 rows | | |
| AI judge | 66 rows AI-only | | |
| Dashboard manual window | job/result/group/full alert | | |
| Dashboard schedule/recovery | unique window/catch-up/gap | | |
| Dashboard failure/security | timeout/allowlist/escaped text | | |
| Human grading | 66 scored outputs | | |
| Manual timing | 33 elapsed values | | |
| Cleanup/Git | status/diff | | |
