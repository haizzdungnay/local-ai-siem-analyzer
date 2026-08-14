# Prompt tiep tuc cong viec: kiem chung Security Test -> Wazuh -> AI local

Ban dang tiep tuc mot cong viec da duoc nguoi dung phe duyet trong repository
`C:\Users\Tplab\local-ai-siem-analyzer`. Khong yeu cau nguoi dung lap lai boi
canh. Hay doc file nay truoc, sau do doc day du `CLAUDE.md`, kiem tra
`git status --short`, va giu nguyen moi thay doi khong lien quan trong worktree
da rat ban. Khong reset, checkout, revert, hoac xoa cac thay doi cua nguoi dung.

## Muc tieu bat buoc

Hoan thien trang local `/security-tests` de moi kich ban DVWA allowlist chay
theo chuoi kiem chung tuan tu:

```text
Nguoi dung bam scenario
  -> script co dinh tren Kali .30 gui traffic toi DVWA .20
  -> cho Wazuh ingest trong gioi han
  -> doc cac alert da loc dung .30 -> .20 trong cua so thoi gian cua Kali
  -> chi khi co alert moi tao 1 job AI local
  -> hien thi evidence va ket qua AI tren chinh trang test
  -> moi cho phep chay kich ban tiep theo
```

Nguoi dung muon test tung kich ban va sau tung kich ban AI local phai doc bao
cao de kiem chung. Tuy nhien, verdict phat hien phai dua tren alert Wazuh that,
khong dua tren suy doan cua model. AI chi co vai tro tom tat/dien giai evidence
da sanitize. Khong duoc ghi `thanh cong` neu script chay xong ma khong co alert.

## Boi canh va hien trang chinh xac

- Lab co lap va da duoc phep: Kali co dinh `.30`, DVWA/Wazuh agent co dinh
  `.20`, Wazuh Indexer nam trong lab, dashboard chi listen loopback
  `127.0.0.1:8765`. Khong mo rong pham vi sang host, URL, tai khoan, hay target
  khac.
- Trang `/security-tests` da ton tai voi 18 scenario allowlist, confirmation
  dialog va terminal chi doc. Browser chi gui `scenario_id` va `confirm`; khong
  bao gio nhan command, target, URL, path script, payload, credential, hoac SSH
  key tu browser.
- `ai_module/security_test_runner.py` dang chay SSH serial tu host Windows sang
  Kali. Script/request da co cap: SSH connect 5 giay, curl 2 giay/request,
  script deadline 18 giay va Python hard timeout 20 giay.
- `scripts/attacks/dvwa-module-test.sh` in dong ket thuc dang:
  `SCENARIO=... TARGET=... END_UTC=YYYY-MM-DDTHH:MM:SSZ`. Phai parse timestamp
  nay; khong dung `started_at`/`finished_at` cua dashboard de correlation.
- `ai_module/dashboard.py` hien chi goi `security_test_runner.start()` tai
  `POST /api/security-tests/runs`. Runner hien chi luu run trong memory va ket
  thuc sau SSH. Day la nguyen nhan truc tiep AI/web chua nhan duoc alert.
- Pipeline dashboard binh thuong da co san: `DashboardStore` tao job,
  `DashboardRuntime` trong `ai_module/dashboard_worker.py` lay alert bang
  `fetch_alerts_window()`, aggregate, goi `AnalysisService.analyze_aggregate()`,
  va luu report AI. Uu tien tai su dung pipeline nay thay vi viet mot LLM flow
  thu hai.
- `ai_module/reader.py:fetch_alerts_window()` va `fetch_alerts_range()` hien
  chi loc theo thoi gian. Can bo sung filter noi bo cho `data.srcip=.30` va
  `agent.ip=.20` o ca aggregate query va detail query, de tranh AI doc alert
  khong lien quan. Browser/API public khong duoc truyen filter tu do.
- Kali/Victim/Wazuh cham hon host dashboard khoang 65 giay. Da co alert that
  tren Indexer voi source `.30`, agent `.20`, cac rule `31104` (traversal),
  `31105` (XSS-shaped), va `31101` (API 404), nhung full smoke 18 scenario
  truoc do khong the gan tung alert vi chua co correlation theo clock Kali.
- Mot dashboard job truoc do da doc duoc alert `31105` tu Wazuh, nhung
  `CyberCrew/notmythos-8b:latest` tra fallback `unknown`. Dung
  `qwen2.5:7b` co dinh cho security-test analysis; model nay da nam trong
  allowlist local va la lua chon tot hon trong lab. Khong dung CyberCrew lam
  fallback tu dong cho flow nay.
- Khong dua credential, private-key path, full raw log, cookie, token, password,
  payload day du, hay endpoint nhay cam vao source tracked, terminal web, AI
  prompt, changelog, hay handoff.

## Yeu cau gioi han thoi gian va suy luan

Nguoi dung da yeu cau tranh treo va tranh dot token vo nghia. Day la contract
bat buoc, khong phai goi y:

| Buoc | Gioi han |
| --- | --- |
| Script attack | giu cap hien co: toi da 20 giay |
| Cho Wazuh ingest | toi da 12-15 giay, polling doc-only co gioi han |
| Moi Indexer request | timeout ngan, khong vuot qua 5 giay |
| AI local | chi 1 lan goi, `qwen2.5:7b`, temperature 0, toi da 512 token, timeout toi da 45 giay |
| Retry attack/AI | cam; chi duoc retry query trang thai/doc-only trong cap ingest |
| Toan bo mot scenario | muc tieu <= 90 giay; khi het cap phai ket thuc minh bach |

Khong dung chain-of-thought, multi-agent reasoning, prompt lap lai, multi-model
voting, hay retry model de co duoc cau tra loi dep. Prompt AI phai ngan va chi
chua aggregate/evidence da sanitize. Khi AI timeout, sai schema, hay `unknown`,
giu evidence Wazuh va danh dau `analysis_failed` hoac `partial`; khong thu lai.

## Thiet ke can trien khai

### 1. Correlation an toan va serial

1. Sau khi SSH script exit `0`, parse `END_UTC` tu output an toan cua Kali va
   luu `attack_end_utc` vao run. Neu khong parse duoc, danh dau correlation
   failed va khong tao AI job.
2. Dung cua so UTC cua Kali, vi du `start = attack_end_utc - 30s`,
   `end = attack_end_utc + 10s`. Neu can, clamp `end` khong vuot qua host UTC
   hien tai de reader khong reject future time. Khong thay bang timestamp cua
   browser/dashboard.
3. Trong thoi gian ingest wait, query Wazuh theo `timestamp` + fixed
   `data.srcip=192.168.100.30` + fixed `agent.ip=192.168.100.20`. Neu chua co
   alert thi retry query doc-only theo interval ngan den het cap; khong rerun
   attack.
4. Giu security runner o trang thai active cho den khi correlation va AI job
   terminal. Khong cho hai script co the dung chung source/target/correlation
   window chay song song.
5. Neu script failed/timed out, khong query/phan tich alert cu. Ket thuc run
   voi loi script ro rang.

### 2. Tai su dung job AI dashboard

Uu tien tao mot job dashboard noi bo sau khi da co Wazuh evidence, thay vi goi
LLM truc tiep tu browser. Job nay can mang metadata/correlation an toan de
worker dung dung cua so va filters. Cach lam duoc khuyen nghi:

- Them metadata JSON/column migration nhe cho job (vi du `correlation_json`)
  neu can luu `security_test_run_id`, scenario, fixed source/agent filter va
  attack window. Tang schema version va viet migration khong lam mat history.
- `DashboardStore.create_job()` chi nhan correlation/filter tu internal
  coordinator. `POST /api/jobs` cong khai van khong duoc nhan arbitrary filter
  hay arbitrary model/command.
- `DashboardRuntime._run_job()` chuyen filters da duoc validate vao ca
  `fetch_alerts_window()` va detail fetch. Duy tri contract cu cho manual va
  scheduled job khong co filters.
- Security-test job dung `qwen2.5:7b`, language `vi`, `delivery_channel=none`,
  va LLM parameters deterministic: temperature 0, top_p 1, max_tokens 512.
  Them per-job/per-security-test analysis timeout da cap neu can, thay vi de
  timeout chung 120 giay cua Ollama vuot contract.
- Khong tao AI job khi Wazuh alert count bang 0. Day la cach tiet kiem token va
  bao dung su that: `script_succeeded_no_matching_wazuh_alert`.

Neu phai chon giua mo rong persistence va mot callback trong memory, uu tien
persistence cua job/evidence de trang test co the xem job/report sau restart.
Tuy nhien, khong viet raw alert/source vao SQLite ngoai contract hien co; chi
luu reference, aggregate da sanitize va metadata an toan.

### 3. Run state va API/UI contract

Mo rong DTO cua security run bang cac truong public, bounded va da sanitize:

```text
phase: running_script | waiting_ingest | querying_wazuh | queued_ai |
       analyzing_ai | completed | no_alert | analysis_failed | failed | timed_out
attack_end_utc
analysis_window_start, analysis_window_end
wazuh_alert_count, wazuh_rule_ids
ai_job_id, ai_status, ai_severity, ai_summary, ai_error
verdict: detected | no_matching_alert | analysis_partial | analysis_failed |
         script_failed
```

Chi them truong khi co gia tri; error phai la thong diep an toan, khong co URL,
credential, traceback, raw request, hay raw alert. `status` cua script va
`verdict` cua detection phai tach biet.

Cap nhat `ai_module/web/test.html` va `ai_module/web/test.js` de:

- Hien thi phase dung (script -> Wazuh -> AI), khong dung thong diep cu bao
  nguoi dung phai tu mo dashboard de doc alert.
- Hien thi alert count/rule IDs, cua so UTC dung de correlation, job ID AI,
  severity/summary AI da sanitize, va link/nut mo dashboard job neu kha dung.
- Giu terminal chi doc: command SSH da an key path, transcript output, va
  script preview. Khong them o nhap command.
- Poll den terminal cua ca run, khong dung polling vo han. Khi network/polling
  loi, hien thi data co the cu va khong tu dong chay lai scenario.
- Hien thi ro: `script da chay nhung chua co Wazuh alert trong cua so` khac voi
  `AI loi sau khi Wazuh da ghi nhan alert`.

### 4. Config hop le

Neu can them config duoc doc tu `security_tests`, chi them cac khoa an toan nhu:

```yaml
analysis_model: qwen2.5:7b
ingest_wait_seconds: 12
ingest_poll_seconds: 2
indexer_timeout_seconds: 5
analysis_timeout_seconds: 45
analysis_max_tokens: 512
```

Cap nhat `_security_tests_cfg()` de allowlist va validate type/range. Gia tri
model phai nam trong `dashboard.allowed_models`, va model fallback tu dong bi
cam. Cap nhat `ai_module/config.example.yaml`, nhung khong sua/print secret
trong `ai_module/config.yaml`.

## Thu tu live test sau khi code va test tu dong pass

Nguoi dung da phe duyet chay traffic trong lab nay. Chay **mot scenario moi
lan**, doi run terminal, doc report AI, ghi ket qua, roi moi chay scenario ke
tiep. Khong chay lai full 18-card smoke va khong scan volume lon.

Uu tien theo kha nang co telemetry da biet:

1. `file-inclusion` - ky vong Wazuh rule `31104` (traversal-shaped).
2. `xss-reflected` - ky vong Wazuh rule `31105` (XSS-shaped).
3. `api` - ky vong Wazuh rule `31101` (API/web 404-shaped).
4. `csp-bypass` hoac scenario XSS co contract rule ro rang tiep theo.

Voi moi run, ghi bang ket qua ngan trong `HANDOFF.md` hoac evidence note:

```text
scenario | script status/exit | attack_end_utc | Wazuh count/rules |
AI job/status/model | AI summary/severity | verdict | time spent
```

Khong dua ra ket luan exploit da thanh cong. Cac ket luan hop le chi la:

- `detected`: script da xong, co alert Wazuh matching fixed filters/window, va
  AI report da duoc luu (AI co the partial nhung evidence van ton tai).
- `no_matching_alert`: script da xong nhung khong co alert trong cua so bounded.
- `analysis_failed`/`analysis_partial`: Wazuh co evidence, nhung AI timeout,
  fallback unknown, sai schema, hay khong du bao cao; khong rerun AI.
- `script_failed`: script SSH/curl/timebox that bai; khong dung alert cu de claim.

Neu scenario khong co expected Wazuh rule/telemetry contract, danh dau can
`needs_telemetry_contract`, khong tu suy dien va khong dot token de thu lai.

## Kiem thu bat buoc truoc live lab

Them/cap nhat regression tests cho it nhat cac truong hop sau:

- Runner parse dung `END_UTC`, giu serial lock qua follow-up, va khong follow-up
  khi SSH failed/timed out.
- Reader build bool filter co timestamp + `data.srcip` + `agent.ip` o ca
  aggregate va detail query; manual dashboard query khong thay doi contract.
- Security API van reject field la, target/command/payload/filter tu browser.
- No alert khong tao/gioi thieu AI job; alert matching tao mot job voi
  `qwen2.5:7b` va bounded LLM params; AI failure hien thi `analysis_failed`.
- Clock skew va UTC boundary: correlation dung `END_UTC` remote, khong lay
  `started_at` host; end future duoc xu ly fail-closed/clamp an toan.
- UI co cac phase/evidence/AI fields moi, khong co terminal input, va khong
  tuyen bo detection khi khong co alert.

Chay it nhat:

```powershell
python -m compileall ai_module
python -m pytest -q tests/test_security_test_runner.py tests/test_dashboard_core.py tests/test_dashboard_api.py tests/test_dashboard_store_worker.py tests/test_dashboard_ui.py
node --check ai_module/web/test.js
git diff --check
```

Sau do chay full `pytest -q` neu thoi gian cho phep. Chi bat dau live scenario
sau khi cac check lien quan pass. Khong chay test live song song voi scheduler,
migration, restore, hoac mot security run khac.

## Quy tac lam viec va definition of done

- Dung `apply_patch` cho edit thuong; khong dung destructive git command.
- Khong tu y doi model, port, target, hay mo egress. Khong dung Nikto hoac scan
  volume lon trong flow nay.
- Giu text/file UTF-8 dung, khong lam hong tieng Viet trong UI/docs.
- Sau moi ket qua repo hoan thanh, cap nhat `CHANGELOG.md` truoc, roi cap nhat
  `HANDOFF.md` dung yeu cau trong `CLAUDE.md`. Ghi ro verification va known
  limitation; khong ghi credential hay identifier nhay cam.
- Hoan thanh khi: click mot card tao full chain tu script toi Wazuh toi AI local;
  UI phan biet dung cac failure mode; co it nhat mot scenario uu tien da duoc
  kiem chung live tung buoc va report AI doc duoc; regression checks pass; cac
  scenario khac chi duoc chay lan luot theo dung procedure tren.

Bat dau bang viec kiem tra code hien tai va implement correlation/job contract;
khong hoi nguoi dung lap lai boi canh hoac xin phep cho cac buoc lab da neu o
tren. Neu bi chan boi config/lab dependency khong an toan, bao cao blocker cu
the kem evidence thay vi mo rong pham vi hoac retry vo han.
