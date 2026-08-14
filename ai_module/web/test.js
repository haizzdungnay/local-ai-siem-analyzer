const $ = id => document.getElementById(id);
const state = {catalog: null, activeRunId: null, selectedScenario: null, selectedModel: null, pollTimer: null, pollDeadline: 0};
const TERMINAL_PHASES = new Set(['completed', 'no_alert', 'analysis_failed', 'failed', 'timed_out']);
const PHASE_LABELS = {
  queued: 'Dang cho', running_script: 'Dang chay script', waiting_ingest: 'Cho Wazuh ingest',
  querying_wazuh: 'Dang truy van Wazuh', queued_ai: 'Da xep hang AI', analyzing_ai: 'Dang phan tich AI',
  completed: 'Hoan tat', no_alert: 'Het cap ingest, chua thay alert', analysis_failed: 'AI phan tich loi',
  failed: 'Script loi', timed_out: 'Het thoi gian'
};
const MODEL_DETAILS = {'cybercrew/notmythos-8b:latest': '8B Q4_K_M'};

function setText(node, value) { node.textContent = String(value ?? ''); }
async function api(path, options = {}) {
  const response = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...options});
  let body = {};
  try { body = await response.json(); } catch (_) { /* status fallback */ }
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}
function statusLabel(value) { return PHASE_LABELS[value] || value || 'unknown'; }
function modelLabel(model) {
  const detail = MODEL_DETAILS[String(model || '').toLocaleLowerCase()];
  return detail ? `${model} · ${detail}` : String(model || '');
}
function selectedModel() { return $('security-test-model').value; }
function renderModels(data) {
  const select = $('security-test-model');
  const previous = select.value;
  select.replaceChildren();
  const models = Array.isArray(data.allowed_models) ? data.allowed_models : [];
  models.forEach(model => {
    const option = document.createElement('option');
    option.value = model; setText(option, modelLabel(model)); select.append(option);
  });
  const preferred = models.includes(previous) ? previous : data.default_model;
  if (models.includes(preferred)) select.value = preferred;
  select.disabled = !data.enabled || Boolean(data.active_run) || models.length === 0;
}
function scenarioReason(scenario) {
  return scenario?.disabled_reason || 'Kich ban nay hien chua du dieu kien de chay.';
}
function scenarioDisplay(scenario) {
  if (scenario?.id === 'brute-force') {
    return {
      title: 'Brute Force (DVWA login)',
      description: 'Gui dung 300 POST voi credential lab khong hop le toi endpoint DVWA co dinh; luong lab-only bounded, chi xac nhan request da gui, khong xac nhan auth failure hay compromise.',
    };
  }
  return {title: scenario?.title || '', description: scenario?.description || ''};
}
function setConfirmError(message = '') {
  const node = $('security-test-confirm-error');
  setText(node, message);
  node.classList.toggle('hidden', !message);
  if (message) node.focus();
}
function findScenario(catalog, scenarioId) {
  return catalog?.scenarios?.find(item => item.id === scenarioId) || null;
}
function renderDetail(target, fields) {
  const root = $(target); root.replaceChildren();
  for (const [key, value] of Object.entries(fields)) {
    const dt = document.createElement('dt'); const dd = document.createElement('dd');
    setText(dt, key); setText(dd, value ?? '-'); root.append(dt, dd);
  }
}
function renderTerminal(run) {
  setText($('security-test-terminal-command'), `$ ${run.terminal_command || 'Dang tao lenh allowlist...'}`);
  setText($('security-test-terminal-state'), statusLabel(run.phase || run.status));
  const transcript = [];
  if (run.phase === 'queued') transcript.push('# Dang cho runner nhan luot chay.');
  else if (run.phase === 'running_script') transcript.push('# SSH dang chay; output se xuat hien khi lenh ket thuc.');
  else transcript.push(`# Run dang o phase: ${statusLabel(run.phase || run.status)}.`);
  if (run.output) transcript.push(run.output.trimEnd());
  if (run.error) transcript.push(`ERROR: ${run.error}`);
  setText($('security-test-terminal-output'), transcript.join('\n'));
  setText($('security-test-script-preview'), run.script_preview || '# Script preview khong kha dung.');
}
function renderEvidence(run) {
  const rules = Array.isArray(run.wazuh_rule_ids) ? run.wazuh_rule_ids.join(', ') : '-';
  renderDetail('security-test-evidence-detail', {
    'Cua so UTC': run.analysis_window_start && run.analysis_window_end ? `${run.analysis_window_start} -> ${run.analysis_window_end}` : '-',
    'Wazuh alert count': run.wazuh_alert_count ?? '-', 'Wazuh rule IDs': rules,
    'AI job ID': run.ai_job_id ?? '-', 'AI status': run.ai_status || '-',
    'AI severity': run.ai_severity || '-', 'AI summary': run.ai_summary || '-', 'AI error': run.ai_error || '-'
  });
  setText($('security-test-verdict'), run.verdict ? `Verdict: ${run.verdict}` : '');
  const link = $('security-test-job-link');
  if (run.ai_job_id != null) { link.href = `/?job=${encodeURIComponent(run.ai_job_id)}`; link.classList.remove('hidden'); }
  else link.classList.add('hidden');
}
function renderCatalog(data) {
  state.catalog = data;
  renderModels(data);
  renderDetail('security-test-lab', {'Runner': data.enabled ? 'San sang' : 'Dang khoa', 'Nguon Kali': data.source_ip, 'Target DVWA': data.target_ip, 'Model mac dinh': modelLabel(data.default_model), 'Ly do': data.reason || 'Chi nhan scenario va model AI allowlist.'});
  const enabledCount = data.scenarios.filter(scenario => scenario.enabled).length;
  setText($('security-test-catalog-count'), `${enabledCount}/${data.scenarios.length} kich ban da xac minh telemetry`);
  const root = $('security-test-cards'); root.replaceChildren();
  data.scenarios.forEach(scenario => {
    const display = scenarioDisplay(scenario);
    const card = document.createElement('article'); card.className = `card security-test-card${scenario.enabled ? '' : ' is-disabled'}`;
    const category = document.createElement('p'); category.className = 'eyebrow'; setText(category, scenario.category);
    const title = document.createElement('h3'); setText(title, display.title);
    const description = document.createElement('p'); description.className = 'muted'; setText(description, display.description);
    const rules = Array.isArray(scenario.expected_rule_ids) && scenario.expected_rule_ids.length ? scenario.expected_rule_ids.join(', ') : '-';
    const metadata = document.createElement('p'); metadata.className = 'security-test-meta'; setText(metadata, `Timeout: ${scenario.timeout_seconds}s · Wazuh rules: ${rules}`);
    const availability = document.createElement('p'); availability.className = `security-test-availability ${scenario.enabled ? 'is-ready' : 'is-blocked'}`;
    setText(availability, scenario.enabled ? 'San sang chay' : `Chua kha dung: ${scenarioReason(scenario)}`);
    const button = document.createElement('button'); button.type = 'button'; button.dataset.scenarioId = scenario.id;
    setText(button, scenario.enabled ? 'Chay test' : 'Chua kha dung'); button.disabled = !scenario.enabled;
    if (!scenario.enabled) button.title = scenarioReason(scenario);
    button.addEventListener('click', () => openConfirm(scenario)); card.append(category, title, description, metadata, availability, button); root.append(card);
  });
}
async function loadCatalog() {
  try {
    const data = await api('/api/security-tests/catalog', {cache: 'no-store'});
    renderCatalog(data);
    return data;
  } catch (error) {
    setText($('security-test-message'), `Khong tai duoc catalog: ${error.message}`);
    return null;
  }
}
async function openConfirm(scenario) {
  setConfirmError();
  if (!scenario?.enabled) {
    setText($('security-test-message'), scenarioReason(scenario));
    return;
  }
  setText($('security-test-message'), 'Dang xac minh lai trang thai scenario...');
  try {
    const catalog = await api('/api/security-tests/catalog', {cache: 'no-store'});
    renderCatalog(catalog);
    const current = findScenario(catalog, scenario.id);
    if (!current?.enabled) {
      state.selectedScenario = null;
      setText($('security-test-message'), scenarioReason(current));
      return;
    }
    if (!selectedModel()) {
      setText($('security-test-message'), 'Khong co model AI local kha dung cho security test.');
      return;
    }
    state.selectedScenario = current;
    state.selectedModel = selectedModel();
    $('security-test-model').disabled = true;
    const display = scenarioDisplay(current); setText($('security-test-confirm-title'), `Chay ${display.title}`);
    const requestNote = current.id === 'brute-force'
      ? 'Script lab-only bounded se gui dung 300 POST login voi credential khong hop le; khong xac nhan auth failure hay compromise.'
      : `Script bounded se chay tu Kali .30 den DVWA .20, toi da ${current.timeout_seconds} giay.`;
    setText($('security-test-confirm-copy'), requestNote);
    setText($('security-test-confirm-model'), `AI se phan tich bang: ${modelLabel(state.selectedModel)}`);
    setText($('security-test-message'), '');
    $('security-test-confirm').showModal();
  } catch (error) {
    setText($('security-test-message'), `Khong xac minh duoc scenario: ${error.message}`);
  }
}
async function startSelectedScenario() {
  const scenario = state.selectedScenario; if (!scenario) return;
  const chosenModel = state.selectedModel;
  const button = $('security-test-confirm-run'); button.disabled = true; setText(button, 'Dang xac minh...'); setConfirmError();
  try {
    const previousModel = chosenModel;
    const catalog = await api('/api/security-tests/catalog', {cache: 'no-store'});
    renderCatalog(catalog);
    $('security-test-model').disabled = true;
    const current = findScenario(catalog, scenario.id);
    if (!current?.enabled) throw new Error(scenarioReason(current));
    if (!catalog.allowed_models.includes(previousModel)) {
      throw new Error('Model AI da chon khong con duoc cai dat hoac nam trong allowlist. Hay dong hop thoai va chon lai.');
    }
    const model = previousModel;
    state.selectedScenario = current; setText(button, 'Dang tao luot chay...');
    const data = await api('/api/security-tests/runs', {method: 'POST', cache: 'no-store', body: JSON.stringify({scenario_id: current.id, model, confirm: true})});
    $('security-test-confirm').close(); state.selectedScenario = null; state.selectedModel = null; state.activeRunId = data.run.id; showRun(data.run); await loadCatalog(); schedulePoll();
  } catch (error) {
    const message = `Khong the bat dau script: ${error.message}`;
    setConfirmError(message); setText($('security-test-message'), message);
    await loadCatalog();
    $('security-test-model').disabled = true;
  }
  finally { button.disabled = false; setText(button, 'Chay script'); }
}
function showRun(run) {
  $('security-test-active').classList.remove('hidden'); setText($('security-test-active-title'), run.title);
  setText($('security-test-active-status'), statusLabel(run.phase || run.status));
  renderDetail('security-test-active-detail', {'Scenario': run.scenario_id, 'Model AI': modelLabel(run.analysis_model), 'Phase': statusLabel(run.phase || run.status), 'Nguon': run.source_ip, 'Target': run.target_ip, 'Bat dau UTC': run.started_at, 'Ket thuc UTC': run.finished_at, 'Exit code': run.exit_code, 'Loi': run.error});
  renderTerminal(run); renderEvidence(run); setText($('security-test-output'), run.output || 'Chua co output.');
  if (TERMINAL_PHASES.has(run.phase || run.status)) {
    clearInterval(state.pollTimer); state.pollTimer = null;
    const noAlert = run.phase === 'no_alert' || run.verdict === 'no_matching_alert';
    setText($('security-test-message'), noAlert ? 'Script da chay; khong thay Wazuh alert matching truoc khi het cap ingest cho cua so bounded. Alert den tre co the nam trong Indexer nhung khong duoc dung hoi to de tao AI job.' : run.verdict === 'detected' ? 'Wazuh da ghi nhan alert matching; AI report da duoc luu.' : `Run ket thuc: ${run.error || run.verdict || statusLabel(run.phase)}.`);
    loadCatalog();
  }
}
async function pollRun() {
  if (!state.activeRunId) return;
  if (Date.now() >= state.pollDeadline) { clearInterval(state.pollTimer); state.pollTimer = null; setText($('security-test-message'), 'Da dung polling sau cap an toan; khong tu dong chay lai scenario.'); return; }
  try { showRun((await api(`/api/security-tests/runs/${state.activeRunId}`)).run); }
  catch (error) { setText($('security-test-message'), `Khong lay duoc trang thai: ${error.message}`); }
}
function schedulePoll() { clearInterval(state.pollTimer); state.pollDeadline = Date.now() + 90000; state.pollTimer = setInterval(pollRun, 1500); pollRun(); }
$('security-test-refresh').addEventListener('click', loadCatalog);
function closeConfirm() {
  setConfirmError(); state.selectedScenario = null; state.selectedModel = null;
  $('security-test-confirm').close();
  renderCatalog(state.catalog);
}
$('security-test-confirm-close').addEventListener('click', closeConfirm);
$('security-test-confirm-run').addEventListener('click', startSelectedScenario);
$('security-test-confirm').addEventListener('cancel', event => { event.preventDefault(); closeConfirm(); });
loadCatalog();
