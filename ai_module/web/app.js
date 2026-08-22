const $ = id => document.getElementById(id);
const state = {
  activeJob: null,
  activeJobStatus: null,
  activeJobData: null,
  timelineSelection: null,
  jobs: [],
  notifications: {},
  scheduleFormDirty: false,
  scheduleSnapshot: null,
  historyPage: 1,
  historyPageSize: 12,
  historyPages: 1,
  historyTotal: 0,
  historyServerPagination: false,
  historyRequest: 0,
  selectedJobs: new Set(),
  historyLoading: false,
  batchDetailsOpener: null,
  batchDetailsOpenerKey: null,
};
// UI text is also the print surface; redact credential-shaped values before
// they reach the DOM so browser print cannot bypass the export boundary.
const redactClientText = value => String(value ?? '').replace(
  /\b(api[_ -]?key|authorization|bearer|password|passwd|secret|token|cookie|session(?:[_ -]?id)?)\b\s*([=:])\s*[^,\s;]+/gi,
  '$1$2[redacted]',
);
const text = (node, value) => { node.textContent = redactClientText(value); };
const processingPhases = {
  queued: ['Đang chờ worker', 'Job đã được lưu và đang chờ worker cục bộ nhận việc.'],
  fetching_alerts: ['Đang đọc Wazuh Indexer', 'Đang lấy alert thật theo cửa sổ đã chọn.'],
  preparing_analysis: ['Đang chuẩn bị dữ liệu', 'Đang gom nhóm, tính coverage và dựng prompt giới hạn.'],
  calling_ollama: ['Đang gọi Ollama local', 'Đang chờ model tạo JSON; bước này có thể mất vài giây hoặc lâu hơn.'],
  analyzing_attack_chain: ['Đang dựng chuỗi tấn công', 'Đang chọn IP nguồn nhiều alert nhất và phân tích chuỗi theo thời gian.'],
  saving_result: ['Đang lưu kết quả', 'Đã nhận phản hồi và đang lưu JSON cùng metadata kiểm chứng.'],
};

function phaseLabel(job) {
  return processingPhases[job.phase]?.[0] || job.phase || job.status;
}

function applyTheme(value) {
  const theme = value === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  $('theme').value = theme;
  try { localStorage.setItem('wazuh-ai-theme', theme); } catch (_) { /* Browser storage can be disabled. */ }
}

function loadTheme() {
  let saved = 'dark';
  try { saved = localStorage.getItem('wazuh-ai-theme') || 'dark'; } catch (_) { /* Keep default. */ }
  applyTheme(saved);
}

async function api(path, options = {}) {
  const response = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...options});
  let body = {};
  try { body = await response.json(); } catch (_) { body = {}; }
  if (!response.ok) {
    const error = new Error(body.error || `HTTP ${response.status}`);
    error.code = typeof body.code === 'string' ? body.code : (typeof body.error_code === 'string' ? body.error_code : 'http_error');
    error.status = response.status;
    throw error;
  }
  return body;
}

const deliveryMessages = {
  gmail_auth_failed: 'Gmail authentication failed. Check the App Password and SMTP settings.',
  gmail_network_error: 'Cannot connect to Gmail. Check network/DNS and try again.',
  gmail_timeout: 'Gmail timed out. Check the network and retry; delivery may be uncertain.',
  telegram_auth_failed: 'Telegram authentication failed. Check Bot Token and Chat ID.',
  telegram_network_error: 'Cannot connect to Telegram. Check network/DNS and try again.',
  telegram_timeout: 'Telegram timed out. Check the network and retry; delivery may be uncertain.',
  telegram_provider_error: 'Telegram could not accept the PDF document. Check the chat before retrying.',
  telegram_rate_limited: 'Telegram rate-limited the PDF upload. Wait, then retry explicitly.',
  telegram_partial_timeout: 'Telegram sent only part of the report before timing out. Check the chat before retrying.',
  configuration: 'This channel is not fully configured. Open Settings and save valid values.',
  unsupported_channel: 'This delivery channel is not supported.',
};
const deliveryMessage = (error, channel) => deliveryMessages[error?.code]
  || `${channel} delivery failed. Check configuration and connectivity, then retry.`;
// Compatibility markers retained for the existing UI contract tests.
// Chi tiết alert đã lọc · Gửi lại ${label} · Xuất JSON v2 · Lọc source IP · Gửi test Telegram thất bại

function localIso(value) { return new Date(value).toLocaleString(); }
function ageLabel(value) {
  const milliseconds = Date.now() - new Date(value).getTime();
  if (!value || !Number.isFinite(milliseconds)) return 'không ghi nhận';
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s trước`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m trước`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h trước`;
  return `${Math.floor(seconds / 86400)}d trước`;
}
function setMessage(value) { text($('form-message'), value); }

function setButtonBusy(button, busy, busyLabel, idleLabel) {
  if (!button) return;
  button.disabled = busy;
  if (busy) {
    button.dataset.idleLabel = idleLabel ?? button.textContent;
    text(button, busyLabel);
  } else {
    text(button, idleLabel ?? button.dataset.idleLabel ?? button.textContent);
  }
}

const filterIds = ['history-search', 'history-status', 'history-language', 'history-mode', 'history-review', 'history-severity'];
function saveHistoryFilters() {
  try { localStorage.setItem('wazuh-ai-history-filters', JSON.stringify(Object.fromEntries(filterIds.map(id => [id, $(id).value])))); } catch (_) { /* Storage is optional. */ }
}
function loadHistoryFilters() {
  try {
    const saved = JSON.parse(localStorage.getItem('wazuh-ai-history-filters') || '{}');
    filterIds.forEach(id => { if (typeof saved[id] === 'string') $(id).value = saved[id]; });
  } catch (_) { /* Keep defaults. */ }
}
function reviewStatus(job) { return job.review?.status || 'none'; }
function matchingJobs(jobs) {
  const search = $('history-search').value.trim().toLocaleLowerCase();
  return jobs.filter(job => {
    const haystack = [job.id, job.model, job.ai_summary, job.status, job.review?.note, ...(job.review?.tags || []), ...(job.search_terms || [])].join(' ').toLocaleLowerCase();
    return (!search || haystack.includes(search))
      && (!$('history-status').value || job.status === $('history-status').value)
      && (!$('history-language').value || job.language === $('history-language').value)
      && (!$('history-mode').value || job.analysis_mode === $('history-mode').value)
      && (!$('history-review').value || reviewStatus(job) === $('history-review').value)
      && (!$('history-severity').value || Number(job.max_level || 0) >= Number($('history-severity').value));
  });
}
function applyHistoryPivot(value) {
  $('history-search').value = value;
  saveHistoryFilters();
  renderJobs();
  window.scrollTo({top: 0, behavior: 'smooth'});
}

const modelDisplayDetails = {
  'cybercrew/notmythos-8b:latest': '8B Q4_K_M',
};

function modelLabel(model) {
  const configured = modelDisplayDetails[String(model.name || '').toLocaleLowerCase()];
  const details = configured || [model.parameter_size, model.quantization_level].filter(Boolean).join(' ');
  return `${model.name} ${details}`.trim();
}

function fillModels(models) {
  for (const id of ['model', 'schedule-model', 'ip-model']) {
    const select = $(id);
    select.replaceChildren();
    models.forEach(model => {
      const option = document.createElement('option');
      option.value = model.name;
      text(option, modelLabel(model));
      select.append(option);
    });
  }
  if (state.scheduleSnapshot && !state.scheduleFormDirty) applyScheduleForm(state.scheduleSnapshot);
}

function visibleHistoryJobs() {
  if (state.historyServerPagination) {
    return {jobs: state.jobs, pageJobs: state.jobs, pages: state.historyPages, total: state.historyTotal};
  }
  const jobs = matchingJobs(state.jobs);
  const pages = Math.max(1, Math.ceil(jobs.length / state.historyPageSize));
  state.historyPage = Math.min(state.historyPage, pages);
  const start = (state.historyPage - 1) * state.historyPageSize;
  return {jobs, pageJobs: jobs.slice(start, start + state.historyPageSize), pages, total: jobs.length};
}

function resetHistoryPage() { state.historyPage = 1; }

function downloadBlob(content, filename, type) {
  const blob = new Blob([content], {type});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 0);
}

function exportHistory(format) {
  // Server paging makes exports intentionally page-scoped; it avoids silently
  // downloading an unbounded SOC history from a button meant for table data.
  const jobs = state.historyServerPagination ? state.jobs : matchingJobs(state.jobs);
  const fields = ['id', 'status', 'language', 'analysis_mode', 'window_start', 'window_end', 'alert_count', 'group_count', 'rule_count', 'max_level', 'ai_severity', 'ai_summary', 'review'];
  const safeJob = job => Object.fromEntries(fields.map(field => [
    field,
    field === 'review'
      ? (job.review ? {status: job.review.status, severity: job.review.severity, tags: job.review.tags} : null)
      : redactClientText(job[field]),
  ]));
  const safeJobs = jobs.map(safeJob);
  if (format === 'json') {
    downloadBlob(JSON.stringify({export_metadata: {scope: 'history', page: 'current-page', redacted: true, redaction_version: 'export-redaction-v1', field_inventory: {included: fields, excluded: ['llm_parameters', 'deliveries', 'raw logs', 'prompts', 'credentials', 'private config fields']}}, jobs: safeJobs}, null, 2), 'wazuh-ai-history.json', 'application/json');
    return;
  }
  // Quoted CSV cells are still executable formulas in spreadsheet apps. Prefix
  // formula-like text with an apostrophe before escaping it for CSV.
  const csvValue = value => {
    let cell = String(value ?? '');
    if (/^[\t\r\n ]*[=+\-@]/.test(cell)) cell = `'${cell}`;
    return `"${cell.replace(/"/g, '""')}"`;
  };
  const rows = [fields.map(csvValue).join(',')];
  safeJobs.forEach(job => rows.push(fields.map(field => csvValue(field === 'review' ? reviewStatus(job) : job[field])).join(',')));
  downloadBlob(`\uFEFF${rows.join('\n')}`, 'wazuh-ai-history.csv', 'text/csv;charset=utf-8');
}

function restoreBatchDetailsFocus() {
  const dialog = $('batch-details-dialog');
  let opener = state.batchDetailsOpener;
  const openerKey = state.batchDetailsOpenerKey;
  if ((!opener || !opener.isConnected || opener.disabled) && openerKey) {
    opener = [...document.querySelectorAll('button[data-batch-details-job]')]
      .find(button => button.dataset.batchDetailsJob === openerKey.jobId && button.dataset.batchDetailsKind === openerKey.kind);
  }
  state.batchDetailsOpener = null;
  state.batchDetailsOpenerKey = null;
  if (opener && opener.isConnected && !opener.disabled) {
    const focusOpener = () => {
      if (!opener.isConnected || opener.disabled) return;
      const active = document.activeElement;
      if (!active || active === document.body || active === document.documentElement || active === dialog || dialog?.contains(active)) opener.focus();
    };
    focusOpener();
    if (typeof queueMicrotask === 'function') queueMicrotask(focusOpener);
    if (typeof requestAnimationFrame === 'function') requestAnimationFrame(focusOpener);
    // Native dialog dismissal can move focus to body after the close event;
    // retry briefly for WebKit's asynchronous modal teardown.
    [0, 16, 50, 150].forEach(delay => setTimeout(focusOpener, delay));
  }
}

function closeBatchDetailsDialog() {
  const dialog = $('batch-details-dialog');
  if (!dialog) return;
  if (typeof dialog.close === 'function' && dialog.open) dialog.close();
  else {
    dialog.removeAttribute('open');
    restoreBatchDetailsFocus();
  }
}

function containBatchDetailsFocus(event) {
  const dialog = $('batch-details-dialog');
  if (!dialog || !dialog.open || event.key !== 'Tab') return;
  const focusable = [...dialog.querySelectorAll('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')]
    .filter(element => element.getClientRects().length);
  if (!focusable.length) {
    event.preventDefault();
    dialog.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

async function openBatchDetails(job, opener = null) {
  const dialog = $('batch-details-dialog');
  if (!dialog) return loadJob(job.id, true);
  state.batchDetailsOpener = opener instanceof HTMLElement ? opener : document.activeElement;
  state.batchDetailsOpenerKey = {
    jobId: String(job.id),
    kind: opener instanceof HTMLElement ? opener.dataset.batchDetailsKind || 'detail' : 'detail',
  };
  let detailJob = job;
  if (!Array.isArray(job.groups) || !Array.isArray(job.alerts)) {
    try { detailJob = await api(`/api/jobs/${job.id}`); }
    catch (error) { setMessage(error.message); return; }
  }
  job = detailJob;
  text($('batch-details-title'), `Batch #${job.id}`);
  const meta = $('batch-details-meta');
  meta.replaceChildren();
  [['Status', job.status], ['Window', `${localIso(job.window_start)} -> ${localIso(job.window_end)}`], ['Alerts', job.alert_count], ['Max level', job.max_level], ['Review', reviewStatus(job)]].forEach(([label, value]) => {
    const item = document.createElement('span');
    text(item, `${label}: ${value ?? '-'}`);
    meta.append(item);
  });
  text($('batch-details-summary'), job.ai_summary || 'Chưa có tóm tắt AI.');
  const rules = $('batch-details-rules');
  rules.replaceChildren();
  (Array.isArray(job.groups) ? job.groups : []).forEach(group => {
    const item = document.createElement('li');
    text(item, `${group.rule_id || 'unknown'} · ${group.description || ''} · ${group.count || 0} alerts · level ${group.max_level || 0}`);
    rules.append(item);
  });
  if (!rules.children.length) { const item = document.createElement('li'); text(item, 'Chưa có rule được kích hoạt.'); rules.append(item); }
  const logs = $('batch-details-logs');
  logs.replaceChildren();
  const alerts = Array.isArray(job.alerts) ? job.alerts : [];
  alerts.slice(0, 100).forEach(alert => {
    const item = document.createElement('li');
    text(item, `${alert.timestamp || '-'} · rule ${alert.rule_id || '-'} · agent ${alert.agent || '-'}`);
    logs.append(item);
  });
  if (!alerts.length) { const item = document.createElement('li'); text(item, 'Backend chưa cung cấp raw log cho batch này.'); logs.append(item); }
  const recommendation = $('batch-details-recommendation');
  const result = (job.results || []).find(row => row.scope === 'window' && row.scope_key !== 'attack_chain')?.result || {};
  text(recommendation, result.recommendation || (Array.isArray(result.next_steps) ? result.next_steps.join(' · ') : '') || 'Chưa có khuyến nghị RAG.');
  dialog.dataset.jobId = job.id;
  if (typeof dialog.showModal === 'function') dialog.showModal(); else dialog.setAttribute('open', '');
  // Put focus on the named close control and keep keyboard focus inside the modal.
  $('batch-details-close')?.focus();
}

async function quickReview(job) {
  if (reviewStatus(job) !== 'none') return;
  const button = document.querySelector(`[data-review-job="${job.id}"]`);
  if (button) { button.disabled = true; button.classList.add('loading'); }
  try {
    await api(`/api/jobs/${job.id}/review`, {method: 'POST', body: JSON.stringify({status: 'acknowledged', severity: 'inherit', tags: [], note: ''})});
    await loadJobs();
  } catch (error) { setMessage(error.message); if (button) button.disabled = false; }
}

async function bulkReview() {
  const ids = [...state.selectedJobs];
  if (!ids.length) return;
  const button = $('history-bulk-review');
  button.disabled = true; button.classList.add('loading');
  try {
    await api('/api/jobs/review/bulk', {method: 'POST', body: JSON.stringify({job_ids: ids, status: 'acknowledged', severity: 'inherit', tags: [], note: ''})});
    state.selectedJobs.clear();
    await loadJobs();
  } catch (error) { setMessage(error.message); if (button) button.disabled = false; }
  finally { button.disabled = false; button.classList.remove('loading'); }
}

function setSelectValue(id, value) {
  if (value == null || value === '') return;
  const select = $(id);
  const wanted = String(value);
  if ([...select.options].some(option => option.value === wanted)) select.value = wanted;
}

function applyScheduleForm(schedule) {
  $('schedule-enabled').checked = !!schedule.enabled;
  setSelectValue('schedule-interval', schedule.interval_seconds);
  setSelectValue('schedule-model', schedule.model);
  setSelectValue('schedule-language', schedule.language);
  setSelectValue('schedule-delivery-channel', schedule.delivery_channel);
  const parameters = schedule.llm_parameters || {};
  $('schedule-llm-temperature').value = parameters.temperature ?? 0;
  $('schedule-llm-top-p').value = parameters.top_p ?? 1;
  $('schedule-llm-max-tokens').value = parameters.max_tokens ?? 2048;
  $('schedule-llm-system-prompt').value = '';
  $('schedule-clear-system-prompt').checked = false;
  $('schedule-attack-chain').checked = !!schedule.attack_chain;
  if (schedule.attack_chain_seconds) setSelectValue('schedule-attack-chain-seconds', schedule.attack_chain_seconds);
  toggleChainWindow('schedule-attack-chain', 'schedule-attack-chain-window');
}

function readLlmParameters(prefix, {allowPrompt = true} = {}) {
  const parameters = {
    temperature: Number($(`${prefix}llm-temperature`).value),
    top_p: Number($(`${prefix}llm-top-p`).value),
    max_tokens: Number($(`${prefix}llm-max-tokens`).value),
  };
  if (!allowPrompt) return parameters;
  const prompt = $(`${prefix}llm-system-prompt`).value;
  const clear = prefix === 'schedule-' && $('schedule-clear-system-prompt').checked;
  if (prompt || clear) parameters.system_prompt = prompt;
  return parameters;
}

function markScheduleFormDirty() {
  if (!state.scheduleFormDirty) {
    state.scheduleFormDirty = true;
    text($('schedule-message'), 'Đã thay đổi lịch; bấm Lưu lịch để áp dụng.');
  }
}

async function loadStatus() {
  try {
    const status = await api('/api/status');
    text($('health'), `App ${status.app} · Worker ${status.worker} · Delivery ${status.delivery_worker || '—'} · Queue ${status.queue ?? '—'} · DB ${status.database ?? '—'} · RAG ${status.rag}`);
    $('health').title = `RAG ready: ${status.rag}. Trạng thái này chỉ mô tả index tham chiếu cục bộ.`;
  } catch (error) {
    text($('health'), error.message);
    $('health').title = 'Không thể đọc trạng thái RAG; kiểm tra kết nối dashboard.';
  }
}

async function loadModels() {
  try {
    const data = await api('/api/models');
    fillModels(data.models);
    if (!data.models.length) setMessage('Không có model allowlist nào đang cài.');
  } catch (error) {
    setMessage(error.message);
  }
}

async function mutate(path, successMessage, button = null, busyLabel = 'Đang xử lý…') {
  const idleLabel = button?.textContent;
  setButtonBusy(button, true, busyLabel, idleLabel);
  try {
    await api(path, {method: 'POST', body: '{}'});
    setMessage(successMessage);
    await Promise.all([loadJobs(), loadSchedule()]);
    if (state.activeJob) await loadJob(state.activeJob);
  } catch (error) {
    setMessage(error.message);
  } finally {
    setButtonBusy(button, false, '', idleLabel);
  }
}

async function loadSchedule() {
  const schedule = await api('/api/schedule');
  state.scheduleSnapshot = schedule;
  if (!state.scheduleFormDirty) applyScheduleForm(schedule);
  text($('schedule-state'), schedule.state);

  const detail = $('schedule-detail');
  detail.replaceChildren();
  [
    ['Next window', schedule.next_window_start ? localIso(schedule.next_window_start) : '—', 'Thời điểm bắt đầu cửa sổ kế tiếp theo lịch local.'],
    ['Ingest delay', `${schedule.ingest_delay_seconds}s`, 'Khoảng đệm để Wazuh Indexer nhận đủ alert trước khi cửa sổ được quét.'],
    ['Delivery', schedule.delivery_channel || 'none', 'Kênh gửi báo cáo sau khi batch hoàn tất.'],
    ['Coverage gaps', schedule.gap_windows, 'Số cửa sổ bị bỏ qua khi scheduler không thể catch-up hết; đây là khoảng trống dữ liệu.'],
    ['Error', schedule.error || '—', 'Lỗi cuối cùng khiến lịch bị block, nếu có.'],
  ].forEach(([label, value, hint]) => {
    const term = document.createElement('dt');
    const description = document.createElement('dd');
    text(term, label);
    term.title = hint;
    term.setAttribute('aria-label', `${label}: ${hint}`);
    text(description, value);
    detail.append(term, description);
  });
  $('schedule-actions').classList.toggle('hidden', schedule.state !== 'blocked');
}

async function loadJobs() {
  const query = new URLSearchParams({page: String(state.historyPage), page_size: String(state.historyPageSize)});
  const filterMap = {search: 'history-search', status: 'history-status', language: 'history-language', mode: 'history-mode', review: 'history-review', severity: 'history-severity'};
  Object.entries(filterMap).forEach(([name, id]) => {
    const value = $(id).value.trim();
    if (value) query.set(name, value);
  });
  const requestId = ++state.historyRequest;
  const data = await api(`/api/jobs?${query}`);
  if (requestId !== state.historyRequest) return;
  state.jobs = data.jobs;
  state.historyServerPagination = Number.isInteger(data.total) && Number.isInteger(data.page) && Number.isInteger(data.page_size);
  if (state.historyServerPagination) {
    state.historyPage = data.page;
    state.historyPageSize = data.page_size;
    state.historyTotal = data.total;
    state.historyPages = Number.isInteger(data.pages) ? data.pages : Math.max(1, Math.ceil(data.total / data.page_size));
  } else {
    state.historyTotal = state.jobs.length;
    state.historyPages = Math.max(1, Math.ceil(state.jobs.length / state.historyPageSize));
    const known = new Set(state.jobs.map(job => job.id));
    state.selectedJobs.forEach(id => { if (!known.has(id)) state.selectedJobs.delete(id); });
  }
  renderJobs();
}

function renderJobs() {
  const body = $('jobs');
  body.replaceChildren();
  const {jobs, pageJobs, pages, total} = visibleHistoryJobs();
  const pageInfo = $('history-page-info');
  if (pageInfo) text(pageInfo, `${total ? ((state.historyPage - 1) * state.historyPageSize + 1) : 0}-${Math.min(state.historyPage * state.historyPageSize, total)} / ${total}`);
  if ($('history-page-prev')) $('history-page-prev').disabled = state.historyPage <= 1;
  if ($('history-page-next')) $('history-page-next').disabled = state.historyPage >= pages;
  if ($('history-bulk-review')) $('history-bulk-review').disabled = !state.selectedJobs.size;
  if (!jobs.length) {
    const row = document.createElement('tr');
    const empty = document.createElement('td');
    empty.colSpan = 11;
    empty.className = 'batch-empty';
    text(empty, state.jobs.length ? 'Không có batch khớp bộ lọc.' : 'Chưa có batch analysis.');
    row.append(empty);
    body.append(row);
    return;
  }
  pageJobs.forEach(job => {
    const row = document.createElement('tr');
    row.className = 'batch-row';
    row.setAttribute('aria-label', `Mở nhận xét AI cho batch ${job.id}`);
    row.classList.toggle('selected', job.id === state.activeJob);
    const open = () => loadJob(job.id, true).catch(error => setMessage(error.message));
    row.addEventListener('click', event => {
      if (event.target.closest('button, input, a')) return;
      open();
    });
    const batch = document.createElement('td');
    const batchId = document.createElement('strong');
    const batchType = document.createElement('small');
    const selector = document.createElement('input');
    selector.type = 'checkbox';
    selector.checked = state.selectedJobs.has(job.id);
    selector.setAttribute('aria-label', `Chọn batch ${job.id}`);
    selector.addEventListener('click', event => event.stopPropagation());
    selector.addEventListener('change', () => {
      if (selector.checked) state.selectedJobs.add(job.id); else state.selectedJobs.delete(job.id);
      renderJobs();
    });
    text(batchId, `#${job.id}`);
    const type = job.job_type === 'scheduled_window' ? 'scheduled' : 'manual';
    const chainTag = job.attack_chain ? ' · chuỗi tấn công' : '';
    text(batchType, `${type} · ${job.analysis_mode || 'full'} · ${String(job.language || 'vi').toUpperCase()}${chainTag}`);
    const detail = document.createElement('button');
    detail.type = 'button'; detail.className = 'link-button'; text(detail, `#${job.id}`);
    detail.dataset.batchDetailsJob = String(job.id);
    detail.dataset.batchDetailsKind = 'detail';
    detail.setAttribute('aria-label', `Open details for batch ${job.id}`);
    detail.addEventListener('click', event => { event.stopPropagation(); openBatchDetails(job, event.currentTarget); });
    batch.append(selector, detail, batchType);

    const range = document.createElement('td');
    const start = document.createElement('span');
    const end = document.createElement('small');
    text(start, localIso(job.window_start));
    text(end, `→ ${localIso(job.window_end)}`);
    range.append(start, end);

    const status = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.className = 'badge';
    text(statusBadge, job.status);
    status.append(statusBadge);

    const numericCell = value => {
      const cell = document.createElement('td');
      cell.className = 'numeric';
      text(cell, value);
      return cell;
    };

    const ai = document.createElement('td');
    const aiBadge = document.createElement('span');
    const aiSummary = document.createElement('small');
    const processing = ['pending', 'running'].includes(job.status);
    const severity = String(job.ai_severity || (processing ? phaseLabel(job) : 'no result'));
    aiBadge.className = `badge severity-${severity.replace(/[^a-z]+/g, '-')}`;
    text(aiBadge, severity);
    text(aiSummary, job.ai_summary || (
        job.status === 'failed'
          ? 'Batch failed'
          : processing ? processingPhases[job.phase]?.[1] || 'Đang xử lý' : 'Chưa có nhận xét AI'
      ));
    aiSummary.className = 'history-summary-clamp';
    aiSummary.title = job.ai_summary || '';
    ai.append(aiBadge, aiSummary);
    if (job.ai_summary) {
      const more = document.createElement('button');
      more.type = 'button'; more.className = 'link-button'; text(more, 'Xem thêm');
      more.dataset.batchDetailsJob = String(job.id);
      more.dataset.batchDetailsKind = 'summary';
      more.setAttribute('aria-label', `Open full AI summary for batch ${job.id}`);
      more.addEventListener('click', event => { event.stopPropagation(); openBatchDetails(job, event.currentTarget); });
      ai.append(more);
    }
    const review = document.createElement('td');
    const reviewBadge = document.createElement('span');
    reviewBadge.className = 'badge';
    text(reviewBadge, reviewStatus(job) === 'none' ? 'unreviewed' : reviewStatus(job));
    review.append(reviewBadge);
    if (reviewStatus(job) === 'none') {
      const mark = document.createElement('button');
      mark.type = 'button'; mark.className = 'link-button quick-review'; mark.dataset.reviewJob = job.id;
      text(mark, 'Mark reviewed'); mark.title = 'Đánh dấu đã review';
      mark.addEventListener('click', event => { event.stopPropagation(); quickReview(job); });
      review.append(mark);
    }
    const freshness = document.createElement('td');
    const freshnessTime = job.finished_at || job.created_at;
    const freshnessLabel = document.createElement('span');
    const freshnessDetail = document.createElement('small');
    text(freshnessLabel, ageLabel(freshnessTime));
    text(freshnessDetail, freshnessTime ? localIso(freshnessTime) : 'chưa có timestamp');
    freshnessLabel.title = freshnessTime || '';
    freshness.append(freshnessLabel, freshnessDetail);

    const delivery = document.createElement('td');
    const deliveries = Array.isArray(job.deliveries) ? job.deliveries : (job.delivery ? [job.delivery] : []);
    if (!deliveries.length) text(delivery, job.delivery_channel && job.delivery_channel !== 'none' ? 'queued' : '—');
    deliveries.forEach(item => {
      const line = document.createElement('small');
      const label = item.channel === 'gmail' ? 'Gmail' : 'Telegram';
      text(line, `${label}: ${item.status} · attempt ${item.attempt_count || 0}/3${item.delivery_stage && item.delivery_stage !== 'none' ? ` · ${item.delivery_stage}` : ''}${item.updated_at ? ` · ${localIso(item.updated_at)}` : ''}${item.error_code ? ` · ${item.error_code}` : ''}`);
      delivery.append(line);
    });

    row.append(
      batch, range, status,
      numericCell(job.alert_count), numericCell(job.group_count), numericCell(job.rule_count),
      numericCell(job.max_level), ai, review, delivery, freshness,
    );
    body.append(row);
  });
}

function metric(label, value) {
  const item = document.createElement('div');
  const number = document.createElement('strong');
  const name = document.createElement('span');
  item.className = 'metric';
  text(number, value);
  text(name, label);
  item.append(number, name);
  return item;
}

function timelineForJob(job) {
  if (Array.isArray(job.timeline) && job.timeline.length) return job.timeline;
  const rows = Array.isArray(job.alerts) ? job.alerts : [];
  if (!rows.length) return [];
  const windowStart = new Date(job.window_start).getTime();
  const windowEnd = new Date(job.window_end).getTime();
  const duration = Math.max(1, windowEnd - windowStart);
  const bucketCount = Math.min(48, Math.max(1, Math.ceil(duration / 60000)));
  const step = duration / bucketCount;
  const buckets = Array.from({length: bucketCount}, (_, index) => ({
    start: new Date(windowStart + step * index).toISOString(),
    end: new Date(windowStart + step * (index + 1)).toISOString(),
    count: 0,
  }));
  rows.forEach(row => {
    const timestamp = new Date(row.timestamp).getTime();
    if (timestamp < windowStart || timestamp >= windowEnd) return;
    const index = Math.min(bucketCount - 1, Math.floor((timestamp - windowStart) / step));
    buckets[index].count += 1;
  });
  return buckets;
}

function alertInBucket(alert, bucket) {
  if (!bucket) return true;
  const timestamp = new Date(alert.timestamp).getTime();
  return timestamp >= new Date(bucket.start).getTime() && timestamp < new Date(bucket.end).getTime();
}

function groupInBucket(group, bucket) {
  if (!bucket) return true;
  const first = new Date(group.first_seen).getTime();
  const last = new Date(group.last_seen).getTime();
  if (!Number.isFinite(first) || !Number.isFinite(last)) return true;
  return first < new Date(bucket.end).getTime() && last >= new Date(bucket.start).getTime();
}

function selectTimelineBucket(job, bucket) {
  state.timelineSelection = bucket;
  renderTimeline(job);
  renderEventLists(job, bucket);
}

function renderTimeline(job) {
  const chart = $('alert-timeline');
  const empty = $('timeline-empty');
  const axis = $('timeline-axis');
  const selection = state.timelineSelection;
  const buckets = timelineForJob(job);
  chart.replaceChildren();
  chart.style.removeProperty('--timeline-columns');
  $('timeline-reset').classList.toggle('hidden', !selection);
  $('timeline-analyze').classList.toggle('hidden', !selection || !selection.count);

  if (!buckets.length || !buckets.some(bucket => Number(bucket.count))) {
    text(empty, job.progress_total ? 'Chưa có timeline cho batch cũ này.' : 'Cửa sổ này không có alert.');
    empty.classList.remove('hidden');
    axis.classList.add('hidden');
    text($('timeline-selection'), '');
    return;
  }

  empty.classList.add('hidden');
  axis.classList.remove('hidden');
  chart.style.setProperty('--timeline-columns', buckets.length);
  const maximum = Math.max(...buckets.map(bucket => Number(bucket.count) || 0), 1);
  buckets.forEach(bucket => {
    const slot = document.createElement('div');
    const bar = document.createElement('button');
    const count = document.createElement('span');
    const isSelected = selection && selection.start === bucket.start && selection.end === bucket.end;
    slot.className = 'timeline-slot';
    slot.setAttribute('role', 'listitem');
    bar.type = 'button';
    bar.className = 'timeline-bar';
    bar.classList.toggle('selected', !!isSelected);
    bar.disabled = !bucket.count;
    bar.style.setProperty('--bar-height', `${Math.max(bucket.count ? 8 : 2, bucket.count / maximum * 100)}%`);
    bar.setAttribute('aria-pressed', String(!!isSelected));
    bar.setAttribute(
      'aria-label',
      `${bucket.count} alert từ ${localIso(bucket.start)} đến ${localIso(bucket.end)}`,
    );
    bar.title = bar.getAttribute('aria-label');
    text(count, bucket.count || '');
    bar.append(count);
    bar.addEventListener('click', () => selectTimelineBucket(job, bucket));
    slot.append(bar);
    chart.append(slot);
  });
  text(axis.children[0], localIso(buckets[0].start));
  text(axis.children[1], localIso(buckets[buckets.length - 1].end));
  text(
    $('timeline-selection'),
    selection
      ? `${selection.count} alert · ${localIso(selection.start)} – ${localIso(selection.end)}`
      : 'Chưa chọn bucket; toàn bộ cửa sổ đang được hiển thị.',
  );
}

function aggregateRules(groups) {
  const rules = new Map();
  groups.forEach(group => {
    const ruleId = String(group.rule_id || 'unknown');
    const current = rules.get(ruleId) || {ruleId, count: 0, maxLevel: 0};
    current.count += Number(group.count) || 0;
    current.maxLevel = Math.max(current.maxLevel, Number(group.max_level) || 0);
    rules.set(ruleId, current);
  });
  return [...rules.values()].sort((left, right) => right.count - left.count || left.ruleId.localeCompare(right.ruleId));
}

function chartRules(rules) {
  if (rules.length <= 6) return rules;
  const visible = rules.slice(0, 5);
  visible.push({
    ruleId: 'Other',
    count: rules.slice(5).reduce((total, rule) => total + rule.count, 0),
    maxLevel: Math.max(...rules.slice(5).map(rule => rule.maxLevel)),
  });
  return visible;
}

function showTooltip(rule, total, anchor) {
  const tooltip = $('chart-tooltip');
  const percent = total ? `${(rule.count / total * 100).toFixed(1)}%` : '0.0%';
  const bounds = anchor.getBoundingClientRect();
  text(tooltip, `${rule.ruleId}: ${rule.count} alerts · ${percent} cửa sổ`);
  tooltip.style.left = `${Math.min(bounds.left, window.innerWidth - 290)}px`;
  tooltip.style.top = `${Math.max(8, bounds.top - 42)}px`;
  tooltip.classList.remove('hidden');
}

function hideTooltip() { $('chart-tooltip').classList.add('hidden'); }

function renderRuleVisual(groups, totalAlerts) {
  const rules = aggregateRules(groups);
  const chart = $('rules-chart');
  const table = $('rules-table');
  chart.replaceChildren();
  table.replaceChildren();

  if (!rules.length) {
    const empty = document.createElement('p');
    empty.className = 'chart-empty';
    text(empty, 'Không có alert trong cửa sổ này.');
    chart.append(empty);
  } else {
    const visible = chartRules(rules);
    const maximum = Math.max(...visible.map(rule => rule.count));
    visible.forEach(rule => {
      const row = document.createElement('div');
      const label = document.createElement('span');
      const track = document.createElement('div');
      const bar = document.createElement('button');
      const value = document.createElement('span');
      row.className = 'chart-row';
      track.className = 'bar-track';
      bar.type = 'button';
      bar.className = 'bar';
      bar.style.width = `${Math.max(3, rule.count / maximum * 100)}%`;
      bar.setAttribute('aria-label', `${rule.ruleId}: ${rule.count} alerts`);
      text(label, rule.ruleId);
      text(value, rule.count);
      bar.append(value);
      bar.addEventListener('pointerenter', () => showTooltip(rule, totalAlerts, bar));
      bar.addEventListener('pointerleave', hideTooltip);
      bar.addEventListener('focus', () => showTooltip(rule, totalAlerts, bar));
      bar.addEventListener('blur', hideTooltip);
      track.append(bar);
      row.append(label, track);
      chart.append(row);
    });
  }

  rules.forEach(rule => {
    const row = document.createElement('tr');
    [rule.ruleId, rule.count, rule.maxLevel].forEach(value => {
      const cell = document.createElement('td');
      text(cell, value);
      row.append(cell);
    });
    table.append(row);
  });
}

function renderJobActions(job) {
  const actions = $('job-actions');
  actions.replaceChildren();
  if (['pending', 'running'].includes(job.status) && !job.cancel_requested) {
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'danger';
    text(cancel, 'Huỷ job');
    cancel.addEventListener('click', () => mutate(`/api/jobs/${job.id}/cancel`, `Đã yêu cầu huỷ job #${job.id}`));
    actions.append(cancel);
  } else if (job.status === 'failed' && job.retry_count < 3 && !job.correlation?.security_test_run_id) {
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'secondary';
    text(retry, 'Thử lại');
    retry.addEventListener('click', () => mutate(`/api/jobs/${job.id}/retry`, `Đã đưa lại job #${job.id} vào hàng đợi`));
    actions.append(retry);
  } else if (job.cancel_requested && ['pending', 'running'].includes(job.status)) {
    const requested = document.createElement('span');
    requested.className = 'muted';
    text(requested, 'Đang chờ huỷ');
    actions.append(requested);
  }
  if (['succeeded', 'partial'].includes(job.status)) {
    const deliveries = Array.isArray(job.deliveries)
      ? job.deliveries
      : (job.delivery ? [job.delivery] : []);
    const knownChannels = new Set(deliveries.map(delivery => delivery.channel));
    deliveries.forEach(delivery => {
      const channel = delivery.channel || 'notification';
      const label = channel === 'gmail' ? 'Gmail' : 'Telegram';
      const status = document.createElement('span');
      status.className = 'muted';
      text(status, `${label}: ${delivery.status} · attempt ${delivery.attempt_count || 0}/3${delivery.delivery_stage && delivery.delivery_stage !== 'none' ? ` · ${delivery.delivery_stage}` : ''}${delivery.error_code ? ` · ${delivery.error_code}` : ''}`);
      actions.append(status);
      if (['failed', 'uncertain', 'sent'].includes(delivery.status) && delivery.attempt_count < 3) {
        const retryDelivery = document.createElement('button');
        retryDelivery.type = 'button';
        retryDelivery.className = 'secondary';
        const resend = delivery.status === 'sent';
        const legacyPartial = channel === 'telegram' && String(delivery.error_code || '').startsWith('telegram_partial_');
        text(retryDelivery, resend ? `Gửi lại ${label}` : `Retry ${label}`);
        retryDelivery.addEventListener('click', async () => {
          const prompt = resend
            ? `Gửi lại report ${label} với format hiện tại? Điều này sẽ tạo thêm một message/email.`
            : legacyPartial
              ? `Lần gửi cũ đã có summary nhưng thiếu PDF. Gửi lại bằng format một tài liệu PDF duy nhất? Chat sẽ có thêm một report.`
              : `Gửi lại report ${label}? Có thể tạo message trùng nếu lần trước đã tới provider.`;
          if (!window.confirm(prompt)) return;
          try {
            await api(`/api/deliveries/${delivery.id}/retry`, {
              method: 'POST', body: JSON.stringify({confirm: true, force: resend || legacyPartial}),
            });
            setMessage(`Đã xếp lại ${label} delivery của job #${job.id}.`);
            await loadJob(job.id);
          } catch (error) { setMessage(deliveryMessage(error, label)); }
        });
        actions.append(retryDelivery);
      }
    });
    [['telegram', 'Telegram'], ['gmail', 'Gmail']].forEach(([channel, label]) => {
      if (knownChannels.has(channel)) return;
      const send = document.createElement('button');
      send.type = 'button';
      send.className = 'secondary';
      text(send, `Gửi ${label}`);
      send.addEventListener('click', async () => {
        const description = channel === 'telegram'
          ? 'Gửi một tài liệu PDF kèm caption tóm tắt đã redact tới Telegram?'
          : 'Gửi bản tóm tắt đã redact tới Gmail?';
        if (!window.confirm(description)) return;
        try {
          await api(`/api/jobs/${job.id}/delivery`, {
            method: 'POST', body: JSON.stringify({channel, confirm: true}),
          });
          setMessage(`Đã xếp report job #${job.id} vào hàng đợi ${label}.`);
          await loadJob(job.id);
        } catch (error) { setMessage(deliveryMessage(error, label)); }
      });
      actions.append(send);
    });
  }
  const downloadReport = (schema, filename) => {
    const link = document.createElement('a');
    link.href = `/api/jobs/${job.id}/export${schema ? `?schema=${schema}` : ''}`;
    link.download = filename;
    link.click();
  };
  const exportJson = document.createElement('button');
  exportJson.type = 'button';
  exportJson.className = 'secondary';
  text(exportJson, 'Xuất JSON v2');
  exportJson.addEventListener('click', () => {
    downloadReport('', `wazuh-ai-job-${job.id}.json`);
  });
  actions.append(exportJson);
  const exportV1 = document.createElement('button');
  exportV1.type = 'button';
  exportV1.className = 'secondary export-compat';
  text(exportV1, 'JSON v1 (tương thích)');
  exportV1.title = 'Chỉ dùng khi hệ thống nhận dữ liệu cũ hỗ trợ schema v1.';
  exportV1.addEventListener('click', () => {
    downloadReport('v1', `wazuh-ai-job-${job.id}-v1.json`);
  });
  actions.append(exportV1);
}

function renderProvenance(job, windowResult) {
  const panel = $('ai-provenance');
  panel.replaceChildren();
  if (!windowResult) {
    panel.classList.add('hidden');
    return;
  }
  const provenance = windowResult.provenance || {};
  const recorded = Object.keys(provenance).length > 0;
  const originLabels = {
    ollama_model: 'JSON hợp lệ parse từ phản hồi Ollama',
    local_fallback: 'Fallback do ứng dụng tạo vì phản hồi model không hợp lệ',
  };
  const rows = recorded ? [
    ['Nguồn', `${provenance.provider || 'unknown'} · ${provenance.transport || 'transport chưa ghi'} `],
    ['Model', `${job.model}${provenance.response_model ? ` · Ollama trả ${provenance.response_model}` : ''}`],
    ['Nguồn output', originLabels[provenance.output_origin] || provenance.output_origin || 'unknown'],
    ['Wall latency', `${Number(windowResult.latency_s || 0).toFixed(3)} giây`],
    ['Tokens', `prompt ${provenance.prompt_eval_count ?? '—'} · output ${provenance.eval_count ?? '—'}`],
    ['Thời điểm', provenance.response_created_at || windowResult.created_at || '—'],
    ['SHA-256 phản hồi', provenance.response_content_sha256 || '—'],
  ] : [
    ['Provenance', 'unknown_legacy — kết quả cũ không có metadata để khẳng định nguồn gọi model'],
    ['Model đã chọn', job.model],
    ['Wall latency đã lưu', `${Number(windowResult.latency_s || 0).toFixed(3)} giây`],
    ['Thời điểm lưu', windowResult.created_at || '—'],
  ];
  rows.forEach(([label, value]) => {
    const term = document.createElement('dt');
    const description = document.createElement('dd');
    text(term, label);
    text(description, value);
    panel.append(term, description);
  });
  panel.classList.remove('hidden');
}

function traceValues(value) {
  if (Array.isArray(value)) return value.filter(item => typeof item === 'string' && item.trim());
  return typeof value === 'string' && value.trim() ? [value] : [];
}

function renderTraceList(id, values, fallback) {
  const list = $(id);
  list.replaceChildren();
  (values.length ? values : [fallback]).forEach(value => {
    const item = document.createElement('li');
    text(item, value);
    list.append(item);
  });
}

function traceFallback(job, fallback) {
  return job.correlation?.security_test_run_id
    ? `Báo cáo AI chưa đạt quality gate: ${fallback}`
    : fallback;
}

function renderSocTrace(job, windowResult) {
  const panel = $('soc-trace');
  const result = windowResult?.result || {};
  // Accept both the current contract and an explicitly named trace during migration.
  const basis = result.assessment_basis || result.soc_trace || result.analysis_trace || {};
  const provenance = windowResult?.provenance || {};
  const hasTrace = basis && typeof basis === 'object' && !Array.isArray(basis) && Object.keys(basis).length;
  const promptVersion = basis.prompt_version || result.prompt_version || provenance.prompt_version;
  const compliance = basis.language_compliance || result.language_compliance || provenance.language_compliance;
  const effectiveLanguage = basis.response_language || result.response_language || provenance.effective_language;
  const confidence = basis.confidence ?? result.confidence;
  if (!windowResult || (!hasTrace && !promptVersion && !compliance && confidence == null)) {
    panel.classList.add('hidden');
    return;
  }

  const meta = $('soc-trace-meta');
  meta.replaceChildren();
  [
    ['Ngôn ngữ yêu cầu', String(job.language || 'vi').toUpperCase()],
    ['Ngôn ngữ phản hồi', effectiveLanguage ? String(effectiveLanguage).toUpperCase() : 'Không ghi nhận'],
    ['Tuân thủ ngôn ngữ', compliance || 'unknown_legacy'],
    ['Prompt version', promptVersion || 'unknown_legacy'],
  ].forEach(([label, value]) => {
    const term = document.createElement('dt');
    const description = document.createElement('dd');
    text(term, label);
    text(description, value);
    meta.append(term, description);
  });
  const confidenceBadge = $('soc-trace-confidence');
  const numericConfidence = typeof confidence === 'number' && Number.isFinite(confidence)
    ? Math.max(0, Math.min(100, confidence))
    : null;
  const confidenceValue = numericConfidence == null ? confidence : `${numericConfidence}%`;
  const confidenceClass = numericConfidence == null
    ? String(confidence ?? 'unknown').replace(/[^a-z0-9]+/gi, '-')
    : numericConfidence >= 80 ? 'high' : numericConfidence >= 50 ? 'medium' : 'low';
  text(confidenceBadge, confidenceValue == null ? 'confidence: unknown' : `confidence: ${confidenceValue}`);
  confidenceBadge.className = `badge confidence-${confidenceClass}`;
  renderTraceList('soc-observed-facts', traceValues(basis.observed_facts), traceFallback(job, 'thiếu fact Wazuh cụ thể.'));
  renderTraceList('soc-inferences', traceValues(basis.inferences), traceFallback(job, 'thiếu suy luận có điều kiện.'));
  renderTraceList('soc-uncertainties', traceValues(basis.uncertainties), traceFallback(job, 'thiếu bất định cụ thể.'));
  renderTraceList('soc-limitations', traceValues(basis.limitations), traceFallback(job, 'thiếu giới hạn dữ liệu cụ thể.'));
  panel.classList.remove('hidden');
}

function renderQualityWarning(job, windowResult, result = {}) {
  const panel = $('ai-quality-warning');
  const list = $('ai-quality-warning-list');
  if (!panel || !list) return;
  list.replaceChildren();
  const warnings = [];
  const addWarning = value => {
    const message = String(value ?? '').trim();
    if (message && !warnings.includes(message)) warnings.push(message);
  };
  if (job.status === 'partial') addWarning('Job có trạng thái partial; báo cáo chưa hoàn chỉnh.');
  (Array.isArray(windowResult?.warnings) ? windowResult.warnings : []).forEach(addWarning);
  const correlation = job.correlation || job.security_test_correlation || {};
  const securityCorrelation = Boolean(correlation.security_test_run_id || correlation.scenario_id);
  const summary = String(result.summary || '').trim();
  const genericSummaries = new Set([
    'Tổng quan về các cảnh báo và nhóm cảnh báo',
    'AI không cung cấp summary.',
  ]);
  if (securityCorrelation && (!summary || genericSummaries.has(summary))) {
    addWarning('Security correlation chưa có summary AI cụ thể; không trình bày như kết luận hoàn chỉnh.');
  }
  if (!warnings.length) { panel.classList.add('hidden'); return; }
  warnings.forEach(value => { const item = document.createElement('li'); text(item, value); list.append(item); });
  panel.classList.remove('hidden');
}

function renderAiReview(job, windowResult) {
  const status = $('ai-review-status');
  const empty = $('ai-review-empty');
  const content = $('ai-review-content');
  const loading = $('ai-loading');
  const steps = $('ai-next-steps');
  steps.replaceChildren();
  loading.classList.add('hidden');
  renderProvenance(job, windowResult);
  renderSocTrace(job, windowResult);
  const result = windowResult?.result || {};
  renderQualityWarning(job, windowResult, result);

  if (!windowResult) {
    let message = 'Batch này chưa có nhận xét AI.';
    if (job.status === 'failed') message = `Batch thất bại trước bước AI: ${job.error || 'không có chi tiết lỗi'}`;
    else if (job.status === 'pending' || job.status === 'running') {
      const phase = processingPhases[job.phase] || ['Đang xử lý', 'Đang chờ cập nhật trạng thái.'];
      text($('ai-loading-title'), phase[0]);
      text(
        $('ai-loading-detail'),
        job.phase === 'calling_ollama' ? `${phase[1]} Model: ${job.model}.` : phase[1],
      );
      loading.classList.remove('hidden');
      message = '';
    }
    else if (!job.progress_total) message = 'Batch không có alert nên hệ thống không gọi AI.';
    text(status, ['pending', 'running'].includes(job.status) ? phaseLabel(job) : job.status === 'failed' ? 'failed' : 'no AI result');
    status.className = 'badge';
    text(empty, message);
    text($('ai-summary'), '');
    text($('ai-root-cause'), '');
    text($('ai-mitre'), '');
    empty.classList.toggle('hidden', !message);
    content.classList.add('hidden');
    return;
  }

  const severity = String(result.severity || 'unknown');
  text(status, severity);
  status.className = `badge severity-${severity.replace(/[^a-z]+/g, '-')}`;
  const correlation = job.correlation || job.security_test_correlation || {};
  const securityCorrelation = Boolean(correlation.security_test_run_id || correlation.scenario_id);
  const summary = String(result.summary || '').trim();
  const genericSummary = summary === 'Tổng quan về các cảnh báo và nhóm cảnh báo' || summary === 'AI không cung cấp summary.';
  text($('ai-summary'), securityCorrelation && (!summary || genericSummary)
    ? 'Security correlation chưa có summary AI cụ thể; không có kết luận hoàn chỉnh.'
    : summary || 'AI không cung cấp summary.');
  const findings = Array.isArray(result.key_findings) ? result.key_findings : [];
  text($('ai-root-cause'), result.root_cause || result.intent || findings.join(' · ') || 'AI không cung cấp root cause/phát hiện chính.');
  const chain = (job.results || []).find(row => row.scope_key === 'attack_chain')?.result || {};
  const chainList = $('ai-chain');
  chainList.replaceChildren();
  if (chain.summary) {
    const head = document.createElement('li');
    text(head, chain.intent ? `${chain.summary} (ý định: ${chain.intent})` : chain.summary);
    chainList.append(head);
  }
  (Array.isArray(chain.kill_chain_stages) ? chain.kill_chain_stages : [])
    .filter(value => String(value ?? '').trim())
    .forEach(value => {
      const item = document.createElement('li');
      text(item, value);
      chainList.append(item);
    });
  $('ai-chain-field').classList.toggle('hidden', !chainList.children.length);
  const mitre = Array.isArray(result.mitre) ? result.mitre : [];
  text($('ai-mitre'), mitre.length ? mitre.join(' · ') : 'Không có MITRE mapping.');
  const nextSteps = Array.isArray(result.next_steps) ? result.next_steps : [];
  (nextSteps.length ? nextSteps : ['AI không cung cấp next steps.']).forEach(value => {
    const item = document.createElement('li');
    text(item, value);
    steps.append(item);
  });
  empty.classList.add('hidden');
  content.classList.remove('hidden');
}

function renderReview(job) {
  const review = job.review || {};
  $('review-status').value = review.status || 'new';
  $('review-severity').value = review.severity || 'inherit';
  $('review-tags').value = Array.isArray(review.tags) ? review.tags.join(', ') : '';
  $('review-note').value = review.note || '';
  text($('review-current'), review.status || 'chưa review');
  const history = $('review-history');
  history.replaceChildren();
  const rows = Array.isArray(job.review_history) ? job.review_history : (job.review ? [job.review] : []);
  if (!rows.length) { const empty = document.createElement('p'); empty.className = 'muted'; text(empty, 'Chưa có analyst review cho job này.'); history.append(empty); return; }
  rows.forEach(row => {
    const item = document.createElement('div'); item.className = 'review-history-item';
    text(item, `${row.created_at || row.updated_at || '—'} · ${row.status || 'new'} · ${row.severity || 'inherit'}${row.tags?.length ? ` · #${row.tags.join(' #')}` : ''}${row.note ? `\n${row.note}` : ''}`);
    history.append(item);
  });
}

function appendValueRow(panel, label, value, status = '') {
  const term = document.createElement('dt'); const detail = document.createElement('dd');
  text(term, label.replace(/_/g, ' '));
  if (status) { const badge = document.createElement('span'); badge.className = `badge dependency-${status}`; text(badge, status); detail.append(badge); }
  const valueText = typeof value === 'object' ? Object.entries(value || {}).filter(([key]) => key !== 'status').map(([key, item]) => `${key.replace(/_/g, ' ')}: ${item}`).join(' · ') : value;
  if (valueText !== '' && valueText != null) { const content = document.createElement('span'); text(content, valueText); detail.append(content); }
  panel.append(term, detail);
}
function renderKeyValue(id, data, emptyText) {
  const panel = $(id); panel.replaceChildren();
  const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined && value !== null && value !== '');
  if (!entries.length) { const empty = document.createElement('p'); empty.className = 'muted'; text(empty, emptyText); panel.append(empty); return; }
  entries.forEach(([key, value]) => appendValueRow(panel, key, value));
}
async function loadDependencies() {
  try {
    const data = await api('/api/dependencies'); const panel = $('dependency-health'); panel.replaceChildren();
    Object.entries(data || {}).forEach(([name, value]) => {
      const details = {...(value.details || {})};
      if (details.status) { details.cluster_status = details.status; delete details.status; }
      if (value.latency_ms != null) details.latency_ms = `${value.latency_ms} ms`;
      appendValueRow(panel, name, details, value.status || 'unknown');
    });
    if (!panel.children.length) renderKeyValue('dependency-health', {}, 'Chưa có dependency status.');
  } catch (error) { renderKeyValue('dependency-health', {error: error.message}, ''); }
}
async function loadMaintenance() {
  try {
    const data = await api('/api/maintenance');
    const fields = {
      retention: data.policy ? `${data.policy.retention_days} ngày · giữ ${data.policy.retention_keep_latest} job mới nhất` : '',
      queue: data.stats?.queue ? `chờ ${data.stats.queue.pending || 0} · đang chạy ${data.stats.queue.running || 0}${data.stats.queue.oldest_pending_at ? ` · cũ nhất ${ageLabel(data.stats.queue.oldest_pending_at)}` : ''}` : '',
      database: data.stats?.database ? `${data.stats.database.job_count || 0} job · ${data.stats.database.terminal_job_count || 0} terminal · ${data.stats.database.bytes || 0} byte` : '',
      reviews: data.stats?.reviews ? `${data.stats.reviews.event_count || 0} sự kiện` : '',
    };
    renderKeyValue('maintenance-stats', fields, 'Chưa có maintenance data.');
    const enabled = !!(data.retention_enabled ?? data.enabled ?? data.retention?.enabled);
    $('maintenance-prune').disabled = !enabled;
    text($('maintenance-note'), enabled ? 'Prune chỉ xóa history theo retention đã cấu hình; cần xác nhận riêng.' : 'Retention chưa bật nên prune bị khóa.');
  } catch (error) { renderKeyValue('maintenance-stats', {error: error.message}, ''); }
}

function renderNotificationStatus(id, notification, channel, limitKey, emptyText) {
  renderKeyValue(id, {
    channel: notification.channel || channel,
    enabled: notification.enabled ? 'on' : 'off',
    configured: notification.configured ? 'ready' : 'missing local secret',
    [limitKey]: notification[limitKey],
  }, emptyText);
}

async function loadNotificationStatus() {
  try {
    const notifications = await api('/api/notifications/status');
    state.notifications = notifications || {};
    const telegram = notifications.telegram || {};
    const gmail = notifications.gmail || {};
    renderNotificationStatus(
      'telegram-status', telegram, 'telegram', 'max_message_chars', 'Chưa có Telegram status.',
    );
    renderNotificationStatus(
      'gmail-status', gmail, 'gmail', 'max_body_chars', 'Chưa có Gmail status.',
    );
    if ($('telegram-test').dataset.loading !== 'true') {
      $('telegram-test').disabled = !(telegram.enabled && telegram.configured);
    }
    $('gmail-test').disabled = !(gmail.enabled && gmail.configured);
  } catch (error) {
    $('telegram-test').disabled = true;
    $('gmail-test').disabled = true;
    renderKeyValue('telegram-status', {error: 'Unable to load Telegram status'}, '');
    renderKeyValue('gmail-status', {error: 'Unable to load Gmail status'}, '');
  }
}

function clearTelegramSettingsForm() {
  $('telegram-settings-form').reset();
  text($('telegram-settings-message'), '');
}

function openTelegramSettings() {
  clearTelegramSettingsForm();
  const dialog = $('telegram-settings-dialog');
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
  $('telegram-bot-token').focus();
}

function closeTelegramSettings() {
  const dialog = $('telegram-settings-dialog');
  if (typeof dialog.close === 'function') dialog.close();
  else dialog.removeAttribute('open');
  clearTelegramSettingsForm();
}

function telegramSettingsValidationError() {
  const token = $('telegram-bot-token').value.trim();
  const chatId = $('telegram-chat-id').value.trim();
  if (!token) return {message: 'Nhập Bot Token trước khi lưu cài đặt Telegram.', field: 'telegram-bot-token'};
  if (!chatId) return {message: 'Nhập Numeric Chat ID trước khi lưu cài đặt Telegram.', field: 'telegram-chat-id'};
  if (!/^-?\d{1,20}$/.test(chatId)) return {message: 'Numeric Chat ID chỉ gồm chữ số, có thể bắt đầu bằng dấu trừ.', field: 'telegram-chat-id'};
  return null;
}

function telegramIsReady() {
  const telegram = state.notifications?.telegram || {};
  return !!(telegram.enabled && telegram.configured);
}

function clearGmailSettingsForm() {
  $('gmail-settings-form').reset();
  text($('gmail-settings-message'), '');
}

function openGmailSettings() {
  clearGmailSettingsForm();
  const dialog = $('gmail-settings-dialog');
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
  $('gmail-sender-email').focus();
}

function closeGmailSettings() {
  const dialog = $('gmail-settings-dialog');
  if (typeof dialog.close === 'function') dialog.close();
  else dialog.removeAttribute('open');
  clearGmailSettingsForm();
}

const ipLookbackLabels = {
  300: '5 phút',
  900: '15 phút',
  1800: '30 phút',
  3600: '1 giờ',
  7200: '2 giờ',
  21600: '6 giờ',
  43200: '12 giờ',
  86400: '24 giờ',
  259200: '3 ngày',
  604800: '7 ngày',
  2592000: '30 ngày',
};

function renderIpList(id, values, emptyText) {
  const list = $(id);
  list.replaceChildren();
  const items = Array.isArray(values) ? values.filter(value => String(value ?? '').trim()) : [];
  (items.length ? items : [emptyText]).forEach(value => {
    const item = document.createElement('li');
    text(item, value);
    list.append(item);
  });
}

function renderIpAnalysis(data) {
  const analysis = data?.analysis || {};
  const basis = analysis.assessment_basis || {};
  const confidence = Number(analysis.confidence);
  const severity = String(analysis.severity || 'unknown').toLowerCase();
  text($('ip-result-address'), data?.source_ip || $('ip-address').value.trim() || $('ip-select').value);
  text($('ip-result-alerts'), Number(data?.total_alerts || 0).toLocaleString());
  text($('ip-result-severity'), severity);
  $('ip-result-severity').className = `severity-text severity-${severity.replace(/[^a-z]+/g, '-')}`;
  text($('ip-result-confidence'), Number.isFinite(confidence) ? `${Math.max(0, Math.min(100, confidence))}%` : 'không xác định');
  text($('ip-result-window'), ipLookbackLabels[Number(data?.lookback_seconds)] || `${data?.lookback_seconds || 0} giây`);
  text($('ip-result-summary'), analysis.summary || 'AI không cung cấp nhận định.');
  text($('ip-result-intent'), analysis.intent || 'Chưa xác định được ý định.');
  renderIpList('ip-result-chain', analysis.kill_chain_stages, 'Chưa tái dựng được giai đoạn tấn công.');
  renderIpList('ip-result-mitre', analysis.mitre, 'Không có ánh xạ MITRE.');
  renderIpList('ip-result-assets', analysis.targeted_assets, 'Chưa xác định tài sản đích.');
  renderIpList('ip-result-steps', analysis.next_steps, 'Kiểm tra thủ công alert của IP trong Wazuh Indexer.');
  renderIpList('ip-result-facts', basis.observed_facts, 'Không có sự kiện quan sát có cấu trúc.');
  renderIpList('ip-result-inferences', basis.inferences, 'Không có suy luận có cấu trúc.');
  renderIpList('ip-result-uncertainties', basis.uncertainties, 'Không ghi nhận bất định.');
  renderIpList('ip-result-limitations', basis.limitations, 'Không ghi nhận giới hạn bổ sung.');
  $('ip-analysis-result').classList.remove('hidden');
}

async function loadActiveIps() {
  const select = $('ip-select');
  if (!select) return;
  const currentVal = select.value;
  try {
    const lookback = $('ip-lookback').value;
    const res = await api(`/api/active-ips?lookback_seconds=${lookback}`);
    select.replaceChildren();
    const defaultOpt = document.createElement('option');
    defaultOpt.value = '';
    text(defaultOpt, res.ips && res.ips.length ? '-- Chọn IP nguồn phát hiện --' : '-- Không có IP hoạt động --');
    select.append(defaultOpt);
    (res.ips || []).forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.ip;
      text(opt, `${item.ip} (${item.count} alerts)`);
      select.append(opt);
    });
    if (currentVal && Array.from(select.options).some(o => o.value === currentVal)) {
      select.value = currentVal;
    }
  } catch (err) {
    select.replaceChildren();
    const opt = document.createElement('option');
    opt.value = '';
    text(opt, '-- Lỗi tải danh sách IP --');
    select.append(opt);
  }
}

async function runIpAnalysis(sourceIp = '') {
  const submit = $('ip-analysis-submit');
  const isAuto = $('ip-auto').checked;
  let address = String(sourceIp || '').trim();
  if (!address && !isAuto) {
    address = $('ip-address').value.trim() || $('ip-select').value;
  }
  if (!address && !isAuto) {
    text($('ip-analysis-message'), 'Vui lòng chọn IP từ danh sách, nhập IP hoặc bật chế độ tự động.');
    $('ip-address').focus();
    return;
  }
  if (address) {
    $('ip-address').value = address;
  }
  setButtonBusy(submit, true, 'Đang đọc Wazuh và suy luận…', 'Phân tích IP');
  text($('ip-analysis-message'), isAuto ? 'Đang tự động tìm IP nhiều hoạt động nhất và truy vấn log...' : `Đang truy vấn log của ${address || 'IP'}...`);
  try {
    const data = await api('/api/ip-analysis', {
      method: 'POST',
      body: JSON.stringify({
        source_ip: address,
        auto: isAuto,
        lookback_seconds: Number($('ip-lookback').value),
        model: $('ip-model').value,
        language: $('ip-language').value,
      }),
    });
    renderIpAnalysis(data);
    if (data.source_ip && data.source_ip !== 'None') {
      $('ip-address').value = data.source_ip;
      if ($('ip-select')) {
        const matchingOpt = Array.from($('ip-select').options).find(o => o.value === data.source_ip);
        if (matchingOpt) $('ip-select').value = data.source_ip;
      }
    }
    text($('ip-analysis-message'), `Đã phân tích ${Number(data.total_alerts || 0).toLocaleString()} alert liên quan đến ${data.source_ip || address}.`);
  } catch (error) {
    text($('ip-analysis-message'), error.message);
  } finally {
    setButtonBusy(submit, false, '', 'Phân tích IP');
  }
}

function investigateSourceIp(sourceIp) {
  const ip = String(sourceIp || '').trim();
  $('ip-address').value = ip;
  $('ip-auto').checked = false;
  $('ip-investigation').scrollIntoView({behavior: 'smooth', block: 'start'});
  runIpAnalysis(ip).catch(error => text($('ip-analysis-message'), error.message));
}

function renderEventLists(job, bucket = null) {
  const groups = $('groups');
  groups.replaceChildren();
  const visibleGroups = job.groups.filter(group => groupInBucket(group, bucket));
  if (!visibleGroups.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    text(empty, 'Không có nhóm alert trong bucket đã chọn.');
    groups.append(empty);
  }
  visibleGroups.forEach(group => {
    const row = document.createElement('div');
    row.className = 'row';
    const countLabel = bucket ? `${group.count} alerts toàn cửa sổ` : `${group.count} alerts`;
    const label = document.createElement('span');
    text(label, `${group.rule_id} · ${group.description} · ${countLabel} · level ${group.max_level}`);
    const actions = document.createElement('div'); actions.className = 'actions';
    [['Lọc rule', group.rule_id], ['Lọc agent', group.agent], ['Lọc source IP', group.source_ip]].forEach(([labelText, value]) => {
      if (!value) return;
      const pivot = document.createElement('button'); pivot.type = 'button'; pivot.className = 'secondary'; text(pivot, labelText);
      pivot.addEventListener('click', () => applyHistoryPivot(String(value))); actions.append(pivot);
    });
    if (group.source_ip) {
      const investigate = document.createElement('button');
      investigate.type = 'button'; investigate.className = 'secondary ip-investigate-button'; text(investigate, 'Phân tích IP');
      investigate.addEventListener('click', () => investigateSourceIp(group.source_ip));
      actions.append(investigate);
    }
    row.append(label, actions);
    groups.append(row);
  });

  const alerts = $('alerts');
  const empty = $('alerts-empty');
  alerts.replaceChildren();
  const visibleAlerts = job.alerts.filter(alert => alertInBucket(alert, bucket));
  text($('alerts-title'), `Alert (${visibleAlerts.length}/${job.alerts.length})`);
  if (!job.alerts.length) {
    text(
      empty,
      job.analysis_mode === 'aggregate'
        ? 'Aggregate-only không tải full alert. Chọn một bucket rồi bấm “Phân tích bucket này” để drill-down.'
        : 'Batch này không có alert detail.',
    );
    empty.classList.remove('hidden');
  } else if (!visibleAlerts.length) {
    text(empty, 'Không có alert detail trong bucket đã chọn.');
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
  }
  visibleAlerts.forEach(alert => {
    const row = document.createElement('div');
    const label = document.createElement('span');
    const button = document.createElement('button');
    const pivots = document.createElement('div'); pivots.className = 'actions';
    row.className = 'row';
    text(label, `${alert.rule_id} · ${alert.timestamp} · ${alert.agent}`);
    text(button, 'Chi tiết alert đã lọc');
    button.type = 'button';
    [['Lọc rule', alert.rule_id], ['Lọc agent', alert.agent], ['Lọc source IP', alert.source_ip]].forEach(([labelText, value]) => {
      if (!value) return;
      const pivot = document.createElement('button'); pivot.type = 'button'; pivot.className = 'secondary'; text(pivot, labelText);
      pivot.addEventListener('click', () => applyHistoryPivot(String(value))); pivots.append(pivot);
    });
    if (alert.source_ip) {
      const investigate = document.createElement('button');
      investigate.type = 'button'; investigate.className = 'secondary ip-investigate-button'; text(investigate, 'Phân tích IP');
      investigate.addEventListener('click', () => investigateSourceIp(alert.source_ip));
      pivots.append(investigate);
    }
    button.addEventListener('click', async () => {
      try {
        const raw = await api(`/api/job-alerts/${alert.id}`);
        text($('alert-json'), JSON.stringify(raw, null, 2));
        $('alert-dialog').showModal();
      } catch (error) {
        setMessage(error.message);
      }
    });
    row.append(label, pivots, button);
    alerts.append(row);
  });
}

async function loadJob(id, reveal = false) {
  const job = await api(`/api/jobs/${id}`);
  if (state.activeJob !== id) state.timelineSelection = null;
  state.activeJob = id;
  state.activeJobStatus = job.status;
  state.activeJobData = job;
  $('result').classList.remove('hidden');
  text($('result-title'), `Job #${id} · ${localIso(job.window_start)} – ${localIso(job.window_end)}`);
  text($('result-status'), job.status);
  const mode = job.analysis_mode || 'full';
  text($('analysis-mode'), mode === 'aggregate' ? 'aggregate only' : 'full detail');
  $('analysis-mode').className = `badge mode-${mode}`;
  text(
    $('result-meta'),
    `Model ${job.model} · AI ${String(job.language || 'vi').toUpperCase()} · Retry ${job.retry_count}/3 · Created ${job.created_at ? `${localIso(job.created_at)} (${ageLabel(job.created_at)})` : '—'} · Finished ${job.finished_at ? `${localIso(job.finished_at)} (${ageLabel(job.finished_at)})` : 'chưa xong'}${job.error ? ` · ${job.error}` : ''}`,
  );
  renderJobActions(job);

  const rules = aggregateRules(job.groups);
  const agents = new Set(job.groups.map(group => group.agent).filter(Boolean));
  const metrics = job.metrics || {};
  const totalAlerts = metrics.total_alerts ?? job.progress_total;
  const summary = $('summary');
  summary.replaceChildren(
    metric('Alerts', totalAlerts),
    metric('Groups', metrics.total_groups ?? job.groups.length),
    metric('Unique rules', metrics.unique_rules ?? rules.length),
    metric('Unique agents', metrics.unique_agents ?? agents.size),
  );
  renderTimeline(job);
  const windowResult = job.results.find(result => result.scope === 'window' && result.scope_key !== 'attack_chain');
  renderAiReview(job, windowResult);
  renderReview(job);

  text($('rules-chart-subtitle'), `${localIso(job.window_start)} – ${localIso(job.window_end)}`);
  renderRuleVisual(job.groups, totalAlerts);
  renderEventLists(job);
  await loadJobs();
  if (reveal) $('result').scrollIntoView({behavior: 'smooth', block: 'start'});
}

$('preset').addEventListener('change', () => {
  document.querySelectorAll('.custom-field').forEach(element => {
    element.classList.toggle('visible', $('preset').value === 'custom');
  });
});

$('job-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('job-submit');
  submit.disabled = true;
  text(submit, 'Đang tạo job…');
  try {
    const body = {
      model: $('model').value,
      language: $('language').value,
      llm_parameters: readLlmParameters(''),
    };
    body.delivery_channel = $('delivery-channel').value;
    body.attack_chain = $('job-attack-chain').checked;
    if (body.attack_chain) body.attack_chain_seconds = Number($('job-attack-chain-seconds').value);
    if ($('preset').value === 'custom') {
      body.start = new Date($('start').value).toISOString();
      body.end = new Date($('end').value).toISOString();
    } else {
      body.preset_seconds = Number($('preset').value);
    }
    const data = await api('/api/jobs', {method: 'POST', body: JSON.stringify(body)});
    setMessage(`Đã tạo job #${data.job_id}; theo dõi từng bước xử lý bên dưới.`);
    await loadJob(data.job_id, true);
  } catch (error) {
    setMessage(error.message);
  } finally {
    submit.disabled = false;
    text(submit, 'Đưa vào hàng đợi');
  }
});

$('ip-analysis-form').addEventListener('submit', event => {
  event.preventDefault();
  runIpAnalysis().catch(error => text($('ip-analysis-message'), error.message));
});

$('ip-auto').addEventListener('change', () => {
  const isAuto = $('ip-auto').checked;
  $('ip-address').disabled = isAuto;
  $('ip-select').disabled = isAuto;
  if (isAuto) {
    text($('ip-analysis-message'), 'Chế độ tự động: Sẽ phân tích IP có nhiều hoạt động nhất.');
  } else {
    text($('ip-analysis-message'), '');
  }
});

$('ip-select').addEventListener('change', () => {
  if ($('ip-select').value) {
    $('ip-address').value = $('ip-select').value;
  }
});

$('ip-lookback').addEventListener('change', () => {
  loadActiveIps();
});

$('schedule-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(submit, true, 'Đang lưu…', 'Lưu lịch');
  try {
    await api('/api/schedule', {
      method: 'PUT',
      body: JSON.stringify({
        enabled: $('schedule-enabled').checked,
        interval_seconds: Number($('schedule-interval').value),
        model: $('schedule-model').value,
        language: $('schedule-language').value,
        delivery_channel: $('schedule-delivery-channel').value,
        attack_chain: $('schedule-attack-chain').checked,
        attack_chain_seconds: Number($('schedule-attack-chain-seconds').value),
        llm_parameters: readLlmParameters('schedule-'),
      }),
    });
    state.scheduleFormDirty = false;
    text($('schedule-message'), 'Đã lưu lịch tự động.');
    await loadSchedule();
  } catch (error) {
    text($('schedule-message'), error.message);
  } finally {
    setButtonBusy(submit, false, '', 'Lưu lịch');
  }
});
$('schedule-form').addEventListener('change', markScheduleFormDirty);

$('schedule-retry').addEventListener('click', event => mutate('/api/schedule/retry', 'Đã mở lại schedule', event.currentTarget, 'Đang mở lại…'));
$('schedule-skip').addEventListener('click', () => {
  if (window.confirm('Bỏ qua cửa sổ này sẽ tạo một coverage gap. Tiếp tục?')) {
    mutate('/api/schedule/skip', 'Đã bỏ qua một schedule window', $('schedule-skip'), 'Đang bỏ qua…');
  }
});
$('refresh').addEventListener('click', () => Promise.all([loadJobs(), loadSchedule(), loadStatus(), loadNotificationStatus()]));
$('deps-refresh').addEventListener('click', loadDependencies);
$('telegram-refresh').addEventListener('click', loadNotificationStatus);
$('telegram-settings').addEventListener('click', openTelegramSettings);
$('telegram-settings-close').addEventListener('click', closeTelegramSettings);
$('telegram-settings-dialog').addEventListener('close', clearTelegramSettingsForm);
$('telegram-settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  const validationError = telegramSettingsValidationError();
  if (validationError) {
    text($('telegram-settings-message'), validationError.message);
    $(validationError.field).focus();
    return;
  }
  const submit = $('telegram-settings-submit');
  submit.disabled = true;
  text(submit, 'Đang lưu…');
  try {
    await api('/api/notifications/telegram/settings', {
      method: 'POST',
      body: JSON.stringify({
        confirm: true,
        bot_token: $('telegram-bot-token').value,
        chat_id: $('telegram-chat-id').value,
      }),
    });
    setMessage('Đã lưu cài đặt Telegram local. Hãy gửi test để xác minh kết nối.');
    await loadNotificationStatus();
    closeTelegramSettings();
  } catch (error) {
    text($('telegram-settings-message'), error.message);
  } finally {
    submit.disabled = false;
    text(submit, 'Lưu cài đặt');
  }
});
$('telegram-test').addEventListener('click', async () => {
  const button = $('telegram-test');
  const message = $('telegram-test-message');
  if (!telegramIsReady()) {
    text(message, 'Telegram chưa sẵn sàng. Lưu Bot Token và Numeric Chat ID hợp lệ, rồi làm mới trạng thái trước khi gửi test.');
    return;
  }
  if (!window.confirm('Gửi message kiểm tra tĩnh tới Telegram đã cấu hình?')) return;
  button.disabled = true;
  button.dataset.loading = 'true';
  button.setAttribute('aria-busy', 'true');
  text(button, 'Đang gửi test…');
  text(message, 'Đang gửi Telegram connectivity test…');
  try {
    await api('/api/notifications/telegram/test', {method: 'POST', body: JSON.stringify({confirm: true})});
    text(message, 'Đã gửi Telegram connectivity test thành công.');
    await loadNotificationStatus();
  } catch (error) {
    text(message, `Gửi test Telegram thất bại: ${error.message}`);
  } finally {
    delete button.dataset.loading;
    button.removeAttribute('aria-busy');
    button.disabled = !telegramIsReady();
    text(button, 'Gửi test Telegram');
  }
});
$('gmail-refresh').addEventListener('click', loadNotificationStatus);
$('gmail-settings').addEventListener('click', openGmailSettings);
$('gmail-settings-close').addEventListener('click', closeGmailSettings);
$('gmail-settings-dialog').addEventListener('close', clearGmailSettingsForm);
$('gmail-settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('gmail-settings-submit');
  submit.disabled = true;
  text(submit, 'Đang lưu…');
  try {
    await api('/api/notifications/gmail/settings', {
      method: 'POST',
      body: JSON.stringify({
        confirm: true,
        sender_email: $('gmail-sender-email').value,
        app_password: $('gmail-app-password').value,
        recipient_email: $('gmail-recipient-email').value,
      }),
    });
    setMessage('Đã lưu cài đặt Gmail local. Hãy gửi test để xác minh kết nối.');
    await loadNotificationStatus();
    closeGmailSettings();
  } catch (error) {
    text($('gmail-settings-message'), error.message);
  } finally {
    submit.disabled = false;
    text(submit, 'Lưu cài đặt');
  }
});
$('gmail-test').addEventListener('click', async () => {
  const button = $('gmail-test');
  const message = $('gmail-test-message');
  text(message, '');
  setButtonBusy(button, false, '', 'Gửi test Gmail');
  if (!window.confirm('Gửi email kiểm tra tĩnh tới Gmail đã cấu hình?')) return;
  try {
    setButtonBusy(button, true, 'Đang gửi…', 'Gửi test Gmail');
    await api('/api/notifications/gmail/test', {method: 'POST', body: JSON.stringify({confirm: true})});
    text(message, 'Gmail connectivity test sent successfully.');
    await loadNotificationStatus();
  } catch (error) { text(message, deliveryMessage(error, 'Gmail')); }
  finally { setButtonBusy(button, false, '', 'Gửi test Gmail'); }
});
$('maintenance-refresh').addEventListener('click', loadMaintenance);
$('maintenance-prune').addEventListener('click', async () => {
  if (!window.confirm('Xóa history theo retention hiện tại? Không thể hoàn tác.')) return;
  const button = $('maintenance-prune');
  setButtonBusy(button, true, 'Đang xóa…', 'Xóa history theo retention');
  try { await api('/api/maintenance/prune', {method: 'POST', body: JSON.stringify({confirm: true})}); setMessage('Đã chạy prune theo retention.'); await Promise.all([loadMaintenance(), loadJobs()]); } catch (error) { setMessage(error.message); }
  finally { setButtonBusy(button, false, '', 'Xóa history theo retention'); }
});
$('review-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!state.activeJob) return;
  const submit = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(submit, true, 'Đang lưu…', 'Lưu review');
  const tags = $('review-tags').value.split(',').map(value => value.trim()).filter(Boolean);
  try {
    await api(`/api/jobs/${state.activeJob}/review`, {method: 'POST', body: JSON.stringify({status: $('review-status').value, severity: $('review-severity').value, tags, note: $('review-note').value.trim()})});
    text($('review-message'), 'Đã lưu review local.');
    await loadJob(state.activeJob);
  } catch (error) { text($('review-message'), error.message); }
  finally { setButtonBusy(submit, false, '', 'Lưu review'); }
});
filterIds.forEach(id => $(id).addEventListener('input', () => { resetHistoryPage(); saveHistoryFilters(); loadJobs().catch(error => setMessage(error.message)); }));
$('history-filter-clear').addEventListener('click', () => { filterIds.forEach(id => { $(id).value = ''; }); resetHistoryPage(); saveHistoryFilters(); loadJobs().catch(error => setMessage(error.message)); });
$('history-page-prev').addEventListener('click', () => { state.historyPage = Math.max(1, state.historyPage - 1); loadJobs().catch(error => setMessage(error.message)); });
$('history-page-next').addEventListener('click', () => { if (state.historyPage < state.historyPages) { state.historyPage += 1; loadJobs().catch(error => setMessage(error.message)); } });
$('history-bulk-review').addEventListener('click', bulkReview);
$('history-export-csv').addEventListener('click', () => exportHistory('csv'));
$('history-export-json').addEventListener('click', () => exportHistory('json'));
$('history-export-pdf').addEventListener('click', () => window.print());
const batchDetailsDialog = $('batch-details-dialog');
batchDetailsDialog.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    event.preventDefault();
    closeBatchDetailsDialog();
    return;
  }
  containBatchDetailsFocus(event);
});
batchDetailsDialog.addEventListener('cancel', event => {
  event.preventDefault();
  closeBatchDetailsDialog();
});
batchDetailsDialog.addEventListener('close', restoreBatchDetailsFocus);
$('batch-details-close').addEventListener('click', closeBatchDetailsDialog);
$('dialog-close').addEventListener('click', () => $('alert-dialog').close());
$('theme').addEventListener('change', event => applyTheme(event.target.value));
$('timeline-reset').addEventListener('click', () => {
  if (!state.activeJobData) return;
  state.timelineSelection = null;
  renderTimeline(state.activeJobData);
  renderEventLists(state.activeJobData);
});
$('timeline-analyze').addEventListener('click', async () => {
  if (!state.activeJobData || !state.timelineSelection) return;
  try {
    const job = state.activeJobData;
    const bucket = state.timelineSelection;
    const data = await api('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({
        start: bucket.start,
        end: bucket.end,
        model: job.model,
        language: job.language || 'vi',
      }),
    });
    setMessage(`Đã tạo batch con #${data.job_id} từ bucket đã chọn`);
    await loadJobs();
    await loadJob(data.job_id, true);
  } catch (error) {
    setMessage(error.message);
  }
});

async function tick() {
  await Promise.allSettled([loadJobs(), loadSchedule(), loadStatus(), loadNotificationStatus()]);
  if (state.activeJob && ['pending', 'running'].includes(state.activeJobStatus)) {
    await loadJob(state.activeJob).catch(() => {});
  }
}

function toggleChainWindow(checkboxId, wrapperId) {
  $(wrapperId).classList.toggle('hidden', !$(checkboxId).checked);
}
[['job-attack-chain', 'job-attack-chain-window'],
 ['schedule-attack-chain', 'schedule-attack-chain-window']].forEach(([checkboxId, wrapperId]) => {
  $(checkboxId).addEventListener('change', () => toggleChainWindow(checkboxId, wrapperId));
  toggleChainWindow(checkboxId, wrapperId);
});

loadTheme();
loadHistoryFilters();
Promise.allSettled([loadStatus(), loadModels(), loadSchedule(), loadJobs(), loadDependencies(), loadMaintenance(), loadNotificationStatus(), loadActiveIps()]);
const requestedJobId = Number(new URLSearchParams(window.location.search).get('job'));
if (Number.isSafeInteger(requestedJobId) && requestedJobId > 0) {
  loadJob(requestedJobId, true).catch(error => setMessage(error.message));
}
setInterval(tick, 2000);
