const $ = id => document.getElementById(id);
const state = {activeJob: null, activeJobStatus: null, activeJobData: null, timelineSelection: null, jobs: []};
const text = (node, value) => { node.textContent = value ?? ''; };
const processingPhases = {
  queued: ['Đang chờ worker', 'Job đã được lưu và đang chờ worker cục bộ nhận việc.'],
  fetching_alerts: ['Đang đọc Wazuh Indexer', 'Đang lấy alert thật theo cửa sổ đã chọn.'],
  preparing_analysis: ['Đang chuẩn bị dữ liệu', 'Đang gom nhóm, tính coverage và dựng prompt giới hạn.'],
  calling_ollama: ['Đang gọi Ollama local', 'Đang chờ model tạo JSON; bước này có thể mất vài giây hoặc lâu hơn.'],
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
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

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

const filterIds = ['history-search', 'history-status', 'history-language', 'history-mode', 'history-review'];
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
      && (!$('history-review').value || reviewStatus(job) === $('history-review').value);
  });
}
function applyHistoryPivot(value) {
  $('history-search').value = value;
  saveHistoryFilters();
  renderJobs();
  window.scrollTo({top: 0, behavior: 'smooth'});
}

function fillModels(models) {
  for (const id of ['model', 'schedule-model']) {
    const select = $(id);
    select.replaceChildren();
    models.forEach(model => {
      const option = document.createElement('option');
      option.value = model.name;
      text(option, `${model.name} ${model.parameter_size || ''} ${model.quantization_level || ''}`);
      select.append(option);
    });
  }
}

async function loadStatus() {
  try {
    const status = await api('/api/status');
    text($('health'), `App ${status.app} · Worker ${status.worker} · Queue ${status.queue ?? '—'} · DB ${status.database ?? '—'} · RAG ${status.rag}`);
  } catch (error) {
    text($('health'), error.message);
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

async function mutate(path, successMessage) {
  try {
    await api(path, {method: 'POST', body: '{}'});
    setMessage(successMessage);
    await Promise.all([loadJobs(), loadSchedule()]);
    if (state.activeJob) await loadJob(state.activeJob);
  } catch (error) {
    setMessage(error.message);
  }
}

async function loadSchedule() {
  const schedule = await api('/api/schedule');
  $('schedule-enabled').checked = !!schedule.enabled;
  $('schedule-interval').value = schedule.interval_seconds;
  if (schedule.model) $('schedule-model').value = schedule.model;
  if (schedule.language) $('schedule-language').value = schedule.language;
  text($('schedule-state'), schedule.state);

  const detail = $('schedule-detail');
  detail.replaceChildren();
  [
    ['Next window', schedule.next_window_start ? localIso(schedule.next_window_start) : '—'],
    ['Ingest delay', `${schedule.ingest_delay_seconds}s`],
    ['Coverage gaps', schedule.gap_windows],
    ['Error', schedule.error || '—'],
  ].forEach(([label, value]) => {
    const term = document.createElement('dt');
    const description = document.createElement('dd');
    text(term, label);
    text(description, value);
    detail.append(term, description);
  });
  $('schedule-actions').classList.toggle('hidden', schedule.state !== 'blocked');
}

async function loadJobs() {
  const data = await api('/api/jobs');
  state.jobs = data.jobs;
  renderJobs();
}

function renderJobs() {
  const body = $('jobs');
  body.replaceChildren();
  const jobs = matchingJobs(state.jobs);
  if (!jobs.length) {
    const row = document.createElement('tr');
    const empty = document.createElement('td');
    empty.colSpan = 10;
    empty.className = 'batch-empty';
    text(empty, state.jobs.length ? 'Không có batch khớp bộ lọc.' : 'Chưa có batch analysis.');
    row.append(empty);
    body.append(row);
    return;
  }
  jobs.forEach(job => {
    const row = document.createElement('tr');
    row.className = 'batch-row';
    row.tabIndex = 0;
    row.setAttribute('role', 'button');
    row.setAttribute('aria-label', `Mở nhận xét AI cho batch ${job.id}`);
    row.setAttribute('aria-selected', String(job.id === state.activeJob));
    row.classList.toggle('selected', job.id === state.activeJob);
    const open = () => loadJob(job.id, true).catch(error => setMessage(error.message));
    row.addEventListener('click', open);
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        open();
      }
    });

    const batch = document.createElement('td');
    const batchId = document.createElement('strong');
    const batchType = document.createElement('small');
    text(batchId, `#${job.id}`);
    const type = job.job_type === 'scheduled_window' ? 'scheduled' : 'manual';
    text(batchType, `${type} · ${job.analysis_mode || 'full'} · ${String(job.language || 'vi').toUpperCase()}`);
    batch.append(batchId, batchType);

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
    text(
      aiSummary,
      job.ai_summary || (
        job.status === 'failed'
          ? 'Batch failed'
          : processing ? processingPhases[job.phase]?.[1] || 'Đang xử lý' : 'Chưa có nhận xét AI'
      ),
    );
    ai.append(aiBadge, aiSummary);
    const review = document.createElement('td');
    const reviewBadge = document.createElement('span');
    reviewBadge.className = 'badge';
    text(reviewBadge, reviewStatus(job) === 'none' ? 'unreviewed' : reviewStatus(job));
    review.append(reviewBadge);
    const freshness = document.createElement('td');
    const freshnessTime = job.finished_at || job.created_at;
    const freshnessLabel = document.createElement('span');
    const freshnessDetail = document.createElement('small');
    text(freshnessLabel, ageLabel(freshnessTime));
    text(freshnessDetail, freshnessTime ? localIso(freshnessTime) : 'chưa có timestamp');
    freshnessLabel.title = freshnessTime || '';
    freshness.append(freshnessLabel, freshnessDetail);

    row.append(
      batch, range, status,
      numericCell(job.alert_count), numericCell(job.group_count), numericCell(job.rule_count),
      numericCell(job.max_level), ai, review, freshness,
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
  } else if (job.status === 'failed' && job.retry_count < 3) {
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
  renderTraceList('soc-observed-facts', traceValues(basis.observed_facts), 'Không có fact có cấu trúc trong kết quả này.');
  renderTraceList('soc-inferences', traceValues(basis.inferences), 'Không có suy luận có cấu trúc trong kết quả này.');
  renderTraceList('soc-uncertainties', traceValues(basis.uncertainties), 'Không có bất định được ghi nhận.');
  renderTraceList('soc-limitations', traceValues(basis.limitations), 'Không có giới hạn được ghi nhận.');
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

  const result = windowResult.result || {};
  const severity = String(result.severity || 'unknown');
  text(status, severity);
  status.className = `badge severity-${severity.replace(/[^a-z]+/g, '-')}`;
  text($('ai-summary'), result.summary || 'AI không cung cấp summary.');
  const findings = Array.isArray(result.key_findings) ? result.key_findings : [];
  text($('ai-root-cause'), result.root_cause || findings.join(' · ') || 'AI không cung cấp root cause/phát hiện chính.');
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
    text(button, 'Full alert');
    button.type = 'button';
    [['Lọc rule', alert.rule_id], ['Lọc agent', alert.agent], ['Lọc source IP', alert.source_ip]].forEach(([labelText, value]) => {
      if (!value) return;
      const pivot = document.createElement('button'); pivot.type = 'button'; pivot.className = 'secondary'; text(pivot, labelText);
      pivot.addEventListener('click', () => applyHistoryPivot(String(value))); pivots.append(pivot);
    });
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
  const windowResult = job.results.find(result => result.scope === 'window');
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
    const body = {model: $('model').value, language: $('language').value};
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

$('schedule-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api('/api/schedule', {
      method: 'PUT',
      body: JSON.stringify({
        enabled: $('schedule-enabled').checked,
        interval_seconds: Number($('schedule-interval').value),
        model: $('schedule-model').value,
        language: $('schedule-language').value,
      }),
    });
    await loadSchedule();
  } catch (error) {
    setMessage(error.message);
  }
});

$('schedule-retry').addEventListener('click', () => mutate('/api/schedule/retry', 'Đã mở lại schedule'));
$('schedule-skip').addEventListener('click', () => {
  if (window.confirm('Bỏ qua cửa sổ này sẽ tạo một coverage gap. Tiếp tục?')) {
    mutate('/api/schedule/skip', 'Đã bỏ qua một schedule window');
  }
});
$('refresh').addEventListener('click', () => Promise.all([loadJobs(), loadSchedule(), loadStatus()]));
$('deps-refresh').addEventListener('click', loadDependencies);
$('maintenance-refresh').addEventListener('click', loadMaintenance);
$('maintenance-prune').addEventListener('click', async () => {
  if (!window.confirm('Xóa history theo retention hiện tại? Không thể hoàn tác.')) return;
  try { await api('/api/maintenance/prune', {method: 'POST', body: JSON.stringify({confirm: true})}); setMessage('Đã chạy prune theo retention.'); await Promise.all([loadMaintenance(), loadJobs()]); } catch (error) { setMessage(error.message); }
});
$('review-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!state.activeJob) return;
  const tags = $('review-tags').value.split(',').map(value => value.trim()).filter(Boolean);
  try {
    await api(`/api/jobs/${state.activeJob}/review`, {method: 'POST', body: JSON.stringify({status: $('review-status').value, severity: $('review-severity').value, tags, note: $('review-note').value.trim()})});
    text($('review-message'), 'Đã lưu review local.');
    await loadJob(state.activeJob);
  } catch (error) { text($('review-message'), error.message); }
});
filterIds.forEach(id => $(id).addEventListener('input', () => { saveHistoryFilters(); renderJobs(); }));
$('history-filter-clear').addEventListener('click', () => { filterIds.forEach(id => { $(id).value = ''; }); saveHistoryFilters(); renderJobs(); });
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
  await Promise.allSettled([loadJobs(), loadSchedule(), loadStatus()]);
  if (state.activeJob && ['pending', 'running'].includes(state.activeJobStatus)) {
    await loadJob(state.activeJob).catch(() => {});
  }
}

loadTheme();
loadHistoryFilters();
Promise.allSettled([loadStatus(), loadModels(), loadSchedule(), loadJobs(), loadDependencies(), loadMaintenance()]);
setInterval(tick, 2000);
