import re
from pathlib import Path


CSS_PATH = Path(__file__).resolve().parents[1] / "ai_module" / "web" / "styles.css"
HTML_PATH = CSS_PATH.with_name("index.html")
JS_PATH = CSS_PATH.with_name("app.js")
SECURITY_TEST_HTML_PATH = CSS_PATH.with_name("test.html")
SECURITY_TEST_JS_PATH = CSS_PATH.with_name("test.js")


def _luminance(color):
    channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92 if channel <= 0.04045
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(left, right):
    light, dark = sorted((_luminance(left), _luminance(right)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def _palette(css, selector):
    block = re.search(rf"{re.escape(selector)}\s*\{{(.*?)\}}", css, re.DOTALL)
    assert block, selector
    return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-f]{6})", block.group(1)))


def test_dashboard_palette_meets_wcag_aa_for_small_text():
    css = CSS_PATH.read_text(encoding="utf-8")
    palettes = {
        "dark": _palette(css, ":root"),
        "light": _palette(css, ':root[data-theme="light"]'),
    }
    pairs = {}
    for theme, palette in palettes.items():
        pairs.update({
            f"{theme} body text": (palette["text"], palette["bg"]),
            f"{theme} muted text": (palette["muted"], palette["bg"]),
            f"{theme} accent text": (palette["accent"], palette["bg"]),
            f"{theme} chart value": ("#ffffff", palette["chart-series"]),
        })

    failures = {
        name: round(_contrast(*colors), 2)
        for name, colors in pairs.items()
        if _contrast(*colors) < 4.5
    }
    assert not failures, failures


def test_card_contrast_is_stable_for_mobile_axe_and_both_themes():
    css = CSS_PATH.read_text(encoding="utf-8")
    palettes = {
        "dark": _palette(css, ":root"),
        "light": _palette(css, ':root[data-theme="light"]'),
    }

    # A gradient makes axe's background sampler report a false zero ratio for
    # otherwise readable card text on mobile. Cards use the start color as a
    # solid paint, and every text role remains readable at either panel edge.
    card = re.search(r"\.card\s*\{(.*?)\}", css, re.DOTALL)
    assert card and "background: var(--panel-start);" in card.group(1)
    assert "linear-gradient" not in card.group(1)
    body = re.search(r"body\s*\{(.*?)\}", css, re.DOTALL)
    assert body and "background: var(--bg);" in body.group(1)
    mobile = re.search(r"@media \(max-width: 850px\)\s*\{(.*?)\n\}", css, re.DOTALL)
    assert mobile and ".batch-table th { position: static; overflow-wrap: anywhere; }" in mobile.group(1)

    required_pairs = (
        ("text", "panel-start"),
        ("text", "panel-end"),
        ("muted", "panel-start"),
        ("muted", "panel-end"),
        ("accent", "panel-start"),
        ("accent", "panel-end"),
    )
    failures = {
        f"{theme} {foreground}/{background}": round(_contrast(palette[foreground], palette[background]), 2)
        for theme, palette in palettes.items()
        for foreground, background in required_pairs
        if _contrast(palette[foreground], palette[background]) < 4.5
    }
    assert not failures, failures


def test_dashboard_has_batch_table_and_explicit_ai_review_panel():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")

    assert '<tbody id="jobs"></tbody>' in html
    assert 'id="ai-review-title"' in html
    assert 'id="ai-root-cause"' in html
    assert 'id="ai-next-steps"' in html
    assert "job.alert_count" in javascript
    assert "renderAiReview(job, windowResult)" in javascript
    # History rows are containers, not interactive controls; keyboard users use
    # the explicitly labelled detail button instead of a row-level button.
    assert "row.setAttribute('role', 'button')" not in javascript
    assert "row.setAttribute('aria-selected'" not in javascript
    assert "openBatchDetails(job, event.currentTarget)" in javascript


def test_attack_chain_result_has_render_target_and_history_tag():
    """Chain jobs store kill_chain_stages/intent; the review panel must render them."""
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")

    assert 'id="ai-chain-field"' in html
    assert 'id="ai-chain"' in html
    # The chain profile is a second result row on the same job, not a child job.
    assert "row.scope_key === 'attack_chain'" in javascript
    assert "chain.kill_chain_stages" in javascript
    assert "result.scope === 'window' && result.scope_key !== 'attack_chain'" in javascript
    assert "$('ai-chain-field').classList.toggle('hidden', !chainList.children.length)" in javascript
    # ponytail: static markup/JS assertions; upgrade to a jsdom or Playwright DOM
    # assertion when the project takes on a browser test dependency.
    assert "job.attack_chain ?" in javascript


def test_history_controls_meet_accessibility_semantics_and_target_size():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")

    assert 'id="batch-details-dialog"' in html
    assert 'aria-labelledby="batch-details-title"' in html
    assert "batchDetailsDialog.addEventListener('cancel'" in javascript
    assert "containBatchDetailsFocus" in javascript
    assert "restoreBatchDetailsFocus" in javascript
    assert "batchDetailsOpenerKey" in javascript
    assert "data-batch-details-job" in javascript
    assert ".link-button { min-width: 24px; min-height: 24px;" in css
    assert ".batch-row td:first-child input { width: 24px; height: 24px;" in css


def test_batch_table_grid_item_can_shrink_on_narrow_viewports():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert ".grid > .card { min-width: 0; }" in css
    assert ".table-scroll { overflow-x: auto; }" in css


def test_batch_table_has_bounded_vertical_scroll_and_sticky_header():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert ".batch-table-scroll { max-height: 420px; overflow-y: auto;" in css
    assert ".batch-table th { position: sticky; top: 0;" in css


def test_dashboard_print_view_keeps_report_readable_and_hides_controls():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert "@media print" in css
    assert "@page { size: landscape;" in css
    assert "main > .control-card" in css
    assert "main > .ops-grid" in css
    assert "dialog::backdrop" in css
    assert ".batch-table-scroll { max-height: none; overflow: visible;" in css
    assert ".batch-table thead { display: table-header-group; }" in css
    assert "break-inside: avoid" in css


def test_dashboard_uses_wider_desktop_content_container():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert "calc((100vw - 1500px) / 2)" in css
    assert "main { max-width: 1500px;" in css


def test_security_test_page_exposes_bounded_serial_scenarios_without_claiming_detection():
    html = SECURITY_TEST_HTML_PATH.read_text(encoding="utf-8")
    javascript = SECURITY_TEST_JS_PATH.read_text(encoding="utf-8")

    assert 'id="security-test-cards"' in html
    assert 'id="security-test-confirm"' in html
    assert 'id="security-test-confirm-error"' in html
    assert 'role="alert"' in html
    assert 'id="security-test-terminal-command"' in html
    assert 'id="security-test-terminal-output"' in html
    assert 'id="security-test-script-preview"' in html
    assert 'id="security-test-evidence-detail"' in html
    assert 'id="security-test-verdict"' in html
    assert 'id="security-test-job-link"' in html
    assert 'id="security-test-model"' in html
    assert 'id="security-test-confirm-model"' in html
    assert 'aria-describedby="security-test-confirm-copy security-test-confirm-model security-test-confirm-risk"' in html
    assert 'id="security-test-confirm-error" class="security-test-confirm-error hidden" role="alert" aria-live="assertive" tabindex="-1"' in html
    assert 'aria-live="polite"' in html
    assert "Serial only" in html
    assert "không xác nhận exploit hoặc alert" in html
    assert "/api/security-tests/catalog" in javascript
    assert "/api/security-tests/runs" in javascript
    assert "scenario_id: current.id, model, confirm: true" in javascript
    assert "renderModels(data)" in javascript
    assert "data.allowed_models" in javascript
    assert "data.default_model" in javascript
    assert "run.analysis_model" in javascript
    assert "state.selectedModel = selectedModel()" in javascript
    assert "const previousModel = chosenModel" in javascript
    assert "catalog.allowed_models.includes(previousModel)" in javascript
    assert "$('security-test-model').disabled = true" in javascript
    assert "if (message) node.focus()" in javascript
    assert "terminal_command" in javascript
    assert "script_preview" in javascript
    assert "renderTerminal(run)" in javascript
    assert "target:" not in javascript
    assert "Wazuh alert count" in javascript
    assert "Wazuh rule IDs" in javascript
    assert "analysis_window_start" in javascript
    assert "ai_summary" in javascript
    assert "verdict" in javascript
    assert "setText" in javascript
    assert "if (!scenario?.enabled)" in javascript
    assert "findScenario(catalog, scenario.id)" in javascript
    assert "cache: 'no-store'" in javascript
    assert "setConfirmError(message)" in javascript
    assert "Chua kha dung" in javascript
    assert "scenario?.disabled_reason" in javascript


def test_security_test_ui_renders_all_read_only_phases_and_bounded_polling():
    javascript = SECURITY_TEST_JS_PATH.read_text(encoding="utf-8")
    for phase in (
        "running_script", "waiting_ingest", "querying_wazuh", "queued_ai",
        "analyzing_ai", "completed", "no_alert", "analysis_failed", "failed", "timed_out",
    ):
        assert phase in javascript
    assert "TERMINAL_PHASES" in javascript
    assert "state.pollDeadline = Date.now() + 90000" in javascript
    assert "khong tu dong chay lai scenario" in javascript
    assert "scenario_id: current.id, model, confirm: true" in javascript
    assert "target:" not in javascript
    assert "khong thay Wazuh alert matching truoc khi het cap ingest" in javascript
    assert "khong duoc dung hoi to de tao AI job" in javascript


def test_security_test_ui_uses_explicit_dvwa_brute_force_wording_and_catalog_guard():
    javascript = SECURITY_TEST_JS_PATH.read_text(encoding="utf-8")

    assert "Brute Force (DVWA login)" in javascript
    assert "Gui dung 300 POST voi credential lab khong hop le" in javascript
    assert "luong lab-only bounded" in javascript
    assert "khong xac nhan auth failure hay compromise" in javascript
    assert "dung 300 POST login" in javascript
    assert "scenario?.id === 'brute-force'" in javascript
    assert "findScenario(catalog, scenario.id)" in javascript
    assert "if (!current?.enabled)" in javascript
    assert "scenario_id: current.id, model, confirm: true" in javascript


def test_alert_dialog_does_not_claim_to_show_the_raw_full_alert():
    javascript = JS_PATH.read_text(encoding="utf-8")

    assert "Chi tiết alert đã lọc" in javascript
    assert "text(button, 'Full alert')" not in javascript


def test_dashboard_vietnamese_literals_are_utf8_not_mojibake():
    javascript = JS_PATH.read_text(encoding="utf-8")
    html = HTML_PATH.read_text(encoding="utf-8")
    # Catch both Vietnamese double-encoding and corrupt smart punctuation.
    mojibake_markers = (
        "\u00c3", "\u00c2", "\u00c4", "\u00e1\u00bb", "\u00e2\u2020", "\u00e2\u20ac", "\ufffd",
    )

    assert "Kh\u00f4ng c\u00f3 alert trong c\u1eeda s\u1ed5 n\u00e0y." in javascript
    assert "→ ${localIso(job.window_end)}" in javascript
    assert "'—'" in javascript
    assert "\u00e2\u20ac\u0093" not in javascript
    assert not [marker for marker in mojibake_markers if marker in javascript]
    assert not [marker for marker in mojibake_markers if marker in html]


def test_dashboard_has_timeline_language_and_theme_controls():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")

    for element_id in (
        "alert-timeline", "timeline-reset", "timeline-analyze",
        "language", "schedule-language", "theme", "delivery-channel",
        "schedule-delivery-channel", "telegram-status", "telegram-test",
        "telegram-test-message",
        "telegram-settings", "telegram-settings-dialog", "telegram-bot-token",
        "telegram-chat-id", "gmail-status", "gmail-test", "gmail-settings",
        "gmail-settings-dialog", "gmail-sender-email", "gmail-app-password",
        "gmail-recipient-email", "schedule-message",
    ):
        assert f'id="{element_id}"' in html
    assert "renderTimeline(job)" in javascript
    assert "state.timelineSelection" in javascript
    assert "language: $('language').value" in javascript
    assert "localStorage.setItem('wazuh-ai-theme'" in javascript
    assert "/api/notifications/telegram/test" in javascript
    assert "/api/notifications/telegram/settings" in javascript
    assert "/api/notifications/gmail/test" in javascript
    assert "/api/notifications/gmail/settings" in javascript
    assert "loadNotificationStatus" in javascript
    assert "Gửi lại ${label}" in javascript
    assert "force: resend" in javascript
    assert "scheduleFormDirty" in javascript
    assert "applyScheduleForm(schedule)" in javascript
    assert "telegramSettingsValidationError" in javascript
    assert "dataset.loading" in javascript
    assert "Gửi test Telegram thất bại" in javascript


def test_dashboard_uses_correct_notmythos_label():
    javascript = JS_PATH.read_text(encoding="utf-8")

    assert "'cybercrew/notmythos-8b:latest': '8B Q4_K_M'" in javascript
    assert "text(option, modelLabel(model));" in javascript


def test_dashboard_exposes_advanced_llm_controls_for_manual_and_scheduled_jobs():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")

    for element_id in (
        "llm-temperature", "llm-top-p", "llm-max-tokens", "llm-system-prompt",
        "schedule-llm-temperature", "schedule-llm-top-p", "schedule-llm-max-tokens",
        "schedule-llm-system-prompt", "schedule-clear-system-prompt",
    ):
        assert f'id="{element_id}"' in html
    assert "readLlmParameters" in javascript
    assert "llm_parameters: readLlmParameters('')" in javascript
    assert "llm_parameters: readLlmParameters('schedule-')" in javascript
    assert ".llm-parameters" in css


def test_dashboard_exposes_honest_processing_state_provenance_and_json_export():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")

    for element_id in (
        "job-submit", "ai-loading", "ai-loading-title", "ai-loading-detail",
        "ai-provenance",
    ):
        assert f'id="{element_id}"' in html
    for marker in (
        "fetching_alerts", "preparing_analysis", "calling_ollama", "saving_result",
        "unknown_legacy", "response_content_sha256", "/export",
        "await loadJob(data.job_id, true)",
    ):
        assert marker in javascript
    assert "@keyframes spin" in css
    assert "prefers-reduced-motion" in css


def test_ai_review_exposes_quality_gate_warning_and_safe_security_fallback():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")

    for element_id in ("ai-quality-warning", "ai-quality-warning-title", "ai-quality-warning-list"):
        assert f'id="{element_id}"' in html
    assert "Báo cáo chưa đạt quality gate" in html
    assert "windowResult.warnings" in javascript
    assert "job.status === 'partial'" in javascript
    assert "Security correlation chưa có summary AI cụ thể" in javascript
    assert "Không trình bày báo cáo này như kết luận hoàn chỉnh." in html
    assert "text(item, value)" in javascript
    assert ".ai-quality-warning" in css


def test_dashboard_exposes_soc_trace_and_versioned_exports():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    for element_id in (
        "soc-trace", "soc-observed-facts", "soc-inferences", "soc-uncertainties",
        "soc-limitations", "soc-trace-confidence", "soc-trace-meta",
    ):
        assert f'id="{element_id}"' in html
    for marker in (
        "assessment_basis", "chain-of-thought", "language_compliance",
        "prompt_version", "downloadReport('v1'", "Xuất JSON v2", "JSON v1",
        "textContent",
    ):
        assert marker in javascript or marker in html
    assert ".soc-trace-grid" in CSS_PATH.read_text(encoding="utf-8")


def test_dashboard_has_local_analyst_triage_filters_and_maintenance_controls():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    for element_id in (
        "history-search", "history-status", "history-language", "history-mode",
        "history-review", "review-form", "review-history", "dependency-health",
        "maintenance-stats", "maintenance-prune",
    ):
        assert f'id="{element_id}"' in html
    for marker in (
        "wazuh-ai-history-filters", "/review", "/api/dependencies",
        "/api/maintenance", "confirm: true", "search_terms", "textContent",
        "ageLabel", "finished_at", "Lọc source IP", "cluster_status", "latency_ms",
    ):
        assert marker in javascript
    assert "dependency-ok" in CSS_PATH.read_text(encoding="utf-8")


def test_dashboard_history_supports_detail_pagination_bulk_and_exports():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")
    for element_id in (
        "history-severity", "history-page-info", "history-page-prev", "history-page-next",
        "history-bulk-review", "history-export-csv", "history-export-json", "history-export-pdf",
        "batch-details-dialog", "batch-details-rules", "batch-details-logs", "batch-details-recommendation",
    ):
        assert f'id="{element_id}"' in html
    for marker in (
        "visibleHistoryJobs", "historyPageSize", "state.selectedJobs", "quickReview(job)",
        "/api/jobs/review/bulk", "historyServerPagination", "page_size", "exportHistory", "window.print", "openBatchDetails",
    ):
        assert marker in javascript
    assert "Export current page CSV" in html
    assert ".history-summary-clamp" in css


def test_history_csv_export_neutralizes_spreadsheet_formulas():
    javascript = JS_PATH.read_text(encoding="utf-8")
    assert "formula-like text" in javascript
    assert "if (/^[\\t\\r\\n ]*[=+\\-@]/.test(cell)) cell = `'${cell}`;" in javascript
    assert "current-page" in javascript
    assert "redactClientText" in javascript
    assert "llm_parameters" in javascript


def test_history_rows_keep_ai_summary_clamp_and_compact_spacing():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert ".history-summary-clamp { display: -webkit-box;" in css
    assert "-webkit-line-clamp: 3; overflow: hidden;" in css
    assert "line-height: 1.35;" in css
    assert ".batch-table { width: 100%; min-width: 0; table-layout: fixed;" in css
    assert ".batch-table td { padding: 8px 6px; border-bottom: 1px solid var(--line); vertical-align: top; line-height: 1.35; }" in css
    assert ".batch-table th:nth-child(11) { width: 10%; }" in css
    assert ".batch-row td:last-child { min-width: 0; max-width: none; }" in css
    assert ".batch-table .badge { padding: 3px 4px; font-size: 9px; white-space: nowrap;" in css
    assert ".batch-row td > small:not(.history-summary-clamp)" in css


def test_dashboard_explains_schedule_operational_terms_and_prevents_double_submit():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")

    assert 'id="health"' in html and 'RAG ready:' in html
    for marker in ("Ingest delay", "Coverage gaps", "RAG ready", "setButtonBusy", "aria-label"):
        assert marker in javascript or marker in html
    assert "schedule-form" in javascript
    assert "finally" in javascript
    assert ".ops-detail dt[title]" in css


def test_dashboard_exposes_ip_investigation_and_attack_chain_controls():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")

    for element_id in (
        "ip-investigation", "ip-analysis-form", "ip-address", "ip-lookback",
        "ip-model", "ip-language", "ip-analysis-submit", "ip-analysis-result",
        "ip-result-chain", "ip-result-mitre", "ip-result-assets", "ip-result-steps",
        "ip-result-facts", "ip-result-inferences", "ip-result-uncertainties",
        "ip-result-limitations",
    ):
        assert f'id="{element_id}"' in html
    assert '<option value="2592000">30 ngày (tối đa)</option>' in html
    for marker in (
        "/api/ip-analysis", "lookback_seconds", "investigateSourceIp",
        "group.source_ip", "alert.source_ip", "renderIpAnalysis",
    ):
        assert marker in javascript
    assert ".attack-chain" in css
    assert ".ip-analysis-overview" in css
    # Assets must stay cache-busted; the exact token changes on each UI bump.
    assert len(set(re.findall(r"/assets/\w+\.(?:css|js)\?v=([\w-]+)", html))) == 1
