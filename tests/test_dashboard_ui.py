import re
from pathlib import Path


CSS_PATH = Path(__file__).resolve().parents[1] / "ai_module" / "web" / "styles.css"
HTML_PATH = CSS_PATH.with_name("index.html")
JS_PATH = CSS_PATH.with_name("app.js")


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


def test_dashboard_has_batch_table_and_explicit_ai_review_panel():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")

    assert '<tbody id="jobs"></tbody>' in html
    assert 'id="ai-review-title"' in html
    assert 'id="ai-root-cause"' in html
    assert 'id="ai-next-steps"' in html
    assert "job.alert_count" in javascript
    assert "renderAiReview(job, windowResult)" in javascript
    assert "event.key === 'Enter' || event.key === ' '" in javascript


def test_batch_table_grid_item_can_shrink_on_narrow_viewports():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert ".grid > .card { min-width: 0; }" in css
    assert ".table-scroll { overflow-x: auto; }" in css


def test_batch_table_has_bounded_vertical_scroll_and_sticky_header():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert ".batch-table-scroll { max-height: 420px; overflow-y: auto;" in css
    assert ".batch-table th { position: sticky; top: 0;" in css


def test_dashboard_uses_wider_desktop_content_container():
    css = CSS_PATH.read_text(encoding="utf-8")

    assert "calc((100vw - 1500px) / 2)" in css
    assert "main { max-width: 1500px;" in css


def test_alert_dialog_does_not_claim_to_show_the_raw_full_alert():
    javascript = JS_PATH.read_text(encoding="utf-8")

    assert "Chi tiết alert đã lọc" in javascript
    assert "text(button, 'Full alert')" not in javascript


def test_dashboard_has_timeline_language_and_theme_controls():
    html = HTML_PATH.read_text(encoding="utf-8")
    javascript = JS_PATH.read_text(encoding="utf-8")

    for element_id in (
        "alert-timeline", "timeline-reset", "timeline-analyze",
        "language", "schedule-language", "theme",
    ):
        assert f'id="{element_id}"' in html
    assert "renderTimeline(job)" in javascript
    assert "state.timelineSelection" in javascript
    assert "language: $('language').value" in javascript
    assert "localStorage.setItem('wazuh-ai-theme'" in javascript


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
