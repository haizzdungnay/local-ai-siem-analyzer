"""Gmail-style PDF rendering for Telegram's full SIEM report attachment.

Only the allow-listed report fields reach this module. The PDF deliberately
renders the Alert map as one scalable chart, never as the plain-text timeline
fallback used by text-only email clients.
"""

from __future__ import annotations

import io
import math
import os
import unicodedata
from pathlib import Path
from typing import Any


MAX_PDF_BYTES = 12 * 1024 * 1024
PAGE_WIDTH = 1240
PAGE_HEIGHT = 1754
MARGIN = 64
CONTENT_BOTTOM = PAGE_HEIGHT - 92


class TelegramPDFError(RuntimeError):
    """Raised when a safe PDF cannot be generated."""


def _font_candidates(*, bold: bool = False) -> list[Path]:
    names = (
        ("arialbd.ttf", "segoeuib.ttf", "calibrib.ttf", "tahomabd.ttf")
        if bold
        else ("arial.ttf", "segoeui.ttf", "calibri.ttf", "tahoma.ttf")
    )
    candidates: list[Path] = []
    configured = os.environ.get("SIEM_REPORT_FONT", "").strip()
    if configured:
        candidates.append(Path(configured))
    windows_dir = Path(os.environ.get("WINDIR", "C:/Windows"))
    candidates.extend(windows_dir / "Fonts" / name for name in names)
    candidates.extend([
        Path(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        ),
        Path(
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"
        ),
    ])
    return list(dict.fromkeys(candidates))


def _load_font(ImageFont: Any, size: int, *, bold: bool = False) -> Any:
    for candidate in _font_candidates(bold=bold):
        try:
            if candidate.is_file():
                return ImageFont.truetype(str(candidate), size=size)
        except (OSError, ValueError):
            continue
    return ImageFont.load_default()


def _ascii_fallback(value: str) -> str:
    return unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")


def _draw_text(draw: Any, xy: tuple[int, int], text: str, *, font: Any, fill: Any) -> None:
    try:
        draw.text(xy, text, font=font, fill=fill)
    except (UnicodeError, ValueError):
        draw.text(xy, _ascii_fallback(text), font=font, fill=fill)


def _text_width(draw: Any, text: str, font: Any) -> float:
    try:
        return float(draw.textlength(text, font=font))
    except (AttributeError, UnicodeError, ValueError):
        return float(draw.textlength(_ascii_fallback(text), font=font))


def _wrap_lines(draw: Any, text: str, *, font: Any, max_width: int) -> list[str]:
    output: list[str] = []
    for paragraph in str(text).splitlines() or [""]:
        if not paragraph:
            output.append("")
            continue
        line = ""
        for word in paragraph.split():
            candidate = word if not line else f"{line} {word}"
            if line and _text_width(draw, candidate, font) > max_width:
                output.append(line)
                line = word
            else:
                line = candidate
            while line and _text_width(draw, line, font) > max_width:
                split_at = max(1, len(line) - 1)
                while split_at > 1 and _text_width(draw, line[:split_at], font) > max_width:
                    split_at -= 1
                output.append(line[:split_at])
                line = line[split_at:]
        if line:
            output.append(line)
    return output


def _line_height(draw: Any, font: Any, gap: int = 8) -> int:
    bbox = draw.textbbox((0, 0), "Ag", font=font)
    return max(18, bbox[3] - bbox[1]) + gap


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return 0
    return max(0, int(value))


def _format_count(value: int) -> str:
    return f"{max(0, int(value)):,}"


def _chart_ticks(peak: int) -> list[int]:
    if peak <= 0:
        return [0]
    return sorted({0, peak, round(peak * 0.25), round(peak * 0.5), round(peak * 0.75)})


def _timeline_highlights(timeline: list[dict[str, Any]]) -> set[int]:
    ranked = sorted(
        (index for index, bucket in enumerate(timeline) if bucket["count"] > 0),
        key=lambda index: (-timeline[index]["count"], index),
    )
    return set(ranked[:6])


def build_pdf_view(job: dict[str, Any]) -> dict[str, Any]:
    """Build the same bounded, redacted content model used by Gmail's HTML view."""

    if not isinstance(job, dict):
        raise TelegramPDFError("Telegram PDF report phải là object")
    try:
        from gmail_notifier import _count as gmail_count, _safe_items, _safe_timeline
        from telegram_notifier import _analysis_from_job, _safe_text, analysis_sha256, attack_chain_from_job
    except (ImportError, OSError) as exc:
        raise TelegramPDFError("telegram_pdf_dependency") from exc

    try:
        analysis, warnings = _analysis_from_job(job)
        metrics = job.get("metrics") if isinstance(job.get("metrics"), dict) else {}
        groups = job.get("groups") if isinstance(job.get("groups"), list) else []
        severity = _safe_text(analysis.get("severity", "unknown"), 32) or "unknown"
        status = _safe_text(job.get("status", "unknown"), 32) or "unknown"
        window_start = _safe_text(job.get("window_start", ""), 64)
        window_end = _safe_text(job.get("window_end", ""), 64)
        model = _safe_text(job.get("model", ""), 96)
        language = _safe_text(job.get("language", "vi"), 16)
        job_id = _safe_text(job.get("id", "?"), 32) or "?"
        confidence = analysis.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence):
            confidence_text = _safe_text(confidence, 32) or "unknown"
        else:
            confidence_text = f"{confidence:.2f}"
        total_alerts = gmail_count(metrics.get("total_alerts", job.get("progress_total", 0)))
        summary = _safe_text(analysis.get("summary", ""), 1800)
        root_cause = _safe_text(analysis.get("root_cause", ""), 1200)
        basis = analysis.get("assessment_basis") if isinstance(analysis.get("assessment_basis"), dict) else {}
        chain = attack_chain_from_job(job)
        chain_items = []
        chain_summary = _safe_text(chain.get("summary", ""), 1200)
        chain_intent = _safe_text(chain.get("intent", ""), 400)
        if chain_summary:
            chain_items.append(f"{chain_summary} ({chain_intent})" if chain_intent else chain_summary)
        chain_items.extend(_safe_items(chain.get("kill_chain_stages"), max_items=12, item_limit=400))
        sections = [
            ("Summary", [summary] if summary else []),
            ("Root cause", [root_cause] if root_cause else []),
            ("Key findings", _safe_items(analysis.get("key_findings"), max_items=12, item_limit=500)),
            ("Attack chain", chain_items),
            ("MITRE", _safe_items(analysis.get("mitre"), max_items=12, item_limit=300)),
            ("Next steps", _safe_items(analysis.get("next_steps"), max_items=12, item_limit=400)),
            ("Observed facts", _safe_items(basis.get("observed_facts"), max_items=12, item_limit=400)),
            ("Inferences", _safe_items(basis.get("inferences"), max_items=12, item_limit=400)),
            ("Uncertainties", _safe_items(basis.get("uncertainties"), max_items=12, item_limit=400)),
            ("Limitations", _safe_items(basis.get("limitations"), max_items=12, item_limit=400)),
            ("Warnings", _safe_items(warnings, max_items=12, item_limit=400)),
        ]
        rule_totals: dict[str, tuple[int, int]] = {}
        for group in groups:
            if not isinstance(group, dict):
                continue
            rule_id = _safe_text(group.get("rule_id", ""), 32)
            if not rule_id:
                continue
            old_count, old_level = rule_totals.get(rule_id, (0, 0))
            rule_totals[rule_id] = (
                old_count + gmail_count(group.get("count", 0)),
                max(old_level, gmail_count(group.get("max_level", 0))),
            )
        rule_rows = [
            (rule_id, count, level)
            for rule_id, (count, level) in sorted(
                rule_totals.items(), key=lambda item: (-item[1][0], item[0]),
            )[:12]
        ]
        timeline = _safe_timeline(job, max_buckets=48)
        metric_rows = [
            ("Alerts", str(total_alerts)),
            ("Groups", str(gmail_count(metrics.get("total_groups", len(groups))))),
            ("Unique rules", str(gmail_count(metrics.get("unique_rules", 0)))),
            ("Unique agents", str(gmail_count(metrics.get("unique_agents", 0)))),
            ("Max level", str(gmail_count(metrics.get("max_level", 0)))),
        ]
        peak = max((bucket["count"] for bucket in timeline), default=0)
        peak_index = next((index for index, bucket in enumerate(timeline) if bucket["count"] == peak), None)
        return {
            "job_id": job_id,
            "status": status,
            "severity": severity,
            "confidence": confidence_text,
            "window": f"{window_start} -> {window_end}",
            "model": model or "unknown",
            "language": language or "unknown",
            "metric_rows": metric_rows,
            "rule_rows": rule_rows,
            "sections": [(title, values) for title, values in sections if values],
            "timeline": timeline,
            "peak": peak,
            "peak_index": peak_index,
            "analysis_hash": analysis_sha256(analysis) or "unknown",
        }
    except TelegramPDFError:
        raise
    except Exception as exc:
        raise TelegramPDFError("telegram_pdf_generation") from exc


def _new_page(Image: Any) -> Any:
    return Image.new("RGB", (PAGE_WIDTH, PAGE_HEIGHT), "#f4f7f5")


def _draw_frame(draw: Any, *, title: str, job_id: str, brand_font: Any, title_font: Any) -> int:
    draw.rounded_rectangle(
        (MARGIN, MARGIN, PAGE_WIDTH - MARGIN, CONTENT_BOTTOM),
        radius=22,
        fill="#ffffff",
        outline="#d8e1de",
        width=2,
    )
    _draw_text(draw, (MARGIN + 34, MARGIN + 30), "SIEM AI ANALYST", font=brand_font, fill="#12836d")
    _draw_text(draw, (MARGIN + 34, MARGIN + 66), title, font=title_font, fill="#17211d")
    _draw_text(draw, (MARGIN + 34, MARGIN + 116), f"Job #{job_id}", font=brand_font, fill="#52615d")
    return MARGIN + 164


def _draw_footer(draw: Any, *, job_id: str, page_number: int, total_pages: int, font: Any) -> None:
    _draw_text(
        draw,
        (MARGIN, PAGE_HEIGHT - 42),
        f"SIEM AI | Job #{job_id} | Page {page_number}/{total_pages}",
        font=font,
        fill="#52615d",
    )


def _draw_metadata_table(draw: Any, x: int, y: int, width: int, rows: list[tuple[str, str]], *, font: Any, label_font: Any) -> int:
    label_width = 212
    line_height = _line_height(draw, font, 5)
    for label, value in rows:
        lines = _wrap_lines(draw, value, font=font, max_width=width - label_width - 28)
        height = max(48, 20 + len(lines) * line_height)
        draw.rectangle((x, y, x + label_width, y + height), fill="#edf3f0")
        draw.rectangle((x + label_width, y, x + width, y + height), fill="#ffffff", outline="#d8e1de", width=1)
        _draw_text(draw, (x + 16, y + 15), label, font=label_font, fill="#17211d")
        text_y = y + 11
        for line in lines:
            _draw_text(draw, (x + label_width + 16, text_y), line, font=font, fill="#17211d")
            text_y += line_height
        y += height
    return y


def _draw_alert_map(draw: Any, x: int, y: int, width: int, height: int, view: dict[str, Any], *, normal: Any, small: Any, heading: Any) -> int:
    draw.rounded_rectangle((x, y, x + width, y + height), radius=16, fill="#eef5f2", outline="#d8e1de", width=2)
    _draw_text(draw, (x + 22, y + 18), "Alert map / Mật độ alert theo thời gian", font=heading, fill="#17211d")
    peak = view["peak"]
    timeline = view["timeline"]
    peak_note = "No alerts in this window."
    if view["peak_index"] is not None:
        bucket = timeline[view["peak_index"]]
        peak_note = f"Peak {_format_count(peak)} alerts at {bucket['start'].replace('T', ' ')[:16]}"
    _draw_text(draw, (x + 24, y + 57), f"{len(timeline)} visual bins | {peak_note}", font=small, fill="#52615d")
    plot_left = x + 92
    plot_right = x + width - 34
    plot_top = y + 98
    baseline = y + height - 62
    plot_height = baseline - plot_top
    ticks = _chart_ticks(peak)
    for tick in ticks:
        ratio = 0 if peak == 0 else tick / peak
        tick_y = int(baseline - ratio * plot_height)
        draw.line((plot_left, tick_y, plot_right, tick_y), fill="#d8e1de", width=1)
        label = _format_count(tick)
        label_width = int(_text_width(draw, label, small))
        _draw_text(draw, (plot_left - label_width - 12, tick_y - 11), label, font=small, fill="#52615d")
    draw.line((plot_left, baseline, plot_right, baseline), fill="#8ba49b", width=2)
    if timeline:
        slot = (plot_right - plot_left) / len(timeline)
        highlights = _timeline_highlights(timeline)
        for index, bucket in enumerate(timeline):
            count = bucket["count"]
            bar_height = 1 if not peak else max(2 if count else 1, round((count / peak) * plot_height))
            left = int(plot_left + index * slot + max(1, slot * 0.12))
            right = int(plot_left + (index + 1) * slot - max(1, slot * 0.12))
            color = "#12836d" if count else "#cfe0d9"
            draw.rectangle((left, baseline - bar_height, max(left + 1, right), baseline), fill=color)
            if index in highlights:
                label = _format_count(count)
                label_width = int(_text_width(draw, label, small))
                label_x = max(plot_left, min(left - label_width // 2, plot_right - label_width))
                _draw_text(draw, (label_x, max(plot_top, baseline - bar_height - 28)), label, font=small, fill="#0f6658")
        label_indexes = sorted({0, len(timeline) // 2, len(timeline) - 1})
        for index in label_indexes:
            raw = timeline[index]["start" if index < len(timeline) - 1 else "end"]
            label = raw.replace("T", " ")[:16]
            label_width = int(_text_width(draw, label, small))
            point = int(plot_left + (index + 0.5) * slot)
            label_x = max(plot_left, min(point - label_width // 2, plot_right - label_width))
            _draw_text(draw, (label_x, baseline + 14), label, font=small, fill="#52615d")
    else:
        _draw_text(draw, (plot_left, plot_top + 90), "No timeline data in this window.", font=normal, fill="#52615d")
    return y + height


def _draw_rule_table(draw: Any, x: int, y: int, width: int, rows: list[tuple[str, int, int]], *, normal: Any, small: Any, heading: Any) -> int:
    _draw_text(draw, (x, y), "Top rules", font=heading, fill="#17211d")
    y += 46
    if not rows:
        _draw_text(draw, (x, y), "No grouped rule data.", font=normal, fill="#52615d")
        return y + 38
    columns = (int(width * 0.56), int(width * 0.24), width)
    header_height = 36
    draw.rectangle((x, y, x + width, y + header_height), fill="#edf3f0")
    _draw_text(draw, (x + 14, y + 8), "Rule", font=small, fill="#17211d")
    _draw_text(draw, (x + columns[0] + 14, y + 8), "Alerts", font=small, fill="#17211d")
    _draw_text(draw, (x + columns[1] + 14, y + 8), "Max level", font=small, fill="#17211d")
    y += header_height
    for rule_id, count, level in rows:
        row_height = 34
        draw.rectangle((x, y, x + width, y + row_height), fill="#ffffff", outline="#d8e1de", width=1)
        _draw_text(draw, (x + 14, y + 7), rule_id, font=normal, fill="#17211d")
        _draw_text(draw, (x + columns[0] + 14, y + 7), _format_count(count), font=normal, fill="#17211d")
        _draw_text(draw, (x + columns[1] + 14, y + 7), str(level), font=normal, fill="#17211d")
        y += row_height
    return y


def _overview_page(Image: Any, ImageDraw: Any, view: dict[str, Any], *, normal: Any, small: Any, heading: Any, title: Any) -> Any:
    page = _new_page(Image)
    draw = ImageDraw.Draw(page)
    y = _draw_frame(draw, title="SIEM AI report", job_id=view["job_id"], brand_font=small, title_font=title)
    metadata = [
        ("Status", f"{view['status']} | Severity: {view['severity']} | Confidence: {view['confidence']}"),
        ("Window", view["window"]),
        ("Model", f"{view['model']} | Language: {view['language']}"),
        ("Metrics", " | ".join(f"{label}: {value}" for label, value in view["metric_rows"])),
    ]
    y = _draw_metadata_table(draw, MARGIN + 34, y, PAGE_WIDTH - 2 * MARGIN - 68, metadata, font=normal, label_font=small)
    y += 24
    y = _draw_alert_map(draw, MARGIN + 34, y, PAGE_WIDTH - 2 * MARGIN - 68, 334, view, normal=normal, small=small, heading=heading)
    y += 30
    _draw_rule_table(draw, MARGIN + 34, y, PAGE_WIDTH - 2 * MARGIN - 68, view["rule_rows"], normal=normal, small=small, heading=heading)
    return page


def _new_content_page(Image: Any, ImageDraw: Any, view: dict[str, Any], *, small: Any, title: Any) -> tuple[Any, Any, int]:
    page = _new_page(Image)
    draw = ImageDraw.Draw(page)
    y = _draw_frame(draw, title="Full analysis", job_id=view["job_id"], brand_font=small, title_font=title)
    return page, draw, y


def _content_pages(Image: Any, ImageDraw: Any, view: dict[str, Any], *, normal: Any, small: Any, heading: Any, title: Any) -> list[Any]:
    pages: list[Any] = []
    page, draw, y = _new_content_page(Image, ImageDraw, view, small=small, title=title)
    content_width = PAGE_WIDTH - 2 * MARGIN - 116
    line_height = _line_height(draw, normal, 8)

    def next_page() -> tuple[Any, Any, int]:
        pages.append(page)
        return _new_content_page(Image, ImageDraw, view, small=small, title=title)

    for section_title, values in view["sections"]:
        heading_height = 54
        if y + heading_height > CONTENT_BOTTOM:
            page, draw, y = next_page()
        _draw_text(draw, (MARGIN + 42, y), section_title, font=heading, fill="#17211d")
        y += heading_height
        for item in values:
            lines = _wrap_lines(draw, item, font=normal, max_width=content_width)
            block_height = max(44, 18 + len(lines) * line_height)
            if y + block_height > CONTENT_BOTTOM:
                page, draw, y = next_page()
                _draw_text(draw, (MARGIN + 42, y), f"{section_title} (continued)", font=heading, fill="#17211d")
                y += heading_height
            draw.rounded_rectangle(
                (MARGIN + 34, y, PAGE_WIDTH - MARGIN - 34, y + block_height),
                radius=10,
                fill="#f8fbfa",
            )
            _draw_text(draw, (MARGIN + 54, y + 12), "-", font=normal, fill="#12836d")
            text_y = y + 12
            for line in lines:
                _draw_text(draw, (MARGIN + 80, text_y), line, font=normal, fill="#17211d")
                text_y += line_height
            y += block_height + 12
        y += 10

    hash_title = "Analysis SHA256"
    hash_lines = _wrap_lines(draw, view["analysis_hash"], font=small, max_width=content_width)
    hash_height = 42 + len(hash_lines) * _line_height(draw, small, 4)
    if y + hash_height > CONTENT_BOTTOM:
        page, draw, y = next_page()
    _draw_text(draw, (MARGIN + 42, y), hash_title, font=heading, fill="#17211d")
    y += 42
    for line in hash_lines:
        _draw_text(draw, (MARGIN + 42, y), line, font=small, fill="#52615d")
        y += _line_height(draw, small, 4)
    pages.append(page)
    return pages


def render_pdf_report(job: dict[str, Any]) -> bytes:
    """Return a Gmail-style, bounded PDF with a scalable visual Alert map."""

    try:
        from PIL import Image, ImageDraw, ImageFont
    except (ImportError, OSError) as exc:
        raise TelegramPDFError("telegram_pdf_dependency") from exc
    try:
        view = build_pdf_view(job)
        normal = _load_font(ImageFont, 22)
        small = _load_font(ImageFont, 18)
        heading = _load_font(ImageFont, 30, bold=True)
        title = _load_font(ImageFont, 44, bold=True)
        pages = [
            _overview_page(
                Image,
                ImageDraw,
                view,
                normal=normal,
                small=small,
                heading=heading,
                title=title,
            ),
            *_content_pages(
                Image,
                ImageDraw,
                view,
                normal=normal,
                small=small,
                heading=heading,
                title=title,
            ),
        ]
        for page_number, page in enumerate(pages, start=1):
            _draw_footer(
                ImageDraw.Draw(page),
                job_id=view["job_id"],
                page_number=page_number,
                total_pages=len(pages),
                font=small,
            )
        output = io.BytesIO()
        pages[0].save(output, format="PDF", save_all=True, append_images=pages[1:], resolution=150.0)
        pdf = output.getvalue()
        if not pdf.startswith(b"%PDF-") or len(pdf) > MAX_PDF_BYTES:
            raise TelegramPDFError("telegram_pdf_size_limit")
        return pdf
    except TelegramPDFError:
        raise
    except Exception as exc:
        raise TelegramPDFError("telegram_pdf_generation") from exc
