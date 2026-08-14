import hashlib
from dataclasses import replace

import pytest
import requests

from gmail_notifier import render_gmail_report
from telegram_pdf import _chart_ticks, build_pdf_view, render_pdf_report
from telegram_notifier import (
    TelegramDeliveryError,
    TelegramNotifier,
    load_env_file,
    render_report,
    render_summary_report,
)


class Response:
    status_code = 200

    def __init__(self, body=None):
        self.body = body if body is not None else {"ok": True, "result": {"message_id": 41}}

    def json(self):
        return self.body


class Session:
    def __init__(self, response=None, error=None):
        self.response = response or Response()
        self.error = error
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def telegram_cfg(max_message_chars=3500):
    return {
        "notifications": {
            "telegram": {
                "enabled": True,
                "max_message_chars": max_message_chars,
                "timeout_seconds": 15,
            }
        }
    }


def job_detail():
    return {
        "id": 42,
        "status": "partial",
        "window_start": "2026-08-10T01:00:00.000Z",
        "window_end": "2026-08-10T01:05:00.000Z",
        "model": "qwen2.5:7b",
        "language": "vi",
        "metrics": {
            "total_alerts": 3,
            "total_groups": 2,
            "unique_rules": 2,
            "unique_agents": 1,
            "max_level": 9,
        },
        "timeline": [
            {"start": "2026-08-10T01:00:00.000Z", "end": "2026-08-10T01:05:00.000Z", "count": 1},
            {"start": "2026-08-10T01:05:00.000Z", "end": "2026-08-10T01:10:00.000Z", "count": 2},
        ],
        "groups": [
            {"rule_id": "5503", "count": 2, "max_level": 9, "description": "RAW_GROUP_SENTINEL"},
            {"rule_id": "5760", "count": 1, "max_level": 4, "source_ip": "203.0.113.50"},
        ],
        "alerts": [{"full_log": "RAW_ALERT_SENTINEL", "source_ip": "203.0.113.50"}],
        "results": [{
            "scope": "window",
            "result": {
                "severity": "medium",
                "confidence": 0.85,
            "summary": (
                "Authorization: Bearer SECRET_VALUE from 203.0.113.50 "
                "and [2001:db8::50] to analyst@example.com"
            ),
                "root_cause": "Failed authentication sequence",
                "key_findings": ["Checksum changed on critical file"],
                "mitre": ["T1070"],
                "next_steps": ["Validate the originating host"],
                "assessment_basis": {
                    "observed_facts": ["Three related alerts were observed"],
                    "inferences": ["May indicate tampering"],
                    "uncertainties": ["File owner was not available"],
                    "limitations": ["No raw log is included"],
                },
            },
            "warnings": ["RAW_WARNING is not an alert reference"],
        }],
    }


def test_env_parser_never_expands_values(tmp_path):
    path = tmp_path / "telegram.local.env"
    path.write_text("TOKEN=literal-$HOME\nCHAT_ID=-10042\n", encoding="utf-8")

    assert load_env_file(path) == {"TOKEN": "literal-$HOME", "CHAT_ID": "-10042"}


def test_renderer_allowlists_report_fields_and_redacts_sensitive_text():
    text, digest = render_report(job_detail())
    gmail_text, _, gmail_digest = render_gmail_report(job_detail())

    assert "RAW_GROUP_SENTINEL" not in text
    assert "RAW_ALERT_SENTINEL" not in text
    assert "SECRET_VALUE" not in text
    assert "203.0.113.50" not in text
    assert "analyst@example.com" not in text
    assert "authorization=[redacted]" in text.lower()
    assert "SECRET_VALUE" not in text
    assert "2001:db8::50" not in text
    assert "5503: 2" in text
    assert "Key findings:" in text
    assert "Observed facts:" in text
    assert "Alert map (2 bins; peak 2 alerts):" in text
    assert text == gmail_text
    assert digest == gmail_digest
    assert digest == hashlib.sha256(text.encode("utf-8")).hexdigest()


def rich_job():
    job = job_detail()
    job["timeline"] = [
        {
            "start": f"2026-08-10T{index // 4:02d}:{(index % 4) * 15:02d}:00.000Z",
            "end": f"2026-08-10T{index // 4:02d}:{((index + 1) % 4) * 15:02d}:00.000Z",
            "count": index % 5,
        }
        for index in range(64)
    ]
    job["results"][0]["result"]["summary"] = "Detailed analyst conclusion. " * 100
    job["results"][0]["result"]["key_findings"] = [f"Finding {index}" for index in range(12)]
    return job


def test_notifier_sends_only_rendered_text_and_hides_credentials(monkeypatch):
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "123456789")
    session = Session()
    notifier = TelegramNotifier(telegram_cfg(), session=session)

    result = notifier.send_report(job_detail())

    assert result["message_id"] == "41"
    assert len(result["payload_sha256"]) == 64
    assert result["message_count"] == 1
    assert len(session.calls) == 1
    document_url, document_kwargs = session.calls[0]
    assert document_url.endswith("/sendDocument")
    assert document_kwargs["data"]["chat_id"] == "123456789"
    caption = document_kwargs["data"]["caption"]
    assert "SIEM AI REPORT | Job #42" in caption
    assert "RAW_ALERT_SENTINEL" not in caption
    assert "SECRET_VALUE" not in caption
    assert "Key findings" not in caption
    assert "Alert map" not in caption
    assert len(caption) <= 1024
    assert document_kwargs["timeout"] == (5, 45)
    filename, pdf_content, mime = document_kwargs["files"]["document"]
    assert filename == "siem-ai-report-job-42.pdf"
    assert mime == "application/pdf"
    assert pdf_content.startswith(b"%PDF-")
    assert b"RAW_ALERT_SENTINEL" not in pdf_content
    assert b"SECRET_VALUE" not in pdf_content
    assert result["payload_sha256"] == hashlib.sha256(
        caption.encode("utf-8") + b"\0" + pdf_content,
    ).hexdigest()
    assert notifier.status() == {
        "channel": "telegram", "enabled": True, "configured": True, "max_message_chars": 3500,
    }


def test_summary_is_concise_while_pdf_contains_full_report():
    summary, summary_digest = render_summary_report(job_detail())
    pdf_content = render_pdf_report(job_detail())

    assert "Summary:" in summary
    assert "Next steps:" in summary
    assert "Key findings:" not in summary
    assert "Alert map" not in summary
    assert "RAW_ALERT_SENTINEL" not in summary
    assert len(summary_digest) == 64
    assert pdf_content.startswith(b"%PDF-")
    assert len(pdf_content) > 10_000
    assert b"RAW_ALERT_SENTINEL" not in pdf_content
    assert b"SECRET_VALUE" not in pdf_content


def test_pdf_is_a_graphical_full_report_attachment():
    pdf_content = render_pdf_report(rich_job())

    assert pdf_content.startswith(b"%PDF-")
    assert len(pdf_content) < 12 * 1024 * 1024
    # The report is rasterized with a locally discovered Unicode font, so raw
    # alert text cannot accidentally leak into the PDF stream.
    assert b"RAW_GROUP_SENTINEL" not in pdf_content
    assert b"RAW_ALERT_SENTINEL" not in pdf_content
    assert b"analyst@example.com" not in pdf_content


def test_pdf_chart_scales_high_alert_counts_without_text_timeline_fallback():
    job = rich_job()
    job["metrics"]["total_alerts"] = 2_000
    job["timeline"] = [
        {
            "start": f"2026-08-10T{index // 2:02d}:{(index % 2) * 30:02d}:00.000Z",
            "end": f"2026-08-10T{index // 2:02d}:{((index + 1) % 2) * 30:02d}:00.000Z",
            "count": 2_000 if index == 24 else index % 17,
        }
        for index in range(48)
    ]

    view = build_pdf_view(job)
    pdf_content = render_pdf_report(job)

    assert ("Alerts", "2000") in view["metric_rows"]
    assert len(view["timeline"]) == 48
    assert view["peak"] == 2_000
    assert _chart_ticks(view["peak"]) == [0, 500, 1000, 1500, 2000]
    assert len(pdf_content) < 12 * 1024 * 1024
    assert pdf_content.count(b"/Type /Page") >= 2


def test_document_timeout_is_uncertain_without_sending_a_summary_first(monkeypatch):
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "123456789")
    notifier = TelegramNotifier(telegram_cfg(1024), session=Session(error=requests.Timeout()))

    with pytest.raises(TelegramDeliveryError) as raised:
        notifier.send_report(rich_job())

    assert raised.value.code == "telegram_timeout"
    assert raised.value.uncertain is True
    assert len(notifier.session.calls) == 1
    assert "files" in notifier.session.calls[0][1]
    assert "json" not in notifier.session.calls[0][1]


def test_document_connection_error_is_one_uncertain_bundle(monkeypatch):
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "123456789")
    notifier = TelegramNotifier(
        telegram_cfg(), session=Session(error=requests.ConnectionError("offline")),
    )

    with pytest.raises(TelegramDeliveryError) as raised:
        notifier.send_report(job_detail())

    assert raised.value.code == "telegram_network_error"
    assert raised.value.uncertain is True
    assert len(notifier.session.calls) == 1
    assert notifier.session.calls[0][0].endswith("/sendDocument")


def test_timeout_is_marked_uncertain_for_manual_review(monkeypatch):
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "123456789")
    notifier = TelegramNotifier(telegram_cfg(), session=Session(error=requests.Timeout()))

    with pytest.raises(TelegramDeliveryError) as raised:
        notifier.send_report(job_detail())

    assert raised.value.code == "telegram_timeout"
    assert raised.value.uncertain is True


def test_notifier_requires_numeric_allowlisted_chat_id(monkeypatch):
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "@not-allowed")
    notifier = TelegramNotifier(telegram_cfg(), session=Session())

    with pytest.raises(ValueError, match="chat ID"):
        notifier.send_test()


def test_discover_chats_needs_only_a_token_and_returns_numeric_ids(monkeypatch):
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.delenv("SIEM_TELEGRAM_CHAT_ID", raising=False)
    session = Session(Response({
        "ok": True,
        "result": [
            {"message": {"chat": {"id": 123456789, "type": "private", "first_name": "Alice"}}},
            {"message": {"chat": {"id": -10077, "type": "group", "title": "SOC"}}},
            {"message": {"chat": {"id": 123456789, "type": "private"}}},
        ],
    }))
    notifier = TelegramNotifier(telegram_cfg(), session=session)

    assert notifier.discover_chats() == [
        {"id": "123456789", "type": "private"},
        {"id": "-10077", "type": "group"},
    ]


def test_configure_local_writes_credentials_without_returning_them(tmp_path, monkeypatch):
    monkeypatch.delenv("SIEM_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("SIEM_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("SIEM_TELEGRAM_ENABLED", raising=False)
    notifier = TelegramNotifier(telegram_cfg(), session=Session())
    env_file = tmp_path / "telegram.local.env"
    notifier.settings = replace(notifier.settings, env_file=env_file)

    status = notifier.configure_local(
        token="123456:TEST_TOKEN_SHOULD_NOT_LEAK", chat_id="-100123456",
    )

    assert status == {
        "channel": "telegram", "enabled": True, "configured": True, "max_message_chars": 3500,
    }
    content = env_file.read_text(encoding="utf-8")
    assert "SIEM_TELEGRAM_ENABLED=true" in content
    assert "SIEM_TELEGRAM_BOT_TOKEN=123456:TEST_TOKEN_SHOULD_NOT_LEAK" in content
    assert "SIEM_TELEGRAM_CHAT_ID=-100123456" in content
    assert "TEST_TOKEN" not in str(status)
    assert "-100123456" not in str(status)


def test_configure_local_rejects_an_invalid_chat_id(tmp_path):
    notifier = TelegramNotifier(telegram_cfg(), session=Session())
    notifier.settings = replace(notifier.settings, env_file=tmp_path / "telegram.local.env")

    with pytest.raises(ValueError, match="chat ID"):
        notifier.configure_local(token="123456:TEST_TOKEN_SHOULD_NOT_LEAK", chat_id="@channel")
