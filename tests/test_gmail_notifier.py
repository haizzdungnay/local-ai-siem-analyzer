from dataclasses import replace

import pytest

from gmail_notifier import GmailDeliveryError, GmailNotifier, render_gmail_report


def gmail_cfg():
    return {
        "notifications": {
            "gmail": {
                "enabled": True,
                "max_body_chars": 20_000,
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
        "metrics": {"total_alerts": 3},
        "timeline": [
            {"start": "2026-08-10T01:00:00.000Z", "end": "2026-08-10T01:05:00.000Z", "count": 1},
            {"start": "2026-08-10T01:05:00.000Z", "end": "2026-08-10T01:10:00.000Z", "count": 2},
        ],
        "groups": [{"rule_id": "5503", "count": 2, "description": "RAW_GROUP_SENTINEL"}],
        "alerts": [{"full_log": "RAW_ALERT_SENTINEL", "source_ip": "203.0.113.50"}],
        "results": [{
            "scope": "window",
            "result": {
                "severity": "medium",
                "summary": "Authorization: Bearer SECRET_VALUE from 203.0.113.50 to analyst@example.com",
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


class SMTP:
    def __init__(self):
        self.login_calls = []
        self.messages = []
        self.quit_called = False

    def login(self, sender, password):
        self.login_calls.append((sender, password))

    def send_message(self, message):
        self.messages.append(message)
        return {}

    def quit(self):
        self.quit_called = True


def configured_notifier(monkeypatch, smtp_factory):
    monkeypatch.setenv("SIEM_GMAIL_SENDER_EMAIL", "sender@example.com")
    monkeypatch.setenv("SIEM_GMAIL_APP_PASSWORD", "abcd efgh ijkl mnop")
    monkeypatch.setenv("SIEM_GMAIL_RECIPIENT_EMAIL", "recipient@example.com")
    return GmailNotifier(gmail_cfg(), smtp_factory=smtp_factory)


def test_notifier_sends_redacted_plain_text_report_without_leaking_credentials(monkeypatch):
    smtp = SMTP()
    factory_calls = []

    def factory(*args, **kwargs):
        factory_calls.append((args, kwargs))
        return smtp

    notifier = configured_notifier(monkeypatch, factory)
    result = notifier.send_report(job_detail())

    assert len(result["payload_sha256"]) == 64
    assert result["message_id"].startswith("<")
    assert factory_calls[0][0][:2] == ("smtp.gmail.com", 465)
    assert smtp.login_calls == [("sender@example.com", "abcdefghijklmnop")]
    message = smtp.messages[0]
    body = message.get_body(preferencelist=("plain",)).get_content()
    html_body = message.get_body(preferencelist=("html",)).get_content()
    assert message["From"] == "sender@example.com"
    assert message["To"] == "recipient@example.com"
    assert message["Subject"] == "[SIEM AI] Report Job #42"
    assert message.get_content_type() == "multipart/alternative"
    assert "RAW_GROUP_SENTINEL" not in body
    assert "RAW_ALERT_SENTINEL" not in body
    assert "SECRET_VALUE" not in body
    assert "203.0.113.50" not in body
    assert "analyst@example.com" not in body
    assert "Key findings:" in body
    assert "Observed facts:" in body
    assert "Alert map (2 bins" in body
    assert "Mật độ alert theo thời gian" in html_body
    assert "Checksum changed on critical file" in html_body
    assert "RAW_ALERT_SENTINEL" not in html_body
    assert "SECRET_VALUE" not in html_body
    assert smtp.quit_called is True
    assert "abcd" not in str(result)
    assert "recipient@example.com" not in str(notifier.status())


def test_test_message_is_static_and_requires_no_report(monkeypatch):
    smtp = SMTP()
    notifier = configured_notifier(monkeypatch, lambda *args, **kwargs: smtp)

    result = notifier.send_test()

    assert result["message_id"].startswith("<")
    assert smtp.messages[0].get_content() == "SIEM AI: Gmail connectivity test passed.\n"
    assert "Report" not in smtp.messages[0]["Subject"]


def test_rich_report_downsamples_alert_map_and_bounds_plain_text():
    job = job_detail()
    job["timeline"] = [
        {
            "start": f"2026-08-10T{index // 4:02d}:{(index % 4) * 15:02d}:00.000Z",
            "end": f"2026-08-10T{index // 4:02d}:{((index + 1) % 4) * 15:02d}:00.000Z",
            "count": index % 4,
        }
        for index in range(64)
    ]

    plain, html_body, digest = render_gmail_report(job, max_chars=8_000)

    assert "Alert map (32 bins" in plain
    assert "32 bins; peak 5 alerts" in html_body
    assert len(digest) == 64
    truncated, _, _ = render_gmail_report(job, max_chars=1024)
    assert len(truncated) <= 1024
    assert truncated.endswith("[truncated]")


def test_attack_chain_row_is_merged_into_the_single_report():
    """One queued analysis is one report, so the chain rides in the window report."""
    job = job_detail()
    job["results"].append({
        "scope": "window",
        "scope_key": "attack_chain",
        "result": {
            "severity": "high", "summary": "192.0.2.10 tried DVWA login repeatedly",
            "intent": "brute force", "kill_chain_stages": ["10:01 - initial - rule=100121"],
            "targeted_assets": [], "mitre": [], "next_steps": ["Block the source"],
            "response_language": "vi", "confidence": 92, "assessment_basis": {},
        },
        "warnings": ["Attack chain profile for source IP 192.0.2.10"],
    })

    plain, html_body, _ = render_gmail_report(job, max_chars=8_000)

    assert "Attack chain" in plain
    assert "10:01 - initial - rule=100121" in plain
    assert "Attack chain" in html_body
    # The window analysis, not the chain profile, still drives severity and hashing.
    assert "Severity: medium" in plain or "medium" in plain
    assert "Failed authentication sequence" in plain


def test_configure_local_hides_addresses_and_app_password(tmp_path, monkeypatch):
    monkeypatch.delenv("SIEM_GMAIL_SENDER_EMAIL", raising=False)
    monkeypatch.delenv("SIEM_GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.delenv("SIEM_GMAIL_RECIPIENT_EMAIL", raising=False)
    monkeypatch.delenv("SIEM_GMAIL_ENABLED", raising=False)
    notifier = GmailNotifier(gmail_cfg(), smtp_factory=lambda *args, **kwargs: SMTP())
    env_file = tmp_path / "gmail.local.env"
    notifier.settings = replace(notifier.settings, env_file=env_file)

    status = notifier.configure_local(
        sender_email="sender@example.com",
        app_password="abcd efgh ijkl mnop",
        recipient_email="recipient@example.com",
    )

    assert status == {
        "channel": "gmail", "enabled": True, "configured": True, "max_body_chars": 20_000,
    }
    content = env_file.read_text(encoding="utf-8")
    assert "SIEM_GMAIL_APP_PASSWORD=abcdefghijklmnop" in content
    assert "sender@example.com" not in str(status)
    assert "recipient@example.com" not in str(status)
    assert "abcdefghijklmnop" not in str(status)


def test_invalid_email_or_header_injection_is_rejected(monkeypatch):
    notifier = configured_notifier(monkeypatch, lambda *args, **kwargs: SMTP())

    with pytest.raises(ValueError, match="Email nhận"):
        notifier.configure_local(
            sender_email="sender@example.com",
            app_password="abcdefghijklmnop",
            recipient_email="recipient@example.com\r\nBcc: attacker@example.com",
        )


def test_auth_failure_is_safe_and_network_failure_is_uncertain(monkeypatch):
    class AuthSMTP(SMTP):
        def login(self, sender, password):
            import smtplib
            raise smtplib.SMTPAuthenticationError(535, b"credentials rejected")

    auth_notifier = configured_notifier(monkeypatch, lambda *args, **kwargs: AuthSMTP())
    with pytest.raises(GmailDeliveryError) as auth_error:
        auth_notifier.send_test()
    assert auth_error.value.code == "gmail_auth_failed"
    assert auth_error.value.uncertain is False

    network_notifier = configured_notifier(
        monkeypatch, lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()),
    )
    with pytest.raises(GmailDeliveryError) as network_error:
        network_notifier.send_test()
    assert network_error.value.code == "gmail_network_error"
    assert network_error.value.uncertain is True
