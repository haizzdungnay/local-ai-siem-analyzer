"""Safe, opt-in Gmail delivery for local SOC reports.

Credentials stay in a local ignored file or the process environment.  Gmail
uses implicit TLS and an App Password; the notifier never exposes credentials,
recipient addresses, or SMTP response text through the dashboard.
"""

from __future__ import annotations

import hashlib
import html
import math
import os
import re
import smtplib
import ssl
import tempfile
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any

from telegram_notifier import _analysis_from_job, _safe_text, analysis_sha256, attack_chain_from_job, load_env_file


GMAIL_CHANNEL = "gmail"
GMAIL_SMTP_HOST = "smtp.gmail.com"
GMAIL_SMTP_PORT = 465
DEFAULT_SENDER_ENV = "SIEM_GMAIL_SENDER_EMAIL"
DEFAULT_PASSWORD_ENV = "SIEM_GMAIL_APP_PASSWORD"
DEFAULT_RECIPIENT_ENV = "SIEM_GMAIL_RECIPIENT_EMAIL"
DEFAULT_ENV_FILE = Path(__file__).with_name("gmail.local.env")
DEFAULT_MAX_BODY_CHARS = 20_000
DEFAULT_SUBJECT_PREFIX = "[SIEM AI]"

_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ADDRESS_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)


class GmailConfigurationError(ValueError):
    """Raised when local Gmail settings are incomplete or unsafe."""


class GmailDeliveryError(RuntimeError):
    """Provider error with a safe code and an ambiguity marker for retry policy."""

    def __init__(self, code: str, *, uncertain: bool = False):
        self.code = str(code)[:80]
        self.uncertain = bool(uncertain)
        super().__init__(self.code)


@dataclass(frozen=True)
class GmailSettings:
    enabled: bool = False
    sender_email_env: str = DEFAULT_SENDER_ENV
    app_password_env: str = DEFAULT_PASSWORD_ENV
    recipient_email_env: str = DEFAULT_RECIPIENT_ENV
    env_file: Path = DEFAULT_ENV_FILE
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS
    timeout_seconds: int = 15
    subject_prefix: str = DEFAULT_SUBJECT_PREFIX


def _resolve_env_file(value: Any) -> Path:
    if value in (None, ""):
        return DEFAULT_ENV_FILE
    candidate = Path(str(value))
    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parent / candidate
    try:
        resolved = candidate.resolve()
        module_dir = Path(__file__).resolve().parent
        if not resolved.is_relative_to(module_dir):
            raise GmailConfigurationError("Gmail env_file phải nằm trong ai_module")
        return resolved
    except OSError as exc:
        raise GmailConfigurationError("Gmail env_file không hợp lệ") from exc


def _env_name(value: Any, default: str) -> str:
    name = str(value or default).strip()
    if not _KEY_RE.fullmatch(name):
        raise GmailConfigurationError("Tên biến môi trường Gmail không hợp lệ")
    return name


def _validate_email(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise GmailConfigurationError(f"{label} Gmail phải là text")
    address = value.strip()
    if (
        not address
        or len(address) > 254
        or any(char in address for char in "\r\n,;\0")
        or any(char.isspace() for char in address)
        or not _ADDRESS_RE.fullmatch(address)
    ):
        raise GmailConfigurationError(f"{label} Gmail không hợp lệ")
    return address


def _validate_app_password(value: Any) -> str:
    if not isinstance(value, str):
        raise GmailConfigurationError("Gmail App Password phải là text")
    if not value or len(value) > 256 or any(char in value for char in "\r\n\0"):
        raise GmailConfigurationError("Thiếu Gmail App Password hợp lệ")
    # Google often displays an App Password in spaced groups; SMTP expects it compact.
    password = "".join(value.split())
    if len(password) < 8 or len(password) > 256:
        raise GmailConfigurationError("Thiếu Gmail App Password hợp lệ")
    return password


def _validate_subject_prefix(value: Any) -> str:
    if not isinstance(value, str):
        raise GmailConfigurationError("Gmail subject_prefix phải là text")
    prefix = value.strip()
    if not prefix or len(prefix) > 80 or any(char in prefix for char in "\r\n\0"):
        raise GmailConfigurationError("Gmail subject_prefix không hợp lệ")
    return prefix


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return 0
    return max(0, int(value))


def _safe_item(value: Any, *, limit: int) -> str:
    if isinstance(value, dict):
        parts = []
        for key in ("id", "technique", "tactic", "name", "description", "value"):
            item = value.get(key)
            text = _safe_text(item, limit // 2)
            if text:
                parts.append(text)
        return " - ".join(parts)[:limit]
    return _safe_text(value, limit)


def _safe_items(value: Any, *, max_items: int, item_limit: int) -> list[str]:
    values = value if isinstance(value, list) else [value]
    output = []
    for item in values[:max_items]:
        text = _safe_item(item, limit=item_limit)
        if text:
            output.append(text)
    return output


def _safe_timeline(job: dict[str, Any], *, max_buckets: int = 48) -> list[dict[str, Any]]:
    raw_timeline = job.get("timeline") if isinstance(job.get("timeline"), list) else []
    buckets = []
    for item in raw_timeline:
        if not isinstance(item, dict):
            continue
        start = _safe_text(item.get("start", ""), 64)
        end = _safe_text(item.get("end", ""), 64)
        if not start or not end:
            continue
        buckets.append({"start": start, "end": end, "count": _count(item.get("count", 0))})
    if len(buckets) <= max_buckets:
        return buckets
    group_size = math.ceil(len(buckets) / max_buckets)
    return [
        {
            "start": group[0]["start"],
            "end": group[-1]["end"],
            "count": sum(item["count"] for item in group),
        }
        for group in (buckets[index:index + group_size] for index in range(0, len(buckets), group_size))
        if group
    ]


def _timeline_label(bucket: dict[str, Any]) -> str:
    start = bucket["start"].replace("T", " ")[:16]
    end = bucket["end"].replace("T", " ")[:16]
    return f"{start} -> {end}"


def _timeline_plain(timeline: list[dict[str, Any]]) -> list[str]:
    if not timeline:
        return []
    maximum = max((bucket["count"] for bucket in timeline), default=0)
    lines = [f"Alert map ({len(timeline)} bins; peak {maximum} alerts):"]
    for bucket in timeline:
        count = bucket["count"]
        width = 0 if not maximum else max(1 if count else 0, round(count / maximum * 24))
        lines.append(f"- {_timeline_label(bucket)} | {count:>3} | {'#' * width}")
    return lines


def _html_text(value: str) -> str:
    return html.escape(value, quote=True).replace("\n", "<br>")


def _html_list(title: str, items: list[str]) -> str:
    if not items:
        return ""
    rows = "".join(f"<li style=\"margin:0 0 6px\">{_html_text(item)}</li>" for item in items)
    return f"<h2 style=\"font-size:16px;margin:24px 0 8px\">{_html_text(title)}</h2><ul style=\"padding-left:20px;margin:0\">{rows}</ul>"


def _html_alert_map(timeline: list[dict[str, Any]]) -> str:
    if not timeline:
        return ""
    maximum = max((bucket["count"] for bucket in timeline), default=0)
    width = 100 / len(timeline)
    bars = []
    for bucket in timeline:
        count = bucket["count"]
        height = 2 if not maximum else max(3 if count else 1, round(count / maximum * 96))
        label = _timeline_label(bucket)
        bars.append(
            "<td style=\"width:{width:.3f}%;height:112px;padding:0 1px;vertical-align:bottom\">"
            "<div title=\"{label}: {count} alerts\" style=\"height:{height}px;background:#12836d;"
            "border-radius:2px 2px 0 0;min-height:1px\"></div></td>".format(
                width=width, label=_html_text(label), count=count, height=height,
            )
        )
    detail_rows = "".join(
        "<tr><td style=\"padding:5px 8px;border-top:1px solid #d8e1de\">{label}</td>"
        "<td style=\"padding:5px 8px;border-top:1px solid #d8e1de;text-align:right\">{count}</td></tr>".format(
            label=_html_text(_timeline_label(bucket)), count=bucket["count"],
        )
        for bucket in timeline
        if bucket["count"]
    ) or "<tr><td colspan=\"2\" style=\"padding:5px 8px\">No alerts in this window.</td></tr>"
    return (
        "<h2 style=\"font-size:16px;margin:24px 0 8px\">Alert map / Mật độ alert theo thời gian</h2>"
        f"<p style=\"margin:0 0 10px;color:#52615d\">{len(timeline)} bins; peak {maximum} alerts.</p>"
        "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;background:#eef5f2\"><tr>"
        + "".join(bars)
        + "</tr></table>"
        f"<p style=\"font-size:12px;color:#52615d;margin:6px 0 12px\">{_html_text(_timeline_label(timeline[0]))} to {_html_text(_timeline_label(timeline[-1]))}</p>"
        "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:13px\">"
        "<thead><tr><th style=\"text-align:left;padding:5px 8px\">Time window</th>"
        "<th style=\"text-align:right;padding:5px 8px\">Alerts</th></tr></thead><tbody>"
        + detail_rows
        + "</tbody></table>"
    )


def render_gmail_report(job: dict[str, Any], *, max_chars: int = DEFAULT_MAX_BODY_CHARS) -> tuple[str, str, str]:
    """Render a rich but allow-listed text/HTML report plus a stable body hash."""

    if not isinstance(job, dict):
        raise GmailConfigurationError("Gmail report phải là object")
    analysis, warnings = _analysis_from_job(job)
    metrics = job.get("metrics") if isinstance(job.get("metrics"), dict) else {}
    severity = _safe_text(analysis.get("severity", "unknown"), 32) or "unknown"
    status = _safe_text(job.get("status", "unknown"), 32) or "unknown"
    window_start = _safe_text(job.get("window_start", ""), 64)
    window_end = _safe_text(job.get("window_end", ""), 64)
    model = _safe_text(job.get("model", ""), 96)
    language = _safe_text(job.get("language", "vi"), 16)
    confidence = analysis.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence):
        confidence_text = _safe_text(confidence, 32)
    else:
        confidence_text = f"{confidence:.2f}"
    total_alerts = _count(metrics.get("total_alerts", job.get("progress_total", 0)))
    summary = _safe_text(analysis.get("summary", ""), 1800)
    root_cause = _safe_text(analysis.get("root_cause", ""), 1200)
    key_findings = _safe_items(analysis.get("key_findings"), max_items=12, item_limit=500)
    mitre = _safe_items(analysis.get("mitre"), max_items=12, item_limit=300)
    next_steps = _safe_items(analysis.get("next_steps"), max_items=12, item_limit=400)
    basis = analysis.get("assessment_basis") if isinstance(analysis.get("assessment_basis"), dict) else {}
    observed = _safe_items(basis.get("observed_facts"), max_items=12, item_limit=400)
    inferences = _safe_items(basis.get("inferences"), max_items=12, item_limit=400)
    uncertainties = _safe_items(basis.get("uncertainties"), max_items=12, item_limit=400)
    limitations = _safe_items(basis.get("limitations"), max_items=12, item_limit=400)
    safe_warnings = _safe_items(warnings, max_items=12, item_limit=400)
    chain = attack_chain_from_job(job)
    chain_items = []
    chain_summary = _safe_text(chain.get("summary", ""), 1200)
    chain_intent = _safe_text(chain.get("intent", ""), 400)
    if chain_summary:
        chain_items.append(f"{chain_summary} ({chain_intent})" if chain_intent else chain_summary)
    chain_items.extend(_safe_items(chain.get("kill_chain_stages"), max_items=12, item_limit=400))
    rule_totals: dict[str, tuple[int, int]] = {}
    groups = job.get("groups") if isinstance(job.get("groups"), list) else []
    for group in groups:
        if not isinstance(group, dict):
            continue
        rule_id = _safe_text(group.get("rule_id", ""), 32)
        if not rule_id:
            continue
        current_count, current_level = rule_totals.get(rule_id, (0, 0))
        rule_totals[rule_id] = (
            current_count + _count(group.get("count", 0)),
            max(current_level, _count(group.get("max_level", 0))),
        )
    rule_rows = [
        (rule_id, count, level)
        for rule_id, (count, level) in sorted(
            rule_totals.items(), key=lambda item: (-item[1][0], item[0]),
        )[:12]
    ]
    timeline = _safe_timeline(job, max_buckets=48 if max_chars >= 6000 else 16)
    analysis_hash = analysis_sha256(analysis) or "unknown"
    metric_rows = [
        ("Alerts", str(total_alerts)),
        ("Groups", str(_count(metrics.get("total_groups", len(groups))))),
        ("Unique rules", str(_count(metrics.get("unique_rules", 0)))),
        ("Unique agents", str(_count(metrics.get("unique_agents", 0)))),
        ("Max level", str(_count(metrics.get("max_level", 0)))),
    ]

    plain_lines = [
        f"SIEM AI REPORT | Job #{GmailNotifier._job_id(job)}",
        f"Status: {status} | Severity: {severity}" + (f" | Confidence: {confidence_text}" if confidence_text else ""),
        f"Window: {window_start} -> {window_end}",
        f"Alerts: {total_alerts} | Model: {model} | Language: {language}",
        "Metrics: " + " | ".join(f"{label}={value}" for label, value in metric_rows[1:]),
    ]
    if rule_rows:
        plain_lines.append("Top rules:\n" + "\n".join(
            f"- {rule_id}: {count} alerts (max level {level})"
            for rule_id, count, level in rule_rows
        ))
    for title, value in (("Summary", summary), ("Root cause", root_cause)):
        if value:
            plain_lines.append(f"{title}: {value}")
    for title, values in (
        ("Key findings", key_findings), ("Attack chain", chain_items), ("MITRE", mitre), ("Next steps", next_steps),
        ("Observed facts", observed), ("Inferences", inferences),
        ("Uncertainties", uncertainties), ("Limitations", limitations), ("Warnings", safe_warnings),
    ):
        if values:
            plain_lines.append(f"{title}:\n" + "\n".join(f"- {value}" for value in values))
    plain_lines.extend(_timeline_plain(timeline))
    plain_lines.append(f"Analysis SHA256: {analysis_hash}")
    plain_text = "\n\n".join(plain_lines)
    if len(plain_text) > max_chars:
        plain_text = plain_text[: max_chars - 28].rstrip() + "\n[truncated]"

    summary_rows = "".join(
        "<tr><th style=\"padding:5px 8px;text-align:left;background:#edf3f0\">{label}</th>"
        "<td style=\"padding:5px 8px\">{value}</td></tr>".format(
            label=_html_text(label), value=_html_text(value),
        )
        for label, value in [
            ("Status", status), ("Severity", severity), ("Confidence", confidence_text or "unknown"),
            ("Window", f"{window_start} -> {window_end}"), ("Model", model), ("Language", language),
            *metric_rows,
        ]
    )
    rule_html = ""
    if rule_rows:
        rule_html = (
            "<h2 style=\"font-size:16px;margin:24px 0 8px\">Top rules</h2>"
            "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:13px\">"
            "<thead><tr><th style=\"text-align:left;padding:5px 8px\">Rule</th>"
            "<th style=\"text-align:right;padding:5px 8px\">Alerts</th>"
            "<th style=\"text-align:right;padding:5px 8px\">Max level</th></tr></thead><tbody>"
            + "".join(
                "<tr><td style=\"padding:5px 8px;border-top:1px solid #d8e1de\">{rule}</td>"
                "<td style=\"padding:5px 8px;border-top:1px solid #d8e1de;text-align:right\">{count}</td>"
                "<td style=\"padding:5px 8px;border-top:1px solid #d8e1de;text-align:right\">{level}</td></tr>".format(
                    rule=_html_text(rule_id), count=count, level=level,
                )
                for rule_id, count, level in rule_rows
            )
            + "</tbody></table>"
        )
    html_body = (
        "<!doctype html><html><body style=\"margin:0;background:#f4f7f5;color:#17211d;"
        "font-family:Segoe UI,Arial,sans-serif;line-height:1.45\"><main style=\"max-width:760px;"
        "margin:0 auto;padding:24px\"><section style=\"background:#fff;border:1px solid #d8e1de;"
        "border-radius:12px;padding:24px\"><p style=\"margin:0;color:#12836d;font-size:12px;"
        "font-weight:700;letter-spacing:.08em\">SIEM AI ANALYST</p>"
        f"<h1 style=\"font-size:24px;margin:6px 0 18px\">Report Job #{GmailNotifier._job_id(job)}</h1>"
        "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px\"><tbody>"
        + summary_rows
        + "</tbody></table>"
        + (f"<h2 style=\"font-size:16px;margin:24px 0 8px\">Summary</h2><p style=\"margin:0\">{_html_text(summary)}</p>" if summary else "")
        + (f"<h2 style=\"font-size:16px;margin:24px 0 8px\">Root cause</h2><p style=\"margin:0\">{_html_text(root_cause)}</p>" if root_cause else "")
        + rule_html
        + _html_list("Key findings", key_findings)
        + _html_list("Attack chain", chain_items)
        + _html_list("MITRE", mitre)
        + _html_list("Next steps", next_steps)
        + _html_alert_map(timeline)
        + _html_list("Observed facts", observed)
        + _html_list("Inferences", inferences)
        + _html_list("Uncertainties", uncertainties)
        + _html_list("Limitations", limitations)
        + _html_list("Warnings", safe_warnings)
        + f"<p style=\"margin:24px 0 0;font-size:12px;color:#52615d\">Analysis SHA256: {_html_text(analysis_hash)}</p>"
        + "</section></main></body></html>"
    )
    return plain_text, html_body, hashlib.sha256(plain_text.encode("utf-8")).hexdigest()


def settings_from_config(cfg: dict[str, Any] | None) -> GmailSettings:
    cfg = cfg if isinstance(cfg, dict) else {}
    notifications = cfg.get("notifications", {})
    if notifications in (None, {}):
        notifications = {}
    if not isinstance(notifications, dict):
        raise GmailConfigurationError("notifications config phải là object")
    gmail = notifications.get("gmail", {})
    if gmail in (None, {}):
        gmail = {}
    if not isinstance(gmail, dict):
        raise GmailConfigurationError("notifications.gmail phải là object")

    enabled = gmail.get("enabled", False)
    if not isinstance(enabled, bool):
        raise GmailConfigurationError("notifications.gmail.enabled phải là boolean")
    max_chars = gmail.get("max_body_chars", DEFAULT_MAX_BODY_CHARS)
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or not 1024 <= max_chars <= 20_000:
        raise GmailConfigurationError("Gmail max_body_chars phải nằm trong 1024..20000")
    timeout = gmail.get("timeout_seconds", 15)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 3 <= timeout <= 60:
        raise GmailConfigurationError("Gmail timeout_seconds phải nằm trong 3..60")
    sender_env = _env_name(gmail.get("sender_email_env"), DEFAULT_SENDER_ENV)
    password_env = _env_name(gmail.get("app_password_env"), DEFAULT_PASSWORD_ENV)
    recipient_env = _env_name(gmail.get("recipient_email_env"), DEFAULT_RECIPIENT_ENV)
    if len({sender_env, password_env, recipient_env, "SIEM_GMAIL_ENABLED"}) != 4:
        raise GmailConfigurationError("Tên biến môi trường Gmail bị trùng")
    return GmailSettings(
        enabled=enabled,
        sender_email_env=sender_env,
        app_password_env=password_env,
        recipient_email_env=recipient_env,
        env_file=_resolve_env_file(gmail.get("env_file")),
        max_body_chars=max_chars,
        timeout_seconds=timeout,
        subject_prefix=_validate_subject_prefix(gmail.get("subject_prefix", DEFAULT_SUBJECT_PREFIX)),
    )


class GmailNotifier:
    """Gmail SMTP adapter with no inbound listener and no credential persistence in SQLite."""

    def __init__(self, cfg: dict[str, Any] | None = None, *, smtp_factory=smtplib.SMTP_SSL):
        self.settings = settings_from_config(cfg)
        self.smtp_factory = smtp_factory

    def _values(self) -> dict[str, str]:
        try:
            file_values = load_env_file(self.settings.env_file)
        except Exception as exc:
            raise GmailConfigurationError("Không đọc được Gmail env_file") from exc
        sender = os.environ.get(
            self.settings.sender_email_env, file_values.get(self.settings.sender_email_env, ""),
        )
        password = os.environ.get(
            self.settings.app_password_env, file_values.get(self.settings.app_password_env, ""),
        )
        recipient = os.environ.get(
            self.settings.recipient_email_env, file_values.get(self.settings.recipient_email_env, ""),
        )
        enabled_override = os.environ.get(
            "SIEM_GMAIL_ENABLED", file_values.get("SIEM_GMAIL_ENABLED", ""),
        )
        return {
            "sender": sender.strip(),
            "password": password,
            "recipient": recipient.strip(),
            "enabled_override": enabled_override.strip().lower(),
        }

    def _enabled(self, values: dict[str, str]) -> bool:
        return self.settings.enabled or values["enabled_override"] in {"true", "1", "yes", "on"}

    def _credentials(self) -> tuple[str, str, str]:
        values = self._values()
        if not self._enabled(values):
            raise GmailConfigurationError("Gmail đang tắt trong cấu hình")
        return (
            _validate_email(values["sender"], "Email gửi"),
            _validate_app_password(values["password"]),
            _validate_email(values["recipient"], "Email nhận"),
        )

    def status(self) -> dict[str, Any]:
        try:
            values = self._values()
            enabled = self._enabled(values)
            if enabled:
                _validate_email(values["sender"], "Email gửi")
                _validate_app_password(values["password"])
                _validate_email(values["recipient"], "Email nhận")
                configured = True
            else:
                configured = bool(values["sender"] and values["password"] and values["recipient"])
        except GmailConfigurationError:
            enabled = False
            configured = False
        return {
            "channel": GMAIL_CHANNEL,
            "enabled": enabled,
            "configured": configured,
            "max_body_chars": self.settings.max_body_chars,
        }

    def configure_local(
        self, *, sender_email: Any, app_password: Any, recipient_email: Any,
    ) -> dict[str, Any]:
        """Atomically store local Gmail settings without reflecting them back."""

        sender = _validate_email(sender_email, "Email gửi")
        password = _validate_app_password(app_password)
        recipient = _validate_email(recipient_email, "Email nhận")
        target = self.settings.env_file
        content = (
            "# Local-only Gmail settings. This file is gitignored.\n"
            "SIEM_GMAIL_ENABLED=true\n"
            f"{self.settings.sender_email_env}={sender}\n"
            f"{self.settings.app_password_env}={password}\n"
            f"{self.settings.recipient_email_env}={recipient}\n"
        )
        temporary_name = ""
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".gmail-local-", suffix=".tmp", dir=target.parent,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            try:
                os.chmod(temporary_name, 0o600)
            except OSError:
                pass
            os.replace(temporary_name, target)
            temporary_name = ""
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise GmailConfigurationError("Không lưu được Gmail local config") from exc
        finally:
            if temporary_name:
                try:
                    Path(temporary_name).unlink(missing_ok=True)
                except OSError:
                    pass
        return self.status()

    @staticmethod
    def _job_id(job: dict[str, Any]) -> str:
        value = job.get("id", "?") if isinstance(job, dict) else "?"
        return str(value) if isinstance(value, int) or str(value).isdigit() else "?"

    def _message(
        self, *, sender: str, recipient: str, subject: str, body: str, html_body: str = "",
    ) -> EmailMessage:
        message = EmailMessage()
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = subject
        message["Date"] = formatdate(localtime=False)
        message["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[1])
        message.set_content(body, subtype="plain", charset="utf-8")
        if html_body:
            message.add_alternative(html_body, subtype="html", charset="utf-8")
        return message

    @staticmethod
    def _close_client(client) -> None:
        if client is None:
            return
        try:
            client.quit()
        except (OSError, smtplib.SMTPException):
            try:
                client.close()
            except (AttributeError, OSError):
                pass

    def _send_message(self, message: EmailMessage, *, sender: str, password: str) -> str:
        client = None
        try:
            try:
                client = self.smtp_factory(
                    GMAIL_SMTP_HOST,
                    GMAIL_SMTP_PORT,
                    timeout=self.settings.timeout_seconds,
                    context=ssl.create_default_context(),
                )
            except ssl.SSLError as exc:
                raise GmailDeliveryError("gmail_tls_error") from exc
            except (TimeoutError, OSError) as exc:
                raise GmailDeliveryError("gmail_network_error", uncertain=True) from exc
            except smtplib.SMTPException as exc:
                raise GmailDeliveryError("gmail_smtp_error") from exc
            try:
                client.login(sender, password)
            except smtplib.SMTPAuthenticationError as exc:
                raise GmailDeliveryError("gmail_auth_failed") from exc
            except ssl.SSLError as exc:
                raise GmailDeliveryError("gmail_tls_error") from exc
            except (TimeoutError, OSError) as exc:
                raise GmailDeliveryError("gmail_network_error", uncertain=True) from exc
            except smtplib.SMTPException as exc:
                raise GmailDeliveryError("gmail_smtp_error") from exc
            try:
                refused = client.send_message(message)
            except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
                raise GmailDeliveryError("gmail_recipient_refused") from exc
            except ssl.SSLError as exc:
                raise GmailDeliveryError("gmail_tls_error", uncertain=True) from exc
            except (TimeoutError, OSError, smtplib.SMTPServerDisconnected) as exc:
                raise GmailDeliveryError("gmail_network_error", uncertain=True) from exc
            except smtplib.SMTPException as exc:
                # After DATA starts, SMTP cannot prove whether Gmail accepted the message.
                raise GmailDeliveryError("gmail_smtp_error", uncertain=True) from exc
            if refused:
                raise GmailDeliveryError("gmail_recipient_refused")
            return str(message["Message-ID"] or "")[:80]
        finally:
            self._close_client(client)

    def send_report(self, job: dict[str, Any]) -> dict[str, str]:
        try:
            body, html_body, payload_sha256 = render_gmail_report(
                job, max_chars=self.settings.max_body_chars,
            )
        except (TypeError, ValueError) as exc:
            raise GmailConfigurationError("Gmail report không hợp lệ") from exc
        sender, password, recipient = self._credentials()
        message = self._message(
            sender=sender,
            recipient=recipient,
            subject=f"{self.settings.subject_prefix} Report Job #{self._job_id(job)}",
            body=body,
            html_body=html_body,
        )
        return {
            "message_id": self._send_message(message, sender=sender, password=password),
            "payload_sha256": payload_sha256,
        }

    def send_test(self) -> dict[str, str]:
        sender, password, recipient = self._credentials()
        message = self._message(
            sender=sender,
            recipient=recipient,
            subject=f"{self.settings.subject_prefix} Gmail connectivity test",
            body="SIEM AI: Gmail connectivity test passed.",
        )
        return {"message_id": self._send_message(message, sender=sender, password=password)}
