"""Safe, opt-in Telegram delivery for local SOC reports.

The notifier deliberately keeps credentials out of YAML, SQLite, HTTP responses,
and logs. It accepts a job detail object and sends one PDF document whose caption
contains the redacted summary. Keeping the caption and document in one provider
request prevents a successful summary from being separated from a failed upload.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


TELEGRAM_CHANNEL = "telegram"
DEFAULT_TOKEN_ENV = "SIEM_TELEGRAM_BOT_TOKEN"
DEFAULT_CHAT_ID_ENV = "SIEM_TELEGRAM_CHAT_ID"
DEFAULT_ENV_FILE = Path(__file__).with_name("telegram.local.env")
DEFAULT_MAX_MESSAGE_CHARS = 3500
TELEGRAM_MAX_MESSAGE_CHARS = 4096
TELEGRAM_MAX_CAPTION_CHARS = 1024
DEFAULT_MAX_REPORT_CHARS = 20_000

_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SECRET_RE = re.compile(
    r"(?i)\b(api[_ -]?key|authorization|bearer|password|passwd|secret|token|cookie|session(?:[_ -]?id)?)\b"
    r"(?:\s*[:=]\s*|\s+(?:is\s+)?)(?:bearer\s+)?[^,\s;]+"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class TelegramConfigurationError(ValueError):
    """Raised when the local Telegram configuration is incomplete or unsafe."""


class TelegramDeliveryError(RuntimeError):
    """Provider error with a safe code and an ambiguity marker for retry policy."""

    def __init__(self, code: str, *, uncertain: bool = False):
        self.code = str(code)[:80]
        self.uncertain = bool(uncertain)
        super().__init__(self.code)


@dataclass(frozen=True)
class TelegramSettings:
    enabled: bool = False
    token_env: str = DEFAULT_TOKEN_ENV
    chat_id_env: str = DEFAULT_CHAT_ID_ENV
    env_file: Path = DEFAULT_ENV_FILE
    max_message_chars: int = DEFAULT_MAX_MESSAGE_CHARS
    timeout_seconds: int = 15


def load_env_file(path: str | Path) -> dict[str, str]:
    """Read a tiny ``KEY=VALUE`` file without expanding variables or logging data."""

    candidate = Path(path)
    if not candidate.exists():
        return {}
    if not candidate.is_file():
        raise TelegramConfigurationError("Telegram env_file phải là file")
    try:
        if candidate.stat().st_size > 16 * 1024:
            raise TelegramConfigurationError("Telegram env_file vượt quá 16 KiB")
        lines = candidate.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TelegramConfigurationError("Không đọc được Telegram env_file") from exc

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise TelegramConfigurationError(f"Telegram env_file có dòng lỗi {line_number}")
        key, value = (part.strip() for part in line.split("=", 1))
        if not _KEY_RE.fullmatch(key):
            raise TelegramConfigurationError(f"Telegram env_file có key lỗi ở dòng {line_number}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


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
            raise TelegramConfigurationError("Telegram env_file phải nằm trong ai_module")
        return resolved
    except OSError as exc:
        raise TelegramConfigurationError("Telegram env_file không hợp lệ") from exc


def _env_name(value: Any, default: str) -> str:
    name = str(value or default).strip()
    if not _KEY_RE.fullmatch(name):
        raise TelegramConfigurationError("Tên biến môi trường Telegram không hợp lệ")
    return name


def _validate_bot_token(value: Any) -> str:
    if not isinstance(value, str):
        raise TelegramConfigurationError("Telegram bot token phải là text")
    token = value.strip()
    if not token or any(char.isspace() for char in token) or len(token) > 256:
        raise TelegramConfigurationError("Thiếu Telegram bot token hợp lệ")
    return token


def _validate_chat_id(value: Any) -> str:
    if not isinstance(value, str):
        raise TelegramConfigurationError("Telegram chat ID phải là text")
    chat_id = value.strip()
    if not re.fullmatch(r"-?\d{1,20}", chat_id):
        raise TelegramConfigurationError("Thiếu Telegram chat ID dạng số")
    return chat_id


def settings_from_config(cfg: dict[str, Any] | None) -> TelegramSettings:
    cfg = cfg if isinstance(cfg, dict) else {}
    notifications = cfg.get("notifications", {})
    if notifications in (None, {}):
        notifications = {}
    if not isinstance(notifications, dict):
        raise TelegramConfigurationError("notifications config phải là object")
    telegram = notifications.get("telegram", {})
    if telegram in (None, {}):
        telegram = {}
    if not isinstance(telegram, dict):
        raise TelegramConfigurationError("notifications.telegram phải là object")

    enabled = telegram.get("enabled", False)
    if not isinstance(enabled, bool):
        raise TelegramConfigurationError("notifications.telegram.enabled phải là boolean")
    max_chars = telegram.get("max_message_chars", DEFAULT_MAX_MESSAGE_CHARS)
    if isinstance(max_chars, bool) or not isinstance(max_chars, int):
        raise TelegramConfigurationError("Telegram max_message_chars phải là số nguyên")
    if not 256 <= max_chars <= TELEGRAM_MAX_MESSAGE_CHARS:
        raise TelegramConfigurationError("Telegram max_message_chars phải nằm trong 256..4096")
    timeout = telegram.get("timeout_seconds", 15)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 3 <= timeout <= 60:
        raise TelegramConfigurationError("Telegram timeout_seconds phải nằm trong 3..60")
    token_env = _env_name(telegram.get("token_env"), DEFAULT_TOKEN_ENV)
    chat_id_env = _env_name(telegram.get("chat_id_env"), DEFAULT_CHAT_ID_ENV)
    if len({token_env, chat_id_env, "SIEM_TELEGRAM_ENABLED"}) != 3:
        raise TelegramConfigurationError("Tên biến môi trường Telegram bị trùng")
    return TelegramSettings(
        enabled=enabled,
        token_env=token_env,
        chat_id_env=chat_id_env,
        env_file=_resolve_env_file(telegram.get("env_file")),
        max_message_chars=max_chars,
        timeout_seconds=timeout,
    )


def _safe_text(value: Any, limit: int) -> str:
    if not isinstance(value, (str, int, float, bool)):
        return ""
    text = _CONTROL_RE.sub(" ", str(value))
    text = " ".join(text.split())
    text = _SECRET_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    text = _IPV4_RE.sub("[ip]", text)
    text = _IPV6_CANDIDATE_RE.sub(_redact_ipv6, text)
    text = _EMAIL_RE.sub("[email]", text)
    return text[:limit]


def _redact_ipv6(match: re.Match[str]) -> str:
    """Redact only valid IPv6 candidates, leaving normal timestamps untouched."""

    try:
        return "[ip]" if ipaddress.ip_address(match.group()).version == 6 else match.group()
    except ValueError:
        return match.group()


def _analysis_from_job(job: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    results = job.get("results") if isinstance(job, dict) else None
    if not isinstance(results, list):
        return {}, []
    windows = [row for row in results if isinstance(row, dict) and row.get("scope") == "window"]
    if not windows:
        return {}, []
    latest = windows[-1]
    analysis = latest.get("result")
    if not isinstance(analysis, dict):
        analysis = {}
    warnings = latest.get("warnings")
    if not isinstance(warnings, list):
        warnings = []
    return analysis, [item for item in warnings if isinstance(item, (str, int, float, bool))]


def _safe_count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return 0
    return max(0, int(value))


def render_summary_report(job: dict[str, Any], *, max_chars: int = DEFAULT_MAX_MESSAGE_CHARS) -> tuple[str, str]:
    """Render the concise Telegram summary that accompanies the full PDF."""

    if not isinstance(job, dict):
        raise TelegramConfigurationError("Telegram report phải là object")
    if (
        isinstance(max_chars, bool)
        or not isinstance(max_chars, int)
        or not 256 <= max_chars <= TELEGRAM_MAX_MESSAGE_CHARS
    ):
        raise TelegramConfigurationError("Telegram summary max_chars phải nằm trong 256..4096")
    analysis, warnings = _analysis_from_job(job)
    metrics = job.get("metrics") if isinstance(job.get("metrics"), dict) else {}
    severity = _safe_text(analysis.get("severity", "unknown"), 32) or "unknown"
    confidence = analysis.get("confidence")
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        confidence_text = f"{confidence:.2f}"
    else:
        confidence_text = "unknown"
    status = _safe_text(job.get("status", "unknown"), 32) or "unknown"
    job_id = _safe_text(job.get("id", "?"), 32)
    window_start = _safe_text(job.get("window_start", ""), 64)
    window_end = _safe_text(job.get("window_end", ""), 64)
    model = _safe_text(job.get("model", ""), 96)
    language = _safe_text(job.get("language", "vi"), 16)
    total_alerts = _safe_count(metrics.get("total_alerts", job.get("progress_total", 0)))
    lines = [
        f"SIEM AI REPORT | Job #{job_id}",
        f"Status: {status} | Severity: {severity} | Confidence: {confidence_text}",
        f"Window: {window_start} -> {window_end}",
        f"Alerts: {total_alerts} | Model: {model} | Language: {language}",
    ]
    groups = job.get("groups") if isinstance(job.get("groups"), list) else []
    rule_totals: dict[str, tuple[int, int]] = {}
    for group in groups:
        if not isinstance(group, dict):
            continue
        rule_id = _safe_text(group.get("rule_id", ""), 32)
        if not rule_id:
            continue
        count_value = _safe_count(group.get("count", 0))
        level_value = _safe_count(group.get("max_level", 0))
        previous_count, previous_level = rule_totals.get(rule_id, (0, 0))
        rule_totals[rule_id] = (previous_count + count_value, max(previous_level, level_value))
    top_rules = sorted(rule_totals.items(), key=lambda item: (-item[1][0], item[0]))[:7]
    if top_rules:
        lines.append("Top rules:\n" + "\n".join(
            f"- {rule_id}: {count} alerts (max level {level})"
            for rule_id, (count, level) in top_rules
        ))
    summary = _safe_text(analysis.get("summary", ""), 1800)
    if summary:
        lines.append(f"Summary: {summary}")
    next_steps = analysis.get("next_steps")
    if isinstance(next_steps, list):
        steps = [_safe_text(item, 400) for item in next_steps[:4]]
        steps = [item for item in steps if item]
        if steps:
            lines.append("Next steps:\n" + "\n".join(f"- {item}" for item in steps))
    safe_warnings = [_safe_text(item, 300) for item in warnings[:5]]
    safe_warnings = [item for item in safe_warnings if item]
    if safe_warnings:
        lines.append("Warnings:\n" + "\n".join(f"- {item}" for item in safe_warnings))
    analysis_hash = analysis_sha256(analysis) or "unknown"
    lines.append(f"Analysis SHA256: {analysis_hash}")
    text = "\n\n".join(lines)
    if len(text) > max_chars:
        text = text[: max_chars - 28].rstrip() + "\n[truncated]"
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_report(job: dict[str, Any], *, max_chars: int = DEFAULT_MAX_REPORT_CHARS) -> tuple[str, str]:
    """Render the rich, allow-listed plain-text report and its content hash.

    Gmail owns the canonical rich text layout so both channels contain the same
    analysis sections and Alert map. The import is local to avoid a module-load
    cycle because the Gmail notifier also reuses Telegram's redaction helpers.
    """

    if not isinstance(job, dict):
        raise TelegramConfigurationError("Telegram report phải là object")
    if (
        isinstance(max_chars, bool)
        or not isinstance(max_chars, int)
        or not 256 <= max_chars <= DEFAULT_MAX_REPORT_CHARS
    ):
        raise TelegramConfigurationError("Telegram report max_chars phải nằm trong 256..20000")
    from gmail_notifier import render_gmail_report

    text, _, payload_sha256 = render_gmail_report(job, max_chars=max_chars)
    return text, payload_sha256


def analysis_sha256(analysis: Any) -> str:
    if not isinstance(analysis, dict):
        return ""
    canonical = json.dumps(analysis, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TelegramNotifier:
    """Loopback app adapter for Telegram Bot API; no webhook or inbound listener."""

    def __init__(self, cfg: dict[str, Any] | None = None, *, session=requests):
        self.settings = settings_from_config(cfg)
        self.session = session

    def _values(self) -> dict[str, str]:
        file_values = load_env_file(self.settings.env_file)
        token = os.environ.get(self.settings.token_env, file_values.get(self.settings.token_env, ""))
        chat_id = os.environ.get(self.settings.chat_id_env, file_values.get(self.settings.chat_id_env, ""))
        enabled_override = os.environ.get("SIEM_TELEGRAM_ENABLED", file_values.get("SIEM_TELEGRAM_ENABLED", ""))
        return {"token": token.strip(), "chat_id": chat_id.strip(), "enabled_override": enabled_override.strip().lower()}

    def status(self) -> dict[str, Any]:
        values = self._values()
        enabled = self._enabled(values)
        return {
            "channel": TELEGRAM_CHANNEL,
            "enabled": enabled,
            "configured": bool(values["token"] and values["chat_id"]),
            "max_message_chars": self.settings.max_message_chars,
        }

    def _enabled(self, values: dict[str, str]) -> bool:
        return self.settings.enabled or values["enabled_override"] in {"true", "1", "yes", "on"}

    def _token(self) -> str:
        values = self._values()
        enabled = self._enabled(values)
        if not enabled:
            raise TelegramConfigurationError("Telegram đang tắt trong cấu hình")
        return _validate_bot_token(values["token"])

    def _credentials(self) -> tuple[str, str]:
        token = self._token()
        return token, _validate_chat_id(self._values()["chat_id"])

    def configure_local(self, *, token: Any, chat_id: Any) -> dict[str, Any]:
        """Atomically store local credentials without returning or logging them."""

        token = _validate_bot_token(token)
        chat_id = _validate_chat_id(chat_id)
        target = self.settings.env_file
        content = (
            "# Local-only Telegram credentials. This file is gitignored.\n"
            "SIEM_TELEGRAM_ENABLED=true\n"
            f"{self.settings.token_env}={token}\n"
            f"{self.settings.chat_id_env}={chat_id}\n"
        )
        temporary_name = ""
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".telegram-local-", suffix=".tmp", dir=target.parent,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            try:
                os.chmod(temporary_name, 0o600)
            except OSError:
                # Windows ACLs are inherited; do not fail a local setup because
                # POSIX-style mode bits are unavailable.
                pass
            os.replace(temporary_name, target)
            temporary_name = ""
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise TelegramConfigurationError("Không lưu được Telegram local config") from exc
        finally:
            if temporary_name:
                try:
                    Path(temporary_name).unlink(missing_ok=True)
                except OSError:
                    pass
        return self.status()

    def _post(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        token = self._token()
        url = f"https://api.telegram.org/bot{token}/{method}"
        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=(5, self.settings.timeout_seconds),
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise TelegramDeliveryError("telegram_timeout", uncertain=True) from exc
        except requests.RequestException as exc:
            raise TelegramDeliveryError("telegram_network_error", uncertain=True) from exc
        status = getattr(response, "status_code", 0)
        if status == 429:
            raise TelegramDeliveryError("telegram_rate_limited")
        if status >= 500:
            raise TelegramDeliveryError("telegram_provider_error", uncertain=True)
        if status >= 400:
            raise TelegramDeliveryError(f"telegram_http_{status}")
        try:
            body = response.json()
        except (ValueError, TypeError) as exc:
            raise TelegramDeliveryError("telegram_invalid_response") from exc
        if not isinstance(body, dict) or body.get("ok") is not True:
            code = body.get("error_code", "api_error") if isinstance(body, dict) else "api_error"
            raise TelegramDeliveryError(f"telegram_api_{code}")
        return body

    def _post_document(self, *, chat_id: str, filename: str, caption: str, content: bytes) -> dict[str, Any]:
        token = self._token()
        url = f"https://api.telegram.org/bot{token}/sendDocument"
        try:
            response = self.session.post(
                url,
                data={"chat_id": chat_id, "caption": caption},
                files={"document": (filename, content, "application/pdf")},
                # Uploads can take longer than a small sendMessage request.
                timeout=(5, max(45, self.settings.timeout_seconds)),
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise TelegramDeliveryError("telegram_timeout", uncertain=True) from exc
        except requests.RequestException as exc:
            raise TelegramDeliveryError("telegram_network_error", uncertain=True) from exc
        status = getattr(response, "status_code", 0)
        if status == 429:
            raise TelegramDeliveryError("telegram_rate_limited")
        if status >= 500:
            raise TelegramDeliveryError("telegram_provider_error", uncertain=True)
        if status >= 400:
            raise TelegramDeliveryError(f"telegram_http_{status}")
        try:
            body = response.json()
        except (ValueError, TypeError) as exc:
            raise TelegramDeliveryError("telegram_invalid_response") from exc
        if not isinstance(body, dict) or body.get("ok") is not True:
            code = body.get("error_code", "api_error") if isinstance(body, dict) else "api_error"
            raise TelegramDeliveryError(f"telegram_api_{code}")
        return body

    def discover_chats(self) -> list[dict[str, str]]:
        """Return recent numeric chat IDs after the owner sends the bot ``/start``.

        This is a local setup helper only. It neither stores the result nor
        exposes it through the dashboard API.
        """
        body = self._post("getUpdates", {"limit": 20, "timeout": 0})
        updates = body.get("result") if isinstance(body.get("result"), list) else []
        output = []
        seen = set()
        for update in updates:
            if not isinstance(update, dict):
                continue
            message = update.get("message") or update.get("channel_post")
            chat = message.get("chat") if isinstance(message, dict) else None
            if not isinstance(chat, dict):
                continue
            chat_id = str(chat.get("id", ""))
            if not re.fullmatch(r"-?\d{1,20}", chat_id) or chat_id in seen:
                continue
            seen.add(chat_id)
            output.append({"id": chat_id, "type": _safe_text(chat.get("type", "unknown"), 32)})
        return output

    def send_report(self, job: dict[str, Any]) -> dict[str, Any]:
        _, chat_id = self._credentials()
        summary, _ = render_summary_report(
            job,
            max_chars=min(self.settings.max_message_chars, TELEGRAM_MAX_CAPTION_CHARS),
        )
        try:
            from telegram_pdf import TelegramPDFError, render_pdf_report

            pdf_content = render_pdf_report(job)
        except TelegramPDFError as exc:
            raise TelegramDeliveryError(str(exc)) from exc
        except Exception as exc:
            raise TelegramDeliveryError("telegram_pdf_generation") from exc

        job_id = re.sub(r"[^A-Za-z0-9_-]", "_", _safe_text(job.get("id", "?"), 32) or "unknown")
        payload_sha256 = hashlib.sha256(
            summary.encode("utf-8") + b"\0" + pdf_content,
        ).hexdigest()
        body = self._post_document(
            chat_id=chat_id,
            filename=f"siem-ai-report-job-{job_id}.pdf",
            caption=summary,
            content=pdf_content,
        )
        result = body.get("result") if isinstance(body.get("result"), dict) else {}
        message_id = result.get("message_id")
        return {
            "message_id": str(message_id)[:80] if message_id is not None else "",
            "payload_sha256": payload_sha256,
            "message_count": 1,
        }

    def send_test(self) -> dict[str, Any]:
        _, chat_id = self._credentials()
        body = self._post(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": "SIEM AI: Telegram connectivity test passed.",
                "disable_web_page_preview": True,
            },
        )
        result = body.get("result") if isinstance(body.get("result"), dict) else {}
        message_id = result.get("message_id")
        return {"message_id": str(message_id)[:80] if message_id is not None else ""}
