"""ai_module/blueprints/notifications.py — Notification status, settings and delivery tests."""

from flask import Blueprint, current_app, jsonify

from gmail_notifier import GmailConfigurationError, GmailDeliveryError
from telegram_notifier import TelegramConfigurationError, TelegramDeliveryError
import dashboard


notifications_bp = Blueprint("notifications", __name__)


@notifications_bp.get("/api/notifications/status")
def notification_status():
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    return jsonify({
        "telegram": runtime.telegram_notifier.status(),
        "gmail": runtime.gmail_notifier.status(),
    })


@notifications_bp.post("/api/notifications/telegram/settings")
def telegram_settings():
    dashboard._validate_origin()
    body = dashboard._json_body()
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    if body.get("confirm") is not True:
        raise ValueError("confirm phải là true để lưu cài đặt Telegram")
    try:
        telegram = runtime.telegram_notifier.configure_local(
            token=body.get("bot_token"), chat_id=body.get("chat_id"),
        )
    except TelegramConfigurationError as exc:
        raise ValueError(str(exc)) from exc
    return jsonify({"status": "saved", "telegram": telegram}), 201


@notifications_bp.post("/api/notifications/telegram/test")
def telegram_test():
    dashboard._validate_origin()
    body = dashboard._json_body()
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    if body.get("confirm") is not True:
        raise ValueError("confirm phải là true để gửi test Telegram")
    try:
        result = runtime.telegram_notifier.send_test()
    except TelegramConfigurationError as exc:
        raise ValueError(str(exc)) from exc
    except TelegramDeliveryError as exc:
        return dashboard._error(f"Telegram test failed: {exc.code}", 503 if exc.uncertain else 422)
    return jsonify({"status": "sent", **result}), 202


@notifications_bp.post("/api/notifications/gmail/settings")
def gmail_settings():
    dashboard._validate_origin()
    body = dashboard._json_body()
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    if body.get("confirm") is not True:
        raise ValueError("confirm phải là true để lưu cài đặt Gmail")
    try:
        gmail = runtime.gmail_notifier.configure_local(
            sender_email=body.get("sender_email"),
            app_password=body.get("app_password"),
            recipient_email=body.get("recipient_email"),
        )
    except GmailConfigurationError as exc:
        raise ValueError(str(exc)) from exc
    return jsonify({"status": "saved", "gmail": gmail}), 201


@notifications_bp.post("/api/notifications/gmail/test")
def gmail_test():
    dashboard._validate_origin()
    body = dashboard._json_body()
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    if body.get("confirm") is not True:
        raise ValueError("confirm phải là true để gửi test Gmail")
    try:
        result = runtime.gmail_notifier.send_test()
    except GmailConfigurationError as exc:
        raise ValueError(str(exc)) from exc
    except GmailDeliveryError as exc:
        return dashboard._error(f"Gmail test failed: {exc.code}", 503 if exc.uncertain else 422)
    return jsonify({"status": "sent", **result}), 202
