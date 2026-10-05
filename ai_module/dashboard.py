"""Localhost-only Flask dashboard for Wazuh alert AI analysis."""

import atexit
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, current_app, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from analysis_service import ANALYSIS_VERSION, AnalysisService, aggregate_alerts, aggregate_rule_buckets
from dashboard_store import DashboardStore
from dashboard_time import format_utc, utc_now
from dashboard_worker import DashboardRuntime, PRESET_SECONDS
from gmail_notifier import GMAIL_CHANNEL, GmailConfigurationError, GmailDeliveryError
from llm import normalize_llm_parameters
from reader import (
    MODULE_DIR,
    fetch_active_source_ips,
    fetch_alert_document,
    fetch_alerts_window,
    load_config,
    validate_time_range,
)
from security_test_runner import (
    SecurityTestBusyError,
    SecurityTestConfigurationError,
    SecurityTestRunner,
)
from telegram_notifier import TELEGRAM_CHANNEL, TelegramConfigurationError, TelegramDeliveryError

# Re-export report and DTO formatting for 100% backward compatibility
from dashboard_reports import (
    _agent_reference,
    _alert_detail_dto,
    _analysis_sha256,
    _apply_export_policy,
    _export_metadata,
    _is_sensitive_export_key,
    _job_report,
    _job_report_v1,
    _job_report_v2,
    _language_compliance,
    _masked_ip,
    _safe_detail_list,
    _safe_detail_text,
    _safe_export_value,
    _source_value,
)

if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from blueprints import (
    ip_analysis_bp,
    jobs_bp,
    maintenance_bp,
    notifications_bp,
    security_tests_bp,
    ui_bp,
)


WEB_DIR = MODULE_DIR / "web"
DEFAULT_CONFIG = MODULE_DIR / "config.yaml"
SECURITY_TEST_MODEL = "qwen2.5:7b"
# The local dashboard has no sensor or hardware workflows. Keep browser access
# to those capabilities denied unless an operator explicitly changes the policy.
DEFAULT_PERMISSIONS_POLICY = (
    "accelerometer=(), bluetooth=(), camera=(), display-capture=(), "
    "geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), "
    "payment=(), screen-wake-lock=(), serial=(), usb=()"
)
DEFAULT_DASHBOARD = {
    "host": "127.0.0.1",
    "port": 8765,
    "database_path": "dashboard_data/dashboard.db",
    "allowed_models": ["qwen2.5:3b", "qwen2.5:7b"],
    "max_alerts_per_job": 2000,
    "max_aggregate_rule_buckets": 1000,
    "max_timeline_buckets": 96,
    "default_language": "vi",
    "max_pending_jobs": 100,
    "max_job_history": 200,
    "ingest_delay_seconds": 120,
    "max_catchup_windows": 24,
    "worker_poll_seconds": 1,
    "request_timeout_seconds": 30,
    "max_json_request_bytes": 65536,
    # Forwarded headers are attacker-controlled unless a known local proxy is
    # the only process able to reach this loopback listener.
    "trust_proxy_headers": False,
    "cors_allowed_origins": [],
    "security_headers": {
        "permissions_policy": DEFAULT_PERMISSIONS_POLICY,
        "hsts": None,
    },
    "retention_days": 0,
    "retention_keep_latest": 20,
    # Opt in only after operators update clients to perform a preview first.
    "require_preview_token": False,
    # SOC correlation normally needs the source address. Privacy owners can
    # select "mask" without changing the report schema.
    "export_ip_policy": "preserve",
    # Analyst notes are bounded and remain owner-controlled text. Set false
    # when notes must stay local to the dashboard.
    "export_review_notes": True,
    # Downloads are not stored by this service; this is advisory metadata only.
    "export_retention_days": None,
}


def _resolve_attack_chain(body):
    """Validate the optional attack-chain follow-up flag and its own window."""
    enabled = body.get("attack_chain", False)
    if not isinstance(enabled, bool):
        raise ValueError("attack_chain phai la boolean")
    seconds = body.get("attack_chain_seconds", 0)
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ValueError("attack_chain_seconds phai la so nguyen")
    if not enabled:
        return False, 0
    if seconds and seconds not in PRESET_SECONDS:
        raise ValueError("attack_chain_seconds khong hop le")
    return True, seconds


def _error(message, status):
    return jsonify({"error": str(message)}), status


def _json_body():
    if not request.is_json:
        raise ValueError("Content-Type phải là application/json")
    max_bytes = current_app.config["MAX_JSON_BODY_BYTES"]
    if request.content_length is not None and request.content_length > max_bytes:
        raise RequestEntityTooLarge("JSON request body exceeds the configured limit")
    raw_body = request.get_data(cache=True)
    if len(raw_body) > max_bytes:
        raise RequestEntityTooLarge("JSON request body exceeds the configured limit")
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid JSON body") from exc
    if not isinstance(body, dict):
        raise ValueError("JSON body phải là object")
    return body


def _resolve_llm_parameters(body, cfg, *, current=None):
    """Build an immutable job/schedule snapshot without exposing saved prompt text."""
    configured = cfg.get("ollama", {}).get("analysis", {})
    defaults = normalize_llm_parameters(configured)
    supplied = body.get("llm_parameters")
    if supplied is None:
        return dict(current) if current is not None else defaults
    if not isinstance(supplied, dict):
        raise ValueError("llm_parameters phải là object")
    merged = dict(current) if current is not None else defaults
    merged.update(supplied)
    return normalize_llm_parameters(merged)


def _llm_parameter_error(exc):
    """Return a client-safe, consistent response for bounded LLM controls."""
    return _error(f"Invalid LLM parameters: {exc}", 400)


def _normalize_origin(value):
    """Return a canonical browser origin and reject paths or credentials."""
    if not isinstance(value, str):
        raise ValueError("Origin khong hop le")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Origin khong hop le") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Origin khong hop le")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = "" if port in {None, default_port} else f":{port}"
    return f"{parsed.scheme}://{host}{suffix}"


def _cors_allowed_origins(dashboard_cfg):
    values = dashboard_cfg.get("cors_allowed_origins", [])
    if not isinstance(values, list) or len(values) > 20:
        raise ValueError("dashboard.cors_allowed_origins phai la list toi da 20 origin")
    normalized = [_normalize_origin(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise ValueError("dashboard.cors_allowed_origins khong duoc trung lap")
    return normalized


def _optional_header_value(value, name):
    """Accept operator-owned literal header values, never multiline input."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"dashboard.security_headers.{name} must be a non-empty string or null")
    if len(value) > 2048 or "\r" in value or "\n" in value:
        raise ValueError(f"dashboard.security_headers.{name} must be a single safe header value")
    return value.strip()


def _security_headers_cfg(dashboard_cfg):
    configured = dashboard_cfg.get("security_headers", {})
    if configured is None:
        configured = {}
    if not isinstance(configured, dict):
        raise ValueError("dashboard.security_headers must be an object")
    unknown = set(configured) - {"permissions_policy", "hsts"}
    if unknown:
        raise ValueError("dashboard.security_headers contains unsupported keys")
    return {
        "permissions_policy": _optional_header_value(
            configured.get("permissions_policy", DEFAULT_PERMISSIONS_POLICY), "permissions_policy",
        ),
        "hsts": _optional_header_value(configured.get("hsts"), "hsts"),
    }


def _request_origin():
    return _normalize_origin(request.host_url.rstrip("/"))


def _validate_origin():
    origin = request.headers.get("Origin")
    if not origin:
        return
    try:
        normalized = _normalize_origin(origin)
    except ValueError as exc:
        raise ValueError("Cross-origin request bi tu choi") from exc
    allowed = current_app.config["CORS_ALLOWED_ORIGINS"]
    request_origin = _request_origin()
    forwarded = request.headers.get("X-Forwarded-Host") or request.headers.get("X-Forwarded-Proto")
    if forwarded and normalized == request_origin and normalized not in allowed:
        raise ValueError("Cross-origin request bị từ chối")
    if normalized != request_origin and normalized not in allowed:
        raise ValueError("Cross-origin request bị từ chối")


def _dashboard_cfg(cfg):
    configured = cfg.get("dashboard", {})
    if not isinstance(configured, dict):
        raise ValueError("dashboard config phải là object")
    dashboard = {**DEFAULT_DASHBOARD, **configured}
    if dashboard["host"] not in {"127.0.0.1", "localhost"}:
        raise ValueError("Dashboard MVP chỉ được bind 127.0.0.1")
    history_limit = dashboard["max_job_history"]
    if isinstance(history_limit, bool) or not isinstance(history_limit, int) or not 1 <= history_limit <= 200:
        raise ValueError("dashboard.max_job_history phải nằm trong khoảng 1..200")
    alert_limit = dashboard["max_alerts_per_job"]
    if isinstance(alert_limit, bool) or not isinstance(alert_limit, int) or not 1 <= alert_limit <= 9999:
        raise ValueError("dashboard.max_alerts_per_job phải nằm trong khoảng 1..9999")
    rule_buckets = dashboard["max_aggregate_rule_buckets"]
    if isinstance(rule_buckets, bool) or not isinstance(rule_buckets, int) or not 1 <= rule_buckets <= 5000:
        raise ValueError("dashboard.max_aggregate_rule_buckets phải nằm trong khoảng 1..5000")
    timeline_buckets = dashboard["max_timeline_buckets"]
    if isinstance(timeline_buckets, bool) or not isinstance(timeline_buckets, int) or not 12 <= timeline_buckets <= 288:
        raise ValueError("dashboard.max_timeline_buckets phải nằm trong khoảng 12..288")
    json_limit = dashboard["max_json_request_bytes"]
    if isinstance(json_limit, bool) or not isinstance(json_limit, int) or not 1 <= json_limit <= 1048576:
        raise ValueError("dashboard.max_json_request_bytes must be in the range 1..1048576")
    if dashboard["default_language"] not in {"vi", "en"}:
        raise ValueError("dashboard.default_language phải là vi hoặc en")
    if not isinstance(dashboard["trust_proxy_headers"], bool):
        raise ValueError("dashboard.trust_proxy_headers phai la boolean")
    dashboard["cors_allowed_origins"] = _cors_allowed_origins(dashboard)
    dashboard["security_headers"] = _security_headers_cfg(dashboard)
    retention_days = dashboard["retention_days"]
    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 0:
        raise ValueError("dashboard.retention_days phai la so nguyen khong am")
    keep_latest = dashboard["retention_keep_latest"]
    if isinstance(keep_latest, bool) or not isinstance(keep_latest, int) or not 0 <= keep_latest <= 10000:
        raise ValueError("dashboard.retention_keep_latest phai nam trong khoang 0..10000")
    if dashboard["export_ip_policy"] not in {"preserve", "mask"}:
        raise ValueError("dashboard.export_ip_policy phai la preserve hoac mask")
    if not isinstance(dashboard["export_review_notes"], bool):
        raise ValueError("dashboard.export_review_notes phai la boolean")
    export_retention = dashboard["export_retention_days"]
    if export_retention is not None and (
        isinstance(export_retention, bool) or not isinstance(export_retention, int)
        or export_retention < 0
    ):
        raise ValueError("dashboard.export_retention_days phai la so nguyen khong am hoac null")
    return dashboard


def _validate_security_test_ranges(values):
    ranges = {
        "ingest_wait_seconds": (12, 15),
        "ingest_poll_seconds": (1, 5),
        "indexer_timeout_seconds": (1, 5),
        "analysis_timeout_seconds": (1, 45),
        "analysis_max_tokens": (64, 512),
    }
    for key, (minimum, maximum) in ranges.items():
        value = values[key]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"security_tests.{key} is invalid")
    if values["analysis_max_tokens"] != 512:
        raise ValueError("security_tests.analysis_max_tokens must be 512")


def _security_tests_cfg(cfg):
    """Validate the local-only runner config without exposing its SSH identity."""
    configured = cfg.get("security_tests")
    if configured is None:
        return {}
    if not isinstance(configured, dict):
        raise ValueError("security_tests config phải là object")
    allowed = {
        "enabled", "attacker_host", "attacker_user", "victim_host", "ssh_identity_path",
        "ssh_port", "connect_timeout_seconds", "analysis_model", "ingest_wait_seconds",
        "ingest_poll_seconds", "indexer_timeout_seconds", "analysis_timeout_seconds",
        "analysis_max_tokens", "allowed_analysis_models",
    }
    unknown = set(configured) - allowed
    if unknown:
        raise ValueError("security_tests contains unsupported keys")
    if "enabled" in configured and not isinstance(configured["enabled"], bool):
        raise ValueError("security_tests.enabled phải là boolean")
    values = {
        "analysis_model": SECURITY_TEST_MODEL,
        "ingest_wait_seconds": 15,
        "ingest_poll_seconds": 2,
        "indexer_timeout_seconds": 5,
        "analysis_timeout_seconds": 45,
        "analysis_max_tokens": 512,
    }
    values.update(configured)
    analysis_model = values["analysis_model"]
    if not isinstance(analysis_model, str) or not analysis_model.strip():
        raise ValueError("security_tests.analysis_model must be a non-empty model name")
    allowed_models = values.get("allowed_analysis_models")
    if allowed_models is not None:
        if (
            not isinstance(allowed_models, list) or not allowed_models
            or not all(isinstance(item, str) and item.strip() for item in allowed_models)
            or len(set(allowed_models)) != len(allowed_models)
        ):
            raise ValueError("security_tests.allowed_analysis_models must be a non-empty unique list")
        if analysis_model not in allowed_models:
            raise ValueError("security_tests.analysis_model must be in security_tests.allowed_analysis_models")
    _validate_security_test_ranges(values)
    return values


def _allowed_models(cfg):
    values = _dashboard_cfg(cfg).get("allowed_models", [])
    if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
        raise ValueError("dashboard.allowed_models phải là list không rỗng")
    return set(values)


def _resolve_window(body, now=None):
    now = now or datetime.now(timezone.utc)
    if "preset_seconds" in body:
        seconds = body["preset_seconds"]
        if isinstance(seconds, bool) or seconds not in PRESET_SECONDS:
            raise ValueError("preset_seconds không hợp lệ")
        end = now
        start = end - timedelta(seconds=seconds)
    else:
        start, end = body.get("start"), body.get("end")
    return validate_time_range(start, end, now=now)


def _resolve_language(body, dashboard_cfg):
    language = body.get("language", dashboard_cfg.get("default_language", "vi"))
    if language not in {"vi", "en"}:
        raise ValueError("language phải là vi hoặc en")
    return language


def _resolve_delivery_channel(body, runtime):
    channel = body.get("delivery_channel", "none")
    if channel not in {"none", TELEGRAM_CHANNEL, GMAIL_CHANNEL}:
        raise ValueError("delivery_channel không hợp lệ")
    if channel != "none":
        notifier = (
            runtime.telegram_notifier if channel == TELEGRAM_CHANNEL
            else runtime.gmail_notifier
        )
        status = notifier.status()
        if not status["enabled"] or not status["configured"]:
            label = "Telegram" if channel == TELEGRAM_CHANNEL else "Gmail"
            raise ValueError(f"{label} chưa được cấu hình hoặc chưa bật")
    return channel


def _model_list(cfg, *, timeout=None):
    allowed = _allowed_models(cfg)
    response = requests.get(
        f"{cfg['ollama']['base_url'].rstrip('/')}/api/tags",
        timeout=timeout or _dashboard_cfg(cfg).get("request_timeout_seconds", 30),
    )
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("models"), list):
        raise ValueError("Ollama /api/tags response không hợp lệ")
    output = []
    for item in body["models"]:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("model")
        if name not in allowed:
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        output.append({
            "name": name,
            "digest": item.get("digest", ""),
            "size": item.get("size", 0),
            "parameter_size": details.get("parameter_size", ""),
            "quantization_level": details.get("quantization_level", ""),
        })
    return output


def _dependency_result(request_fn):
    started = time.perf_counter()
    try:
        response, details = request_fn()
        response.raise_for_status()
        return {
            "status": "ok",
            "http_status": getattr(response, "status_code", None),
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "details": details(response),
        }
    except requests.Timeout:
        return {"status": "timeout", "latency_ms": round((time.perf_counter() - started) * 1000)}
    except (requests.RequestException, ValueError, TypeError, AttributeError, KeyError):
        return {"status": "unavailable", "latency_ms": round((time.perf_counter() - started) * 1000)}


def _dependency_health(cfg):
    timeout = _dashboard_cfg(cfg).get("request_timeout_seconds", 30)
    indexer = cfg["wazuh_indexer"]
    indexer_url = (
        f"{indexer.get('protocol', 'https')}://{indexer['host']}:{indexer['port']}/_cluster/health"
    )

    def ollama_request():
        response = requests.get(f"{cfg['ollama']['base_url'].rstrip('/')}/api/tags", timeout=timeout)
        return response, lambda item: {"model_count": len(item.json().get("models", []))}

    def indexer_request():
        response = requests.get(
            indexer_url,
            auth=(indexer["user"], indexer["password"]),
            verify=indexer.get("ca_bundle", indexer.get("verify_ssl", True)),
            timeout=timeout,
        )

        def details(item):
            body = item.json()
            if not isinstance(body, dict):
                raise ValueError("invalid indexer health")
            output = {key: body[key] for key in ("status", "number_of_nodes") if key in body}
            if "status" not in output:
                raise ValueError("missing indexer health status")
            return output

        return response, details

    return {"ollama": _dependency_result(ollama_request), "indexer": _dependency_result(indexer_request)}


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _extract_hostname(host_value):
    """Extract and normalize hostname from a Host header value."""
    if host_value.startswith("["):
        bracket_end = host_value.find("]")
        hostname = host_value[1:bracket_end] if bracket_end != -1 else host_value[1:]
    else:
        hostname = host_value.rsplit(":", 1)[0]
    return hostname.lower().rstrip(".")


def _is_allowed_host(hostname, allowed_origins):
    if hostname in _LOOPBACK_HOSTS:
        return True
    for origin in allowed_origins:
        origin_host = urlparse(origin).hostname
        if origin_host and origin_host.lower().rstrip(".") == hostname:
            return True
    return False


def create_app(config_path=DEFAULT_CONFIG, *, cfg=None, start_runtime=True):
    cfg = cfg or load_config(config_path)
    dashboard_cfg = _dashboard_cfg(cfg)
    cfg["dashboard"] = dashboard_cfg
    cfg["security_tests"] = _security_tests_cfg(cfg)
    if cfg["security_tests"]:
        dashboard_models = _allowed_models(cfg)
        security_models = cfg["security_tests"].get("allowed_analysis_models")
        if security_models is None:
            security_models = [
                model for model in dashboard_cfg.get("allowed_models", [])
                if model in dashboard_models
            ]
            cfg["security_tests"]["allowed_analysis_models"] = security_models
        if not set(security_models).issubset(dashboard_models):
            raise ValueError("security_tests.allowed_analysis_models must be a subset of dashboard.allowed_models")
        if cfg["security_tests"]["analysis_model"] not in security_models:
            raise ValueError("security_tests.analysis_model must be in security_tests.allowed_analysis_models")

    database_path = Path(dashboard_cfg.get("database_path", "dashboard_data/dashboard.db"))
    if not database_path.is_absolute():
        database_path = MODULE_DIR / database_path
    store = DashboardStore(database_path)
    analysis_service = AnalysisService(cfg)
    runtime = DashboardRuntime(
        store, cfg, analysis_service,
        poll_seconds=dashboard_cfg.get("worker_poll_seconds", 1),
    )
    security_test_runner = SecurityTestRunner(
        cfg, store=store, runtime=runtime, analysis_version=ANALYSIS_VERSION,
        model_provider=lambda: [
            item["name"] for item in _model_list(
                cfg, timeout=min(dashboard_cfg.get("request_timeout_seconds", 30), 5),
            )
        ],
    )

    app = Flask(__name__, static_folder=None)
    if dashboard_cfg["trust_proxy_headers"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_host=1, x_proto=1)

    app.config.update(
        DASHBOARD_CFG=cfg,
        DASHBOARD_STORE=store,
        DASHBOARD_RUNTIME=runtime,
        DASHBOARD_ANALYSIS_SERVICE=analysis_service,
        SECURITY_TEST_RUNNER=security_test_runner,
        MAX_JSON_BODY_BYTES=dashboard_cfg["max_json_request_bytes"],
        MAX_CONTENT_LENGTH=dashboard_cfg["max_json_request_bytes"],
        CORS_ALLOWED_ORIGINS=dashboard_cfg["cors_allowed_origins"],
        OPTIONAL_SECURITY_HEADERS=dashboard_cfg["security_headers"],
    )

    @app.before_request
    def _reject_non_loopback_host():
        orig = request.environ.get("werkzeug.proxy_fix.orig", {})
        raw_host = orig.get("HTTP_HOST") or request.host
        hostname = _extract_hostname(raw_host)
        allowed_origins = current_app.config["CORS_ALLOWED_ORIGINS"]
        if not _is_allowed_host(hostname, allowed_origins):
            return _error("Host header không hợp lệ", 421)
        rewritten = _extract_hostname(request.host)
        if rewritten != hostname and not _is_allowed_host(rewritten, allowed_origins):
            return _error("Host header không hợp lệ", 421)
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        optional_headers = current_app.config["OPTIONAL_SECURITY_HEADERS"]
        if optional_headers["permissions_policy"]:
            response.headers["Permissions-Policy"] = optional_headers["permissions_policy"]
        if optional_headers["hsts"] and request.is_secure:
            response.headers["Strict-Transport-Security"] = optional_headers["hsts"]
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            origin = request.headers.get("Origin")
            try:
                normalized_origin = _normalize_origin(origin) if origin else None
            except ValueError:
                normalized_origin = None
            if normalized_origin in current_app.config["CORS_ALLOWED_ORIGINS"]:
                response.headers["Access-Control-Allow-Origin"] = normalized_origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type"
                response.headers["Access-Control-Max-Age"] = "600"
                response.vary.add("Origin")
        elif request.path in {"/", "/security-tests"} or request.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValueError)
    def value_error(exc):
        return _error(exc, 422)

    @app.errorhandler(RequestEntityTooLarge)
    def request_entity_too_large(exc):
        return _error("JSON request body is too large", 413)

    @app.errorhandler(KeyError)
    def key_error(exc):
        return _error("Không tìm thấy resource", 404)

    app.register_blueprint(ui_bp)
    app.register_blueprint(jobs_bp)
    app.register_blueprint(ip_analysis_bp)
    app.register_blueprint(security_tests_bp)
    app.register_blueprint(notifications_bp)
    app.register_blueprint(maintenance_bp)

    if start_runtime:
        runtime.start()
        atexit.register(runtime.stop)
    return app


def main():
    from waitress import serve

    app = create_app()
    dashboard_cfg = app.config["DASHBOARD_CFG"]["dashboard"]
    serve(app, host=dashboard_cfg["host"], port=dashboard_cfg["port"])


if __name__ == "__main__":
    main()
