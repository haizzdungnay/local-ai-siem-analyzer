"""Localhost-only Flask dashboard for Wazuh alert AI analysis."""
import atexit
import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
from urllib.parse import urlparse

import requests
from flask import Flask, current_app, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from analysis_service import ANALYSIS_VERSION, AnalysisService, aggregate_rule_buckets, aggregate_alerts
from dashboard_store import DashboardStore
from dashboard_time import format_utc, utc_now
from dashboard_worker import DashboardRuntime, PRESET_SECONDS
from gmail_notifier import GMAIL_CHANNEL, GmailConfigurationError, GmailDeliveryError
from llm import normalize_llm_parameters
from reader import MODULE_DIR, fetch_alert_document, load_config, validate_time_range, fetch_alerts_window, fetch_active_source_ips
from security_test_runner import (
    SecurityTestBusyError,
    SecurityTestConfigurationError,
    SecurityTestRunner,
)
from telegram_notifier import TELEGRAM_CHANNEL, TelegramConfigurationError, TelegramDeliveryError


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
    # Read a bounded payload before decoding so an oversized body is never parsed.
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
        raise ValueError("llm_parameters pháº£i lÃ  object")
    # A schedule form cannot read its saved custom prompt back. Missing text
    # therefore preserves it while an explicit empty string intentionally clears it.
    merged = dict(current) if current is not None else defaults
    merged.update(supplied)
    return normalize_llm_parameters(merged)


def _llm_parameter_error(exc):
    """Return a client-safe, consistent response for bounded LLM controls."""
    return _error(f"Invalid LLM parameters: {exc}", 400)


def _analysis_sha256(analysis):
    if not isinstance(analysis, dict):
        return ""
    canonical = json.dumps(
        analysis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _language_compliance(value):
    """Normalize pre-contract `pass` metadata while exporting the v2 enum."""
    if value == "pass":
        return "full"
    return value if value in {"full", "partial", "unknown"} else "unknown"


_UNSAFE_EXPORT_KEYS = {
    "_source", "full_log", "sample_log", "raw_prompt", "system_prompt",
    "user_prompt", "prompt_text", "chain_of_thought", "cot", "reasoning",
    "reasoning_trace", "internal_reasoning", "thought_process", "raw_response",
    "raw_preview",
}

# Export is an explicit data-minimisation boundary. These names cover config
# objects even when they are nested under an otherwise approved result field.
_SENSITIVE_EXPORT_KEY_PARTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "cookie", "credential", "private_key", "client_secret",
    "access_key", "refresh_token", "bot_token", "smtp", "telegram", "chat_id",
    "email_config", "mail_config", "chat",
)


def _is_sensitive_export_key(key):
    normalized = re.sub(r"[^a-z0-9_]", "", str(key).lower())
    return any(part.replace("_", "") in normalized for part in _SENSITIVE_EXPORT_KEY_PARTS)


def _safe_export_value(value):
    """Remove hidden fields and credential-like values from export data."""
    if isinstance(value, dict):
        return {
            str(key): _safe_export_value(item)
            for key, item in value.items()
            if str(key).lower() not in _UNSAFE_EXPORT_KEYS
            and not _is_sensitive_export_key(key)
        }
    if isinstance(value, list):
        return [_safe_export_value(item) for item in value]
    if isinstance(value, str):
        # Keep operational identifiers and Unicode intact; redact only values
        # introduced through an explicitly credential-shaped expression.
        return _INLINE_SECRET_RE.sub(
            lambda match: f"{match.group(1)}{match.group(2)}[redacted]", value,
        )
    return value


_INLINE_SECRET_RE = re.compile(
    r"(?i)\b(api[_ -]?key|authorization|bearer|password|passwd|secret|token|cookie|session(?:[_ -]?id)?)\b"
    r"\s*([=:])\s*[^,\s;]+"
)


def _export_metadata(report, dashboard_cfg):
    """Attach the versioned privacy contract shared by every job schema."""
    metadata = report.setdefault("export_metadata", {})
    metadata.update({
        "contract_version": "local-ai-export-contract/v1",
        "redaction_marker": "[redacted]",
        "redaction_semantics": {
            "credential_values": "replace-with-marker",
            "sensitive_fields": "omit",
            "raw_logs_prompts_reasoning": "omit",
        },
        "ip_policy": dashboard_cfg.get("export_ip_policy", "preserve"),
        "review_notes": "included-bounded" if dashboard_cfg.get("export_review_notes", True) else "omitted-by-default",
        "field_classifications": {
            "operational": [
                "job", "model_call", "analysis", "assessment_basis", "audit",
                "coverage", "warnings", "metrics", "timeline", "groups",
                "alert_references.alert_id", "alert_references.rule_id",
                "alert_references.timestamp", "alert_references.source_ip",
            ],
            "sensitive": [
                "raw logs", "prompts", "reasoning", "credentials",
                "chat/email configuration", "private config fields",
            ],
            "owner_controlled": ["review.note", "review_history.note", "source_ip masking"],
        },
    })
    retention_days = dashboard_cfg.get("export_retention_days")
    metadata["retention"] = {
        "status": "owner-configured" if retention_days is not None else "not-configured",
        "days": retention_days,
        "expires_at": None,
        "enforcement": "advisory-download-metadata-only",
    }
    if retention_days is not None:
        exported_at = report.get("exported_at")
        try:
            expiry = datetime.fromisoformat(exported_at.replace("Z", "+00:00")) + timedelta(days=retention_days)
            metadata["retention"]["expires_at"] = expiry.isoformat().replace("+00:00", "Z")
        except (AttributeError, TypeError, ValueError):
            pass


def _apply_export_policy(report, dashboard_cfg):
    """Apply owner-selected IP/note policy after the common scrub boundary."""
    if dashboard_cfg.get("export_ip_policy", "preserve") == "mask":
        def mask_fields(value):
            if isinstance(value, dict):
                return {
                    key: (_masked_ip(item) if key == "source_ip" else mask_fields(item))
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [mask_fields(item) for item in value]
            return value
        for key in ("groups", "alert_references"):
            if key in report:
                report[key] = mask_fields(report[key])
    if not dashboard_cfg.get("export_review_notes", True):
        for key in ("review", "review_history"):
            values = report.get(key)
            if isinstance(values, list):
                for value in values:
                    if isinstance(value, dict):
                        value.pop("note", None)
            elif isinstance(values, dict):
                values.pop("note", None)
    _export_metadata(report, dashboard_cfg)
    return report


def _source_value(source, *path):
    value = source
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _safe_detail_text(value, *, max_length=512):
    """Keep short, allow-listed metadata while stripping inline credential values."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    text = " ".join(str(value).split())[:max_length]
    return _INLINE_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[redacted]", text,
    )


def _safe_detail_list(value):
    if not isinstance(value, list):
        value = [value]
    return [text for item in value if (text := _safe_detail_text(item, max_length=128))]


def _masked_ip(value):
    if not isinstance(value, str):
        return ""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return "[redacted]"
    prefix = 24 if address.version == 4 else 64
    network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    return str(network)


def _agent_reference(source):
    identity = _source_value(source, "agent", "id")
    if identity in (None, ""):
        identity = _source_value(source, "agent", "name")
    identity_text = _safe_detail_text(identity, max_length=128)
    if not identity_text:
        return ""
    digest = hashlib.sha256(identity_text.encode("utf-8")).hexdigest()[:12]
    return f"agent-{digest}"


def _alert_detail_dto(row_id, document):
    """Return an analyst-safe alert summary, never an Indexer _source document."""
    source = document.get("_source") if isinstance(document, dict) else None
    if not isinstance(source, dict):
        raise ValueError("Indexer document response is missing a source object")

    rule_level = _source_value(source, "rule", "level")
    if isinstance(rule_level, bool) or not isinstance(rule_level, (int, float)):
        rule_level = None
    return {
        "schema_version": "local-ai-siem-alert-detail/v1",
        "alert_id": row_id,
        "timestamp": _safe_detail_text(_source_value(source, "timestamp"), max_length=64),
        "rule": {
            "id": _safe_detail_text(_source_value(source, "rule", "id"), max_length=128),
            "level": rule_level,
            "description": _safe_detail_text(
                _source_value(source, "rule", "description"), max_length=512,
            ),
            "mitre_ids": _safe_detail_list(_source_value(source, "rule", "mitre", "id")),
        },
        "agent": {"reference": _agent_reference(source)},
        "network": {"source_ip": _masked_ip(_source_value(source, "data", "srcip"))},
        "redactions": {
            "raw_source": True,
            "full_log": True,
            "identity_and_credentials": True,
            "network_addresses_masked": True,
        },
    }


def _job_report_v1(job):
    """Build the original reusable report contract for explicit v1 exports."""
    window_results = [row for row in job["results"] if row["scope"] == "window"]
    window_result = window_results[-1] if window_results else None
    analysis = dict(window_result["result"] or {}) if window_result else None
    provenance = dict(window_result.get("provenance") or {}) if window_result else {}
    # A legacy local fallback may have persisted a raw preview before the
    # privacy fix. Do not expose that text through either export schema.
    if analysis and provenance.get("output_origin") == "local_fallback":
        analysis["summary"] = ""
    if provenance:
        provenance_status = "recorded"
    elif window_result:
        provenance_status = "unknown_legacy"
    elif job["status"] in {"succeeded", "partial"} and not job["progress_total"]:
        provenance_status = "not_called_empty_window"
    elif job["phase"] == "calling_ollama":
        provenance_status = "in_progress"
    else:
        provenance_status = "not_recorded"

    model_call = {
        "evidence_status": provenance_status,
        "requested_model": job["model"],
        "provider": provenance.get("provider", "unknown" if window_result else "none"),
        "transport": provenance.get("transport", ""),
        "response_model": provenance.get("response_model", ""),
        "output_origin": provenance.get("output_origin", provenance_status),
        "wall_latency_s": window_result["latency_s"] if window_result else None,
        "result_created_at": window_result["created_at"] if window_result else None,
    }
    for field in (
        "response_created_at", "done_reason", "response_content_sha256",
        "total_duration", "load_duration", "prompt_eval_count",
        "prompt_eval_duration", "eval_count", "eval_duration",
    ):
        if field in provenance:
            model_call[field] = provenance[field]

    job_fields = (
        "id", "job_type", "status", "phase", "window_start", "window_end",
        "model", "analysis_version", "language", "analysis_mode",
        "progress_current", "progress_total", "retry_count", "error",
        "created_at", "started_at", "finished_at",
    )
    alert_fields = (
        "index_name", "document_id", "timestamp", "rule_id", "rule_level",
        "description", "agent", "source_ip", "group_key",
    )
    return _safe_export_value({
        "schema_version": "local-ai-siem-report/v1",
        "exported_at": utc_now(),
        "export_metadata": {
            "scope": "selected-job-window",
            "page": "single-job",
            "redacted": True,
            "redaction_version": "export-redaction-v1",
            "field_inventory": {
                "included": ["job", "model_call", "analysis", "coverage", "warnings", "metrics", "timeline", "groups", "alert_references"],
                "excluded": ["raw logs", "prompts", "reasoning", "credentials", "chat/email configuration", "private config fields"],
            },
        },
        "job": {field: job.get(field) for field in job_fields},
        "model_call": model_call,
        "analysis": analysis,
        "analysis_sha256": _analysis_sha256(analysis),
        "coverage": window_result["coverage"] if window_result else {},
        "warnings": window_result["warnings"] if window_result else [],
        "metrics": job["metrics"],
        "timeline": job["timeline"],
        "groups": [
            {key: value for key, value in group.items() if key != "sample_log"}
            for group in job["groups"]
        ],
        "alert_references": [
            {field: alert.get(field) for field in alert_fields}
            for alert in job["alerts"]
        ],
    })


def _job_report_v2(job):
    """Build the SOC report contract with bounded evidence and language audit data."""
    v1 = _job_report_v1(job)
    window_results = [row for row in job["results"] if row["scope"] == "window"]
    window_result = window_results[-1] if window_results else None
    # Reuse v1's sanitized analysis so v2 cannot reintroduce a legacy raw
    # fallback preview while adding the new audit contract.
    analysis = dict(v1.get("analysis") or {})
    provenance = dict(window_result.get("provenance") or {}) if window_result else {}
    requested_language = provenance.get("requested_language", job.get("language", "vi"))
    effective_language = provenance.get(
        "effective_language", provenance.get("response_language", analysis.get("response_language", "")),
    )
    assessment_basis = analysis.get("assessment_basis", {})

    # Preserve only the inspectable evidence summary, never hidden model reasoning.
    if not isinstance(assessment_basis, dict):
        assessment_basis = {}
    assessment_basis = {
        field: assessment_basis.get(field, [])
        for field in ("observed_facts", "inferences", "uncertainties", "limitations")
    }
    report = {
        "schema_version": "local-ai-siem-report/v2",
        "exported_at": utc_now(),
        "export_metadata": {
            "scope": "selected-job-window",
            "page": "single-job",
            "redacted": True,
            "redaction_version": "export-redaction-v1",
            "field_inventory": {
                "included": ["job", "analysis", "assessment_basis", "audit", "coverage", "warnings", "metrics", "timeline", "groups", "alert_references", "review"],
                "excluded": ["raw logs", "prompts", "reasoning", "credentials", "chat/email configuration", "private config fields"],
            },
        },
        "job": v1["job"],
        "analysis": analysis or None,
        "analysis_sha256": v1["analysis_sha256"],
        "assessment_basis": assessment_basis,
        "audit": {
            "model": {
                "evidence_status": v1["model_call"]["evidence_status"],
                "requested_model": job.get("model", ""),
                "provider": provenance.get("provider", "unknown" if window_result else "none"),
                "response_model": provenance.get("response_model", ""),
                "model_digest": provenance.get("model_digest", ""),
                "model_digest_source": provenance.get("model_digest_source", ""),
                "model_digest_observed_at": provenance.get("model_digest_observed_at", ""),
                "output_origin": provenance.get("output_origin", ""),
                "options": provenance.get("options", provenance.get("ollama_options", {})),
                "response_content_sha256": provenance.get("response_content_sha256", ""),
                "wall_latency_s": window_result.get("latency_s") if window_result else None,
                "result_created_at": window_result.get("created_at") if window_result else None,
            },
            "prompt": {
                "version": provenance.get("prompt_version", "unknown_legacy"),
                "system_prompt_sha256": provenance.get(
                    "system_prompt_sha256", provenance.get("prompt_sha256", ""),
                ),
            },
            "input": {
                "request_data_sha256": provenance.get("request_data_sha256", ""),
                "output_schema_sha256": provenance.get("output_schema_sha256", ""),
            },
            "language": {
                "requested": requested_language,
                "effective": effective_language,
                "compliance": _language_compliance(provenance.get("language_compliance")),
            },
        },
        "coverage": v1["coverage"],
        "warnings": v1["warnings"],
        "metrics": v1["metrics"],
        "timeline": v1["timeline"],
        "groups": v1["groups"],
        "alert_references": v1["alert_references"],
        "review": job.get("review"),
        "review_history": job.get("review_history", []),
    }
    return _safe_export_value(report)


def _job_report(job, schema="v2", export_cfg=None):
    export_cfg = export_cfg or DEFAULT_DASHBOARD
    if schema == "v1":
        report = _job_report_v1(job)
    elif schema == "v2":
        report = _job_report_v2(job)
    else:
        raise ValueError("schema phai la v1 hoac v2")
    return _apply_export_policy(report, export_cfg)
    raise ValueError("schema phải là v1 hoặc v2")


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
    # Keep this JSON/YAML-shaped so create_app can safely reuse the same cfg.
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
            # Omission keeps the secure baseline; null is the explicit disable.
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
    # ProxyFix cannot identify whether a forwarded header came from the local
    # tunnel or a direct caller. Require an explicit allowlist entry whenever
    # forwarded routing is used, otherwise X-Forwarded-Host can spoof same-origin.
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
        # Deliberately omit exception text because it can contain endpoint details.
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


def create_app(config_path=DEFAULT_CONFIG, *, cfg=None, start_runtime=True):
    cfg = cfg or load_config(config_path)
    dashboard_cfg = _dashboard_cfg(cfg)
    cfg["dashboard"] = dashboard_cfg
    cfg["security_tests"] = _security_tests_cfg(cfg)
    if cfg["security_tests"]:
        dashboard_models = _allowed_models(cfg)
        security_models = cfg["security_tests"].get("allowed_analysis_models")
        if security_models is None:
            # Existing configs immediately gain the same operator-approved choices
            # as the main dashboard while retaining qwen2.5:7b as the default.
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
        # Waitress only listens on loopback; trust the single local tunnel proxy.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_host=1, x_proto=1)
    app.config.update(
        DASHBOARD_CFG=cfg,
        DASHBOARD_STORE=store,
        DASHBOARD_RUNTIME=runtime,
        SECURITY_TEST_RUNNER=security_test_runner,
        MAX_JSON_BODY_BYTES=dashboard_cfg["max_json_request_bytes"],
        MAX_CONTENT_LENGTH=dashboard_cfg["max_json_request_bytes"],
        CORS_ALLOWED_ORIGINS=dashboard_cfg["cors_allowed_origins"],
        OPTIONAL_SECURITY_HEADERS=dashboard_cfg["security_headers"],
    )

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
        # HSTS is meaningful only on an HTTPS response. ProxyFix supplies the
        # scheme only when the deployment explicitly trusts its local proxy.
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
            # Dashboard assets are served directly from disk without a build
            # pipeline, so stale browser caches must not retain an older UI.
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

    @app.route("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.route("/security-tests")
    def security_tests_page():
        return send_from_directory(WEB_DIR, "test.html")

    @app.route("/assets/<path:name>")
    def assets(name):
        return send_from_directory(WEB_DIR, name)

    @app.get("/api/status")
    def status():
        stats = store.maintenance_stats()
        rag_status = analysis_service.rag_status
        return jsonify({
            "app": "ok",
            "worker": "running" if runtime.worker_thread and runtime.worker_thread.is_alive() else "stopped",
            "scheduler": "running" if runtime.scheduler_thread and runtime.scheduler_thread.is_alive() else "stopped",
            "delivery_worker": "running" if runtime.delivery_thread and runtime.delivery_thread.is_alive() else "stopped",
            # `rag` remains the legacy scalar; the additive reason is safe for
            # operators and lets them diagnose a failed lazy initialization.
            "rag": rag_status,
            "rag_reason": analysis_service.rag_status_reason if rag_status == "unavailable" else None,
            "queue": stats["queue"]["pending"] + stats["queue"]["running"],
            "database": "ok",
            "database_bytes": stats["database"]["bytes"],
            "review_events": stats["reviews"]["event_count"],
        })

    @app.get("/api/active-ips")
    def get_active_ips():
        lookback_seconds = request.args.get("lookback_seconds", 604800)
        try:
            lookback_seconds = int(lookback_seconds)
        except (ValueError, TypeError):
            lookback_seconds = 604800
        ip_lookbacks = {300, 900, 1800, 3600, 7200, 21600, 43200, 86400, 259200, 604800, 2592000}
        if lookback_seconds not in ip_lookbacks:
            lookback_seconds = 604800
        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=lookback_seconds)
        try:
            ips = fetch_active_source_ips(cfg, start=start, end=now, limit=50)
        except Exception:
            ips = []
        return jsonify({"ips": ips, "lookback_seconds": lookback_seconds})

    @app.post("/api/ip-analysis")
    def analyze_ip_behavior():
        _validate_origin()
        body = _json_body()
        source_ip = body.get("source_ip")
        auto_mode = body.get("auto", False) is True

        ip_lookbacks = {300, 900, 1800, 3600, 7200, 21600, 43200, 86400, 259200, 604800, 2592000}
        lookback_seconds = body.get("lookback_seconds", 604800)
        if (
            not isinstance(lookback_seconds, int)
            or isinstance(lookback_seconds, bool)
            or lookback_seconds not in ip_lookbacks
        ):
            raise ValueError("Khoảng suy luận IP phải từ 5 phút đến tối đa 30 ngày")

        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=lookback_seconds)

        if auto_mode or not source_ip or not str(source_ip).strip():
            top_ips = fetch_active_source_ips(cfg, start=start, end=now, limit=1)
            if not top_ips:
                source_ip = ""
            else:
                source_ip = top_ips[0]["ip"]

        if source_ip:
            try:
                parsed_ip = ipaddress.ip_address(str(source_ip).strip())
                if parsed_ip.version != 4:
                    raise ValueError("Chỉ hỗ trợ địa chỉ IPv4")
                source_ip = str(parsed_ip)
            except ValueError as exc:
                raise ValueError(f"Địa chỉ IP không hợp lệ: {source_ip}") from exc

        model = body.get("model", cfg.get("ollama", {}).get("model", "qwen2.5:7b"))
        if model not in _allowed_models(cfg):
            raise ValueError("Model không thuộc dashboard.allowed_models")

        language = _resolve_language(body, dashboard_cfg)

        if not source_ip:
            return jsonify({
                "source_ip": "None",
                "total_alerts": 0,
                "lookback_seconds": lookback_seconds,
                "first_seen": "",
                "last_seen": "",
                "analysis": {
                    "summary": (
                        "Không có cảnh báo nào trong khoảng thời gian đã chọn."
                        if language == "vi"
                        else "No alerts were found in the selected time range."
                    ),
                    "intent": "Không phát hiện hoạt động" if language == "vi" else "No activity detected",
                    "severity": "low",
                    "kill_chain_stages": ["Không phát hiện giai đoạn tấn công" if language == "vi" else "No attack stage detected"],
                    "targeted_assets": [],
                    "mitre": [],
                    "next_steps": ["Tiếp tục giám sát." if language == "vi" else "Continue monitoring."],
                    "response_language": language,
                    "confidence": 100.0,
                    "assessment_basis": {
                        "observed_facts": [
                            "Không tìm thấy alert trong Wazuh Indexer."
                            if language == "vi" else "No alert was found in Wazuh Indexer."
                        ],
                        "inferences": [],
                        "uncertainties": [],
                        "limitations": []
                    }
                }
            })

        fetched = fetch_alerts_window(
            cfg,
            start=start,
            end=now,
            source_ip=source_ip,
            max_alerts=dashboard_cfg.get("max_window_alerts", 2000),
            summary_only=False
        )

        if fetched.get("analysis_mode") == "aggregate":
            aggregate = aggregate_rule_buckets(fetched)
        else:
            aggregate = aggregate_alerts(fetched.get("alerts", []))

        if not aggregate.get("total_alerts"):
            return jsonify({
                "source_ip": source_ip,
                "total_alerts": 0,
                "lookback_seconds": lookback_seconds,
                "first_seen": "",
                "last_seen": "",
                "analysis": {
                    "summary": (
                        f"Không có cảnh báo nào từ IP {source_ip} trong khoảng thời gian đã chọn."
                        if language == "vi"
                        else f"No alerts from IP {source_ip} were found in the selected time range."
                    ),
                    "intent": "Không phát hiện hoạt động" if language == "vi" else "No activity detected",
                    "severity": "low",
                    "kill_chain_stages": ["Không phát hiện giai đoạn tấn công" if language == "vi" else "No attack stage detected"],
                    "targeted_assets": [],
                    "mitre": [],
                    "next_steps": ["Tiếp tục giám sát IP này." if language == "vi" else "Continue monitoring this IP."],
                    "response_language": language,
                    "confidence": 100.0,
                    "assessment_basis": {
                        "observed_facts": [
                            "Không tìm thấy alert trong Wazuh Indexer."
                            if language == "vi" else "No alert was found in Wazuh Indexer."
                        ],
                        "inferences": [],
                        "uncertainties": [],
                        "limitations": []
                    }
                }
            })

        result = analysis_service.analyze_ip_profile_aggregate(
            aggregate=aggregate,
            source_ip=source_ip,
            model=model,
            language=language
        )

        groups = aggregate.get("groups") or []
        first_seen = min((group.get("first_seen", "") for group in groups if group.get("first_seen")), default="")
        last_seen = max((group.get("last_seen", "") for group in groups if group.get("last_seen")), default="")
        return jsonify({
            "source_ip": source_ip,
            "total_alerts": aggregate.get("total_alerts", 0),
            "unique_rules": aggregate.get("unique_rules", 0),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "lookback_seconds": lookback_seconds,
            "analysis": result["analysis"],
            "coverage": result["coverage"],
            "provenance": result["provenance"]
        })

    @app.get("/api/security-tests/catalog")
    def security_test_catalog():
        return jsonify(security_test_runner.catalog())

    @app.post("/api/security-tests/runs")
    def create_security_test_run():
        _validate_origin()
        body = _json_body()
        allowed_fields = {"scenario_id", "confirm", "model"}
        unknown_fields = set(body) - allowed_fields
        if unknown_fields:
            raise ValueError("Security test request contains unsupported fields")
        if body.get("confirm") is not True:
            raise ValueError("confirm phải là true để chạy security test")
        scenario_id = body.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario_id không hợp lệ")
        model = body["model"] if "model" in body else cfg["security_tests"].get("analysis_model")
        allowed_security_models = cfg["security_tests"].get("allowed_analysis_models", [])
        if not isinstance(model, str) or model not in allowed_security_models:
            raise ValueError("Model không thuộc security_tests.allowed_analysis_models")
        try:
            run = security_test_runner.start(scenario_id, model=model)
        except SecurityTestBusyError as exc:
            return _error(str(exc), 409)
        except SecurityTestConfigurationError as exc:
            return _error(str(exc), 422)
        return jsonify({"run": run}), 202

    @app.get("/api/security-tests/runs/<run_id>")
    def get_security_test_run(run_id):
        if not re.fullmatch(r"[0-9a-f]{32}", run_id):
            return _error("Invalid security test run ID", 404)
        run = security_test_runner.get_run(run_id)
        if not run:
            return _error("Không tìm thấy security test run", 404)
        return jsonify({"run": run})

    @app.get("/api/notifications/status")
    def notification_status():
        return jsonify({
            "telegram": runtime.telegram_notifier.status(),
            "gmail": runtime.gmail_notifier.status(),
        })

    @app.post("/api/notifications/telegram/settings")
    def telegram_settings():
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phải là true để lưu cài đặt Telegram")
        try:
            telegram = runtime.telegram_notifier.configure_local(
                token=body.get("bot_token"), chat_id=body.get("chat_id"),
            )
        except TelegramConfigurationError as exc:
            raise ValueError(str(exc)) from exc
        # Do not reflect a credential or destination identifier back to the browser.
        return jsonify({"status": "saved", "telegram": telegram}), 201

    @app.post("/api/notifications/telegram/test")
    def telegram_test():
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phải là true để gửi test Telegram")
        try:
            result = runtime.telegram_notifier.send_test()
        except TelegramConfigurationError as exc:
            raise ValueError(str(exc)) from exc
        except TelegramDeliveryError as exc:
            return _error(f"Telegram test failed: {exc.code}", 503 if exc.uncertain else 422)
        return jsonify({"status": "sent", **result}), 202

    @app.post("/api/notifications/gmail/settings")
    def gmail_settings():
        _validate_origin()
        body = _json_body()
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
        # Never reflect an address or App Password to the browser.
        return jsonify({"status": "saved", "gmail": gmail}), 201

    @app.post("/api/notifications/gmail/test")
    def gmail_test():
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phải là true để gửi test Gmail")
        try:
            result = runtime.gmail_notifier.send_test()
        except GmailConfigurationError as exc:
            raise ValueError(str(exc)) from exc
        except GmailDeliveryError as exc:
            return _error(f"Gmail test failed: {exc.code}", 503 if exc.uncertain else 422)
        return jsonify({"status": "sent", **result}), 202

    @app.get("/api/dependencies")
    def dependencies():
        return jsonify(_dependency_health(cfg))

    @app.get("/api/models")
    def models():
        try:
            return jsonify({"models": _model_list(cfg)})
        except requests.Timeout as exc:
            return _error(f"Ollama timeout: {exc}", 504)
        except requests.RequestException as exc:
            return _error(f"Ollama unavailable: {exc}", 503)

    @app.post("/api/jobs")
    def create_job():
        _validate_origin()
        body = _json_body()
        model = body.get("model")
        language = _resolve_language(body, dashboard_cfg)
        if model not in _allowed_models(cfg):
            raise ValueError("Model không thuộc dashboard.allowed_models")
        pending = store.active_job_count()
        if pending >= dashboard_cfg.get("max_pending_jobs", 100):
            return _error("Hàng đợi dashboard đã đầy", 503)
        start, end = _resolve_window(body)
        delivery_channel = _resolve_delivery_channel(body, runtime)
        try:
            llm_parameters = _resolve_llm_parameters(body, cfg)
        except ValueError as exc:
            return _llm_parameter_error(exc)
        attack_chain, attack_chain_seconds = _resolve_attack_chain(body)
        job_id = store.create_job(
            "manual_window", format_utc(start), format_utc(end), model, ANALYSIS_VERSION,
            language=language, delivery_channel=delivery_channel, llm_parameters=llm_parameters,
            attack_chain=attack_chain, attack_chain_seconds=attack_chain_seconds,
        )
        runtime.notify()
        return jsonify({"job_id": job_id}), 202

    @app.get("/api/jobs")
    def list_jobs():
        # Keep the no-query response compatible with older dashboard clients;
        # paged/filtering requests are evaluated by SQLite and include totals.
        query = request.args
        paged = any(name in query for name in
                    ("page", "page_size", "search", "status", "language", "mode", "review", "severity"))
        if not paged:
            return jsonify({"jobs": store.list_jobs(dashboard_cfg["max_job_history"])})
        def integer_arg(name, default):
            raw = query.get(name)
            if raw is None or raw == "":
                return default
            try:
                value = int(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be an integer") from exc
            return value
        try:
            page = integer_arg("page", 1)
            page_size = integer_arg("page_size", 50)
            filters = {name: query.get(name, "") for name in
                       ("search", "status", "language", "mode", "review", "severity")}
            allowed = {
                "status": {"", "pending", "running", "succeeded", "partial", "failed", "cancelled"},
                "language": {"", "vi", "en"},
                "mode": {"", "full", "aggregate"},
                "review": {"", "none", "new", "acknowledged", "investigating", "resolved", "false_positive"},
            }
            for name, values in allowed.items():
                if filters[name] not in values:
                    raise ValueError(f"Invalid {name} filter")
            result = store.list_jobs_page(page=page, page_size=page_size, filters=filters)
        except ValueError as exc:
            return _error(exc, 400)
        return jsonify(result)

    @app.post("/api/jobs/review/bulk")
    def bulk_review_jobs():
        _validate_origin()
        body = _json_body()
        if "tags" in body and not isinstance(body["tags"], list):
            raise ValueError("review.tags phai la list")
        events = store.add_review_events(
            body.get("job_ids"),
            status=body.get("status"),
            severity=body.get("severity", "inherit"),
            tags=body.get("tags", []),
            note=body.get("note", ""),
        )
        return jsonify({"events": events}), 201

    @app.get("/api/jobs/<int:job_id>")
    def get_job(job_id):
        detail = store.get_job_detail(job_id)
        if not detail:
            return _error("Không tìm thấy job", 404)
        return jsonify(detail)

    @app.post("/api/jobs/<int:job_id>/review")
    def review_job(job_id):
        _validate_origin()
        body = _json_body()
        if "tags" in body and not isinstance(body["tags"], list):
            raise ValueError("review.tags phai la list")
        event = store.add_review_event(
            job_id,
            status=body.get("status"),
            severity=body.get("severity", "inherit"),
            tags=body.get("tags", []),
            note=body.get("note", ""),
        )
        return jsonify(event), 201

    @app.get("/api/jobs/<int:job_id>/export")
    def export_job(job_id):
        detail = store.get_job_detail(job_id)
        if not detail:
            return _error("Không tìm thấy job", 404)
        schema = request.args.get("schema", "v2")
        payload = json.dumps(_job_report(detail, schema=schema, export_cfg=dashboard_cfg), ensure_ascii=False, indent=2)
        response = app.response_class(payload, mimetype="application/json")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="wazuh-ai-job-{job_id}.json"'
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/maintenance")
    def maintenance():
        return jsonify({
            "retention_enabled": dashboard_cfg["retention_days"] > 0,
            "policy": {
                "retention_days": dashboard_cfg["retention_days"],
                "retention_keep_latest": dashboard_cfg["retention_keep_latest"],
            },
            "stats": store.maintenance_stats(),
            "backups": store.list_retention_backups(),
        })

    @app.get("/api/maintenance/preview")
    def maintenance_preview():
        return jsonify(store.retention_preview(
            retention_days=dashboard_cfg["retention_days"],
            keep_latest=dashboard_cfg["retention_keep_latest"],
        ))

    @app.post("/api/maintenance/prune")
    def prune_maintenance():
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phai la true de prune")
        preview = store.retention_preview(
            retention_days=dashboard_cfg["retention_days"],
            keep_latest=dashboard_cfg["retention_keep_latest"],
        )
        if dashboard_cfg.get("require_preview_token") and body.get("confirmation_token") != preview["confirmation_token"]:
            raise ValueError("confirmation_token khong hop le hoac da het han; hay preview lai")
        result = store.prune_terminal_jobs(
            retention_days=dashboard_cfg["retention_days"],
            keep_latest=dashboard_cfg["retention_keep_latest"],
        )
        result.update({
            "confirmed": True,
            "preview_candidate_count": preview["candidate_count"],
            "policy": preview["policy"],
            "confirmation_token_required": bool(dashboard_cfg.get("require_preview_token")),
        })
        return jsonify({"result": result, "stats": store.maintenance_stats()})

    @app.post("/api/maintenance/backup")
    def backup_maintenance():
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phai la true de tao backup")
        preview = store.retention_preview(
            retention_days=dashboard_cfg["retention_days"],
            keep_latest=dashboard_cfg["retention_keep_latest"],
        )
        if dashboard_cfg.get("require_preview_token") and body.get("confirmation_token") != preview["confirmation_token"]:
            raise ValueError("confirmation_token khong hop le hoac da het han; hay preview lai")
        return jsonify({"backup": store.create_retention_backup()})

    @app.post("/api/maintenance/restore")
    def restore_maintenance():
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phai la true de restore")
        filename = body.get("backup")
        if not isinstance(filename, str):
            raise ValueError("backup phai la ten file snapshot")
        preview = store.retention_preview(
            retention_days=dashboard_cfg["retention_days"],
            keep_latest=dashboard_cfg["retention_keep_latest"],
        )
        if dashboard_cfg.get("require_preview_token") and body.get("confirmation_token") != preview["confirmation_token"]:
            raise ValueError("confirmation_token khong hop le hoac da het han; hay preview lai")
        return jsonify({"restored": store.restore_retention_backup(filename)})

    @app.post("/api/jobs/<int:job_id>/cancel")
    def cancel_job(job_id):
        _validate_origin()
        _json_body()
        store.request_cancel(job_id)
        return jsonify({"status": "cancel_requested"}), 202

    @app.post("/api/jobs/<int:job_id>/retry")
    def retry_job(job_id):
        _validate_origin()
        _json_body()
        store.retry_job(job_id)
        runtime.notify()
        return jsonify({"status": "pending"}), 202

    @app.post("/api/jobs/<int:job_id>/delivery")
    def enqueue_job_delivery(job_id):
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phải là true để gửi report")
        channel = _resolve_delivery_channel({"delivery_channel": body.get("channel")}, runtime)
        if channel == "none":
            raise ValueError("Chọn một delivery channel để gửi report")
        detail = store.get_job_detail(job_id)
        if not detail:
            return _error("Không tìm thấy job", 404)
        if detail["status"] not in {"succeeded", "partial"}:
            raise ValueError("Chỉ gửi report của job succeeded hoặc partial")
        delivery = store.enqueue_delivery(job_id, channel)
        runtime.notify_delivery()
        return jsonify({"delivery": delivery}), 202

    @app.post("/api/deliveries/<int:delivery_id>/retry")
    def retry_delivery(delivery_id):
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phải là true để retry delivery")
        force = body.get("force", False)
        if not isinstance(force, bool):
            raise ValueError("force phải là boolean")
        delivery = store.retry_delivery(delivery_id, allow_sent=force)
        runtime.notify_delivery()
        return jsonify({"delivery": delivery}), 202

    @app.get("/api/job-alerts/<int:row_id>")
    def get_alert(row_id):
        row = store.get_alert_row(row_id)
        if not row:
            return _error("Không tìm thấy alert reference", 404)
        try:
            document = fetch_alert_document(cfg, row["index_name"], row["document_id"])
            return jsonify(_alert_detail_dto(row_id, document))
        except requests.Timeout as exc:
            return _error(f"Indexer timeout: {exc}", 504)
        except requests.RequestException as exc:
            return _error(f"Indexer unavailable: {exc}", 503)

    @app.get("/api/schedule")
    def get_schedule():
        return jsonify(store.get_schedule())

    @app.put("/api/schedule")
    def put_schedule():
        _validate_origin()
        body = _json_body()
        enabled = body.get("enabled")
        interval = body.get("interval_seconds")
        model = body.get("model")
        language = _resolve_language(body, dashboard_cfg)
        if not isinstance(enabled, bool):
            raise ValueError("enabled phải là boolean")
        if interval not in PRESET_SECONDS:
            raise ValueError("interval_seconds không hợp lệ")
        if model not in _allowed_models(cfg):
            raise ValueError("Model không thuộc dashboard.allowed_models")
        delivery_channel = _resolve_delivery_channel(body, runtime)
        current_schedule = store.get_schedule(include_llm_parameters=True)
        try:
            llm_parameters = _resolve_llm_parameters(
                body, cfg, current=current_schedule.get("llm_parameters")
            )
        except ValueError as exc:
            return _llm_parameter_error(exc)
        attack_chain, attack_chain_seconds = _resolve_attack_chain(body)
        now = datetime.now(timezone.utc)
        schedule = store.configure_schedule(
            enabled=enabled,
            attack_chain=attack_chain, attack_chain_seconds=attack_chain_seconds,
            interval_seconds=interval,
            model=model,
            language=language,
            delivery_channel=delivery_channel,
            llm_parameters=llm_parameters,
            next_window_start=format_utc(now),
            ingest_delay_seconds=dashboard_cfg.get("ingest_delay_seconds", 120),
            max_catchup_windows=dashboard_cfg.get("max_catchup_windows", 24),
        )
        runtime.notify()
        return jsonify(schedule)

    @app.post("/api/schedule/retry")
    def retry_schedule():
        _validate_origin()
        _json_body()
        store.unblock_schedule()
        runtime.notify()
        return jsonify(store.get_schedule())

    @app.post("/api/schedule/skip")
    def skip_schedule():
        _validate_origin()
        _json_body()
        runtime.notify()
        return jsonify(store.skip_schedule_window())

    if start_runtime:
        runtime.start()
        atexit.register(runtime.stop)
    return app


def main():
    from waitress import serve

    app = create_app()
    cfg = app.config["DASHBOARD_CFG"]
    dashboard = _dashboard_cfg(cfg)
    serve(
        app,
        host="127.0.0.1",
        port=int(dashboard.get("port", 8765)),
        threads=4,
    )


if __name__ == "__main__":
    main()
