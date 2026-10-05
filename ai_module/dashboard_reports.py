"""ai_module/dashboard_reports.py — Report formatting, masking and export contracts."""

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timedelta

from dashboard_time import utc_now


_UNSAFE_EXPORT_KEYS = {
    "_source", "full_log", "sample_log", "raw_prompt", "system_prompt",
    "user_prompt", "prompt_text", "chain_of_thought", "cot", "reasoning",
    "reasoning_trace", "internal_reasoning", "thought_process", "raw_response",
    "raw_preview",
}

_SENSITIVE_EXPORT_KEY_PARTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "cookie", "credential", "private_key", "client_secret",
    "access_key", "refresh_token", "bot_token", "smtp", "telegram", "chat_id",
    "email_config", "mail_config", "chat",
)

_INLINE_SECRET_RE = re.compile(
    r"(?i)\b(api[_ -]?key|authorization|bearer|password|passwd|secret|token|cookie|session(?:[_ -]?id)?)\b"
    r"\s*([=:])\s*[^,\s;]+"
)

_DEFAULT_EXPORT_POLICY = {
    "export_ip_policy": "preserve",
    "export_review_notes": True,
    "export_retention_days": None,
}


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
    export_cfg = export_cfg or _DEFAULT_EXPORT_POLICY
    if schema == "v1":
        report = _job_report_v1(job)
    elif schema == "v2":
        report = _job_report_v2(job)
    else:
        raise ValueError("schema phai la v1 hoac v2")
    return _apply_export_policy(report, export_cfg)
