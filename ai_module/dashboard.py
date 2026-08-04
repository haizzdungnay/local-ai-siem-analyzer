"""Localhost-only Flask dashboard for Wazuh alert AI analysis."""
import atexit
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request, send_from_directory

from analysis_service import ANALYSIS_VERSION, AnalysisService
from dashboard_store import DashboardStore
from dashboard_time import format_utc, utc_now
from dashboard_worker import DashboardRuntime, PRESET_SECONDS
from reader import MODULE_DIR, fetch_alert_document, load_config, validate_time_range


WEB_DIR = MODULE_DIR / "web"
DEFAULT_CONFIG = MODULE_DIR / "config.yaml"
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
    "retention_days": 0,
    "retention_keep_latest": 20,
}


def _error(message, status):
    return jsonify({"error": str(message)}), status


def _json_body():
    if not request.is_json:
        raise ValueError("Content-Type phải là application/json")
    body = request.get_json(silent=False)
    if not isinstance(body, dict):
        raise ValueError("JSON body phải là object")
    return body


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


def _safe_export_value(value):
    """Remove raw logs, prompts, and model reasoning from reusable report data."""
    if isinstance(value, dict):
        return {
            str(key): _safe_export_value(item)
            for key, item in value.items()
            if str(key).lower() not in _UNSAFE_EXPORT_KEYS
        }
    if isinstance(value, list):
        return [_safe_export_value(item) for item in value]
    return value


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


def _job_report(job, schema="v2"):
    if schema == "v1":
        return _job_report_v1(job)
    if schema == "v2":
        return _job_report_v2(job)
    raise ValueError("schema phải là v1 hoặc v2")


def _validate_origin():
    origin = request.headers.get("Origin")
    if not origin:
        return
    parsed = urlparse(origin)
    if parsed.scheme != request.scheme or parsed.netloc != request.host:
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
    if dashboard["default_language"] not in {"vi", "en"}:
        raise ValueError("dashboard.default_language phải là vi hoặc en")
    retention_days = dashboard["retention_days"]
    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 0:
        raise ValueError("dashboard.retention_days phai la so nguyen khong am")
    keep_latest = dashboard["retention_keep_latest"]
    if isinstance(keep_latest, bool) or not isinstance(keep_latest, int) or not 0 <= keep_latest <= 10000:
        raise ValueError("dashboard.retention_keep_latest phai nam trong khoang 0..10000")
    return dashboard


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


def _model_list(cfg):
    allowed = _allowed_models(cfg)
    response = requests.get(
        f"{cfg['ollama']['base_url'].rstrip('/')}/api/tags",
        timeout=_dashboard_cfg(cfg).get("request_timeout_seconds", 30),
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
    database_path = Path(dashboard_cfg.get("database_path", "dashboard_data/dashboard.db"))
    if not database_path.is_absolute():
        database_path = MODULE_DIR / database_path
    store = DashboardStore(database_path)
    analysis_service = AnalysisService(cfg)
    runtime = DashboardRuntime(
        store, cfg, analysis_service,
        poll_seconds=dashboard_cfg.get("worker_poll_seconds", 1),
    )

    app = Flask(__name__, static_folder=None)
    app.config.update(DASHBOARD_CFG=cfg, DASHBOARD_STORE=store, DASHBOARD_RUNTIME=runtime)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValueError)
    def value_error(exc):
        return _error(exc, 422)

    @app.errorhandler(KeyError)
    def key_error(exc):
        return _error("Không tìm thấy resource", 404)

    @app.route("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.route("/assets/<path:name>")
    def assets(name):
        return send_from_directory(WEB_DIR, name)

    @app.get("/api/status")
    def status():
        stats = store.maintenance_stats()
        return jsonify({
            "app": "ok",
            "worker": "running" if runtime.worker_thread and runtime.worker_thread.is_alive() else "stopped",
            "scheduler": "running" if runtime.scheduler_thread and runtime.scheduler_thread.is_alive() else "stopped",
            "rag": "enabled" if analysis_service.rag else "disabled",
            "queue": stats["queue"]["pending"] + stats["queue"]["running"],
            "database": "ok",
            "database_bytes": stats["database"]["bytes"],
            "review_events": stats["reviews"]["event_count"],
        })

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
        job_id = store.create_job(
            "manual_window", format_utc(start), format_utc(end), model, ANALYSIS_VERSION,
            language=language,
        )
        runtime.notify()
        return jsonify({"job_id": job_id}), 202

    @app.get("/api/jobs")
    def list_jobs():
        return jsonify({"jobs": store.list_jobs(dashboard_cfg["max_job_history"])})

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
        payload = json.dumps(_job_report(detail, schema=schema), ensure_ascii=False, indent=2)
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
        })

    @app.post("/api/maintenance/prune")
    def prune_maintenance():
        _validate_origin()
        body = _json_body()
        if body.get("confirm") is not True:
            raise ValueError("confirm phai la true de prune")
        result = store.prune_terminal_jobs(
            retention_days=dashboard_cfg["retention_days"],
            keep_latest=dashboard_cfg["retention_keep_latest"],
        )
        return jsonify({"result": result, "stats": store.maintenance_stats()})

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

    @app.get("/api/job-alerts/<int:row_id>")
    def get_alert(row_id):
        row = store.get_alert_row(row_id)
        if not row:
            return _error("Không tìm thấy alert reference", 404)
        try:
            return jsonify(fetch_alert_document(cfg, row["index_name"], row["document_id"]))
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
        now = datetime.now(timezone.utc)
        schedule = store.configure_schedule(
            enabled=enabled,
            interval_seconds=interval,
            model=model,
            language=language,
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
