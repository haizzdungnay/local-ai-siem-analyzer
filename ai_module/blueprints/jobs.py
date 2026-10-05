"""ai_module/blueprints/jobs.py — Job management, review, export, delivery and schedule."""

import json
from datetime import datetime, timezone

import requests
from flask import Blueprint, current_app, jsonify, request

from dashboard_time import format_utc
from dashboard_worker import PRESET_SECONDS
import dashboard


jobs_bp = Blueprint("jobs", __name__)


@jobs_bp.post("/api/jobs")
def create_job():
    dashboard._validate_origin()
    body = dashboard._json_body()
    cfg = current_app.config["DASHBOARD_CFG"]
    dashboard_cfg = cfg.get("dashboard", {})
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]

    model = body.get("model")
    language = dashboard._resolve_language(body, dashboard_cfg)
    if model not in dashboard._allowed_models(cfg):
        raise ValueError("Model không thuộc dashboard.allowed_models")
    pending = store.active_job_count()
    if pending >= dashboard_cfg.get("max_pending_jobs", 100):
        return dashboard._error("Hàng đợi dashboard đã đầy", 503)

    start, end = dashboard._resolve_window(body)
    delivery_channel = dashboard._resolve_delivery_channel(body, runtime)
    try:
        llm_parameters = dashboard._resolve_llm_parameters(body, cfg)
    except ValueError as exc:
        return dashboard._llm_parameter_error(exc)
    attack_chain, attack_chain_seconds = dashboard._resolve_attack_chain(body)

    job_id = store.create_job(
        "manual_window", format_utc(start), format_utc(end), model, dashboard.ANALYSIS_VERSION,
        language=language, delivery_channel=delivery_channel, llm_parameters=llm_parameters,
        attack_chain=attack_chain, attack_chain_seconds=attack_chain_seconds,
    )
    runtime.notify()
    return jsonify({"job_id": job_id}), 202


@jobs_bp.get("/api/jobs")
def list_jobs():
    store = current_app.config["DASHBOARD_STORE"]
    dashboard_cfg = current_app.config["DASHBOARD_CFG"].get("dashboard", {})
    query = request.args
    paged = any(
        name in query
        for name in ("page", "page_size", "search", "status", "language", "mode", "review", "severity")
    )
    if not paged:
        return jsonify({"jobs": store.list_jobs(dashboard_cfg.get("max_job_history", 200))})

    def integer_arg(name, default):
        raw = query.get(name)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be an integer") from exc

    try:
        page = integer_arg("page", 1)
        page_size = integer_arg("page_size", 50)
        filters = {
            name: query.get(name, "")
            for name in ("search", "status", "language", "mode", "review", "severity")
        }
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
        return dashboard._error(exc, 400)
    return jsonify(result)


@jobs_bp.post("/api/jobs/review/bulk")
def bulk_review_jobs():
    dashboard._validate_origin()
    body = dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
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


@jobs_bp.get("/api/jobs/<int:job_id>")
def get_job(job_id):
    store = current_app.config["DASHBOARD_STORE"]
    detail = store.get_job_detail(job_id)
    if not detail:
        return dashboard._error("Không tìm thấy job", 404)
    return jsonify(detail)


@jobs_bp.post("/api/jobs/<int:job_id>/review")
def review_job(job_id):
    dashboard._validate_origin()
    body = dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
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


@jobs_bp.get("/api/jobs/<int:job_id>/export")
def export_job(job_id):
    store = current_app.config["DASHBOARD_STORE"]
    dashboard_cfg = current_app.config["DASHBOARD_CFG"].get("dashboard", {})
    detail = store.get_job_detail(job_id)
    if not detail:
        return dashboard._error("Không tìm thấy job", 404)
    schema = request.args.get("schema", "v2")
    payload = json.dumps(
        dashboard._job_report(detail, schema=schema, export_cfg=dashboard_cfg),
        ensure_ascii=False,
        indent=2,
    )
    response = current_app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="wazuh-ai-job-{job_id}.json"'
    response.headers["Cache-Control"] = "no-store"
    return response


@jobs_bp.post("/api/jobs/<int:job_id>/cancel")
def cancel_job(job_id):
    dashboard._validate_origin()
    dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    store.request_cancel(job_id)
    return jsonify({"status": "cancel_requested"}), 202


@jobs_bp.post("/api/jobs/<int:job_id>/retry")
def retry_job(job_id):
    dashboard._validate_origin()
    dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    store.retry_job(job_id)
    runtime.notify()
    return jsonify({"status": "pending"}), 202


@jobs_bp.post("/api/jobs/<int:job_id>/delivery")
def enqueue_job_delivery(job_id):
    dashboard._validate_origin()
    body = dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    if body.get("confirm") is not True:
        raise ValueError("confirm phải là true để gửi report")
    channel = dashboard._resolve_delivery_channel({"delivery_channel": body.get("channel")}, runtime)
    if channel == "none":
        raise ValueError("Chọn một delivery channel để gửi report")
    detail = store.get_job_detail(job_id)
    if not detail:
        return dashboard._error("Không tìm thấy job", 404)
    if detail["status"] not in {"succeeded", "partial"}:
        raise ValueError("Chỉ gửi report của job succeeded hoặc partial")
    delivery = store.enqueue_delivery(job_id, channel)
    runtime.notify_delivery()
    return jsonify({"delivery": delivery}), 202


@jobs_bp.post("/api/deliveries/<int:delivery_id>/retry")
def retry_delivery(delivery_id):
    dashboard._validate_origin()
    body = dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    if body.get("confirm") is not True:
        raise ValueError("confirm phải là true để retry delivery")
    force = body.get("force", False)
    if not isinstance(force, bool):
        raise ValueError("force phải là boolean")
    delivery = store.retry_delivery(delivery_id, allow_sent=force)
    runtime.notify_delivery()
    return jsonify({"delivery": delivery}), 202


@jobs_bp.get("/api/job-alerts/<int:row_id>")
def get_alert(row_id):
    store = current_app.config["DASHBOARD_STORE"]
    cfg = current_app.config["DASHBOARD_CFG"]
    row = store.get_alert_row(row_id)
    if not row:
        return dashboard._error("Không tìm thấy alert reference", 404)
    try:
        document = dashboard.fetch_alert_document(cfg, row["index_name"], row["document_id"])
        return jsonify(dashboard._alert_detail_dto(row_id, document))
    except requests.Timeout as exc:
        return dashboard._error(f"Indexer timeout: {exc}", 504)
    except requests.RequestException as exc:
        return dashboard._error(f"Indexer unavailable: {exc}", 503)


@jobs_bp.get("/api/schedule")
def get_schedule():
    store = current_app.config["DASHBOARD_STORE"]
    return jsonify(store.get_schedule())


@jobs_bp.put("/api/schedule")
def put_schedule():
    dashboard._validate_origin()
    body = dashboard._json_body()
    cfg = current_app.config["DASHBOARD_CFG"]
    dashboard_cfg = cfg.get("dashboard", {})
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]

    enabled = body.get("enabled")
    interval = body.get("interval_seconds")
    model = body.get("model")
    language = dashboard._resolve_language(body, dashboard_cfg)
    if not isinstance(enabled, bool):
        raise ValueError("enabled phải là boolean")
    if interval not in PRESET_SECONDS:
        raise ValueError("interval_seconds không hợp lệ")
    if model not in dashboard._allowed_models(cfg):
        raise ValueError("Model không thuộc dashboard.allowed_models")
    delivery_channel = dashboard._resolve_delivery_channel(body, runtime)
    current_schedule = store.get_schedule(include_llm_parameters=True)
    try:
        llm_parameters = dashboard._resolve_llm_parameters(
            body, cfg, current=current_schedule.get("llm_parameters")
        )
    except ValueError as exc:
        return dashboard._llm_parameter_error(exc)
    attack_chain, attack_chain_seconds = dashboard._resolve_attack_chain(body)
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


@jobs_bp.post("/api/schedule/retry")
def retry_schedule():
    dashboard._validate_origin()
    dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    store.unblock_schedule()
    runtime.notify()
    return jsonify(store.get_schedule())


@jobs_bp.post("/api/schedule/skip")
def skip_schedule():
    dashboard._validate_origin()
    dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    runtime.notify()
    return jsonify(store.skip_schedule_window())
