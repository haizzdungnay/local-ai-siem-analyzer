"""ai_module/blueprints/ui.py — Static UI assets, status, dependency health and models."""

from threading import Lock

import requests
from flask import Blueprint, current_app, jsonify, send_from_directory

import dashboard
from analysis_service import DASHBOARD_MODEL_KEEP_ALIVE
from llm import ollama_options
from reader import validate_ollama_base_url


ui_bp = Blueprint("ui", __name__)
_model_preload_lock = Lock()


@ui_bp.route("/")
def index():
    return send_from_directory(dashboard.WEB_DIR, "index.html")


@ui_bp.route("/security-tests")
def security_tests_page():
    return send_from_directory(dashboard.WEB_DIR, "test.html")


@ui_bp.route("/assets/<path:name>")
def assets(name):
    return send_from_directory(dashboard.WEB_DIR, name)


@ui_bp.get("/api/status")
def status():
    store = current_app.config["DASHBOARD_STORE"]
    runtime = current_app.config["DASHBOARD_RUNTIME"]
    analysis_service = current_app.config["DASHBOARD_ANALYSIS_SERVICE"]
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
        "rag_reason": analysis_service.rag_status_reason if rag_status in {"unavailable", "degraded"} else None,
        "queue": stats["queue"]["pending"] + stats["queue"]["running"],
        "database": "ok",
        "database_bytes": stats["database"]["bytes"],
        "review_events": stats["reviews"]["event_count"],
        "hardware": __import__("llm").detect_system_hardware(),
    })


@ui_bp.get("/api/dependencies")
def dependencies():
    cfg = current_app.config["DASHBOARD_CFG"]
    return jsonify(dashboard._dependency_health(cfg))


@ui_bp.get("/api/models")
def models():
    cfg = current_app.config["DASHBOARD_CFG"]
    try:
        return jsonify({"models": dashboard._model_list(cfg)})
    except requests.Timeout as exc:
        return dashboard._error(f"Ollama timeout: {exc}", 504)
    except requests.RequestException as exc:
        return dashboard._error(f"Ollama unavailable: {exc}", 503)


@ui_bp.post("/api/models/preload")
def preload_model():
    dashboard._validate_origin()
    body = dashboard._json_body()
    cfg = current_app.config["DASHBOARD_CFG"]
    model = body.get("model")
    if not isinstance(model, str) or model not in dashboard._allowed_models(cfg):
        return dashboard._error("Model không thuộc dashboard.allowed_models", 422)
    if not _model_preload_lock.acquire(blocking=False):
        return dashboard._error("Ollama đang nạp model. Hãy thử lại sau.", 409)
    try:
        if current_app.config["DASHBOARD_STORE"].active_job_count():
            return dashboard._error("Hàng đợi đang phân tích. Hãy nạp model khi hàng đợi trống.", 409)
        service = current_app.config["DASHBOARD_ANALYSIS_SERVICE"]
        params = dashboard._resolve_llm_parameters(body, cfg)
        options = ollama_options(service.window_llm_parameters(model, params))
        base_url = cfg["ollama"]["base_url"]
        validate_ollama_base_url(base_url, allow_remote=cfg["ollama"].get("allow_remote", False))
        # ponytail: let Ollama manage residency; add a queue only if preload needs scheduling.
        response = requests.post(
            f"{base_url.rstrip('/')}/api/chat", timeout=service.timeout, allow_redirects=False,
            json={"model": model, "messages": [], "stream": False,
                  "options": options, "keep_alive": DASHBOARD_MODEL_KEEP_ALIVE},
        )
        if response.status_code == 404:
            return dashboard._error("Model chưa được cài trong Ollama.", 404)
        result = response.json() if response.status_code == 200 else None
        if not isinstance(result, dict) or result.get("done") is not True:
            return dashboard._error("Ollama không xác nhận đã nạp model.", 502)
        return jsonify({"model": model})
    except requests.Timeout:
        return dashboard._error("Ollama nạp model quá thời gian chờ.", 504)
    except requests.RequestException:
        return dashboard._error("Không nhận được phản hồi hợp lệ từ Ollama.", 503)
    finally:
        _model_preload_lock.release()
