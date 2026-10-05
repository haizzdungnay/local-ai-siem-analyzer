"""ai_module/blueprints/ui.py — Static UI assets, status, dependency health and models."""

import requests
from flask import Blueprint, current_app, jsonify, send_from_directory

import dashboard


ui_bp = Blueprint("ui", __name__)


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
        "rag_reason": analysis_service.rag_status_reason if rag_status == "unavailable" else None,
        "queue": stats["queue"]["pending"] + stats["queue"]["running"],
        "database": "ok",
        "database_bytes": stats["database"]["bytes"],
        "review_events": stats["reviews"]["event_count"],
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
