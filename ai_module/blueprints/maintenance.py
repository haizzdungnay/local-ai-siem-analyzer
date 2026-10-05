"""ai_module/blueprints/maintenance.py — Database retention preview, prune, backup and restore."""

from flask import Blueprint, current_app, jsonify

import dashboard


maintenance_bp = Blueprint("maintenance", __name__)


@maintenance_bp.get("/api/maintenance")
def maintenance():
    store = current_app.config["DASHBOARD_STORE"]
    dashboard_cfg = current_app.config["DASHBOARD_CFG"].get("dashboard", {})
    return jsonify({
        "retention_enabled": dashboard_cfg.get("retention_days", 0) > 0,
        "policy": {
            "retention_days": dashboard_cfg.get("retention_days", 0),
            "retention_keep_latest": dashboard_cfg.get("retention_keep_latest", 20),
        },
        "stats": store.maintenance_stats(),
        "backups": store.list_retention_backups(),
    })


@maintenance_bp.get("/api/maintenance/preview")
def maintenance_preview():
    store = current_app.config["DASHBOARD_STORE"]
    dashboard_cfg = current_app.config["DASHBOARD_CFG"].get("dashboard", {})
    return jsonify(store.retention_preview(
        retention_days=dashboard_cfg.get("retention_days", 0),
        keep_latest=dashboard_cfg.get("retention_keep_latest", 20),
    ))


@maintenance_bp.post("/api/maintenance/prune")
def prune_maintenance():
    dashboard._validate_origin()
    body = dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    dashboard_cfg = current_app.config["DASHBOARD_CFG"].get("dashboard", {})
    if body.get("confirm") is not True:
        raise ValueError("confirm phai la true de prune")
    preview = store.retention_preview(
        retention_days=dashboard_cfg.get("retention_days", 0),
        keep_latest=dashboard_cfg.get("retention_keep_latest", 20),
    )
    if dashboard_cfg.get("require_preview_token") and body.get("confirmation_token") != preview["confirmation_token"]:
        raise ValueError("confirmation_token khong hop le hoac da het han; hay preview lai")
    result = store.prune_terminal_jobs(
        retention_days=dashboard_cfg.get("retention_days", 0),
        keep_latest=dashboard_cfg.get("retention_keep_latest", 20),
    )
    result.update({
        "confirmed": True,
        "preview_candidate_count": preview["candidate_count"],
        "policy": preview["policy"],
        "confirmation_token_required": bool(dashboard_cfg.get("require_preview_token")),
    })
    return jsonify({"result": result, "stats": store.maintenance_stats()})


@maintenance_bp.post("/api/maintenance/backup")
def backup_maintenance():
    dashboard._validate_origin()
    body = dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    dashboard_cfg = current_app.config["DASHBOARD_CFG"].get("dashboard", {})
    if body.get("confirm") is not True:
        raise ValueError("confirm phai la true de tao backup")
    preview = store.retention_preview(
        retention_days=dashboard_cfg.get("retention_days", 0),
        keep_latest=dashboard_cfg.get("retention_keep_latest", 20),
    )
    if dashboard_cfg.get("require_preview_token") and body.get("confirmation_token") != preview["confirmation_token"]:
        raise ValueError("confirmation_token khong hop le hoac da het han; hay preview lai")
    return jsonify({"backup": store.create_retention_backup()})


@maintenance_bp.post("/api/maintenance/restore")
def restore_maintenance():
    dashboard._validate_origin()
    body = dashboard._json_body()
    store = current_app.config["DASHBOARD_STORE"]
    dashboard_cfg = current_app.config["DASHBOARD_CFG"].get("dashboard", {})
    if body.get("confirm") is not True:
        raise ValueError("confirm phai la true de restore")
    filename = body.get("backup")
    if not isinstance(filename, str):
        raise ValueError("backup phai la ten file snapshot")
    preview = store.retention_preview(
        retention_days=dashboard_cfg.get("retention_days", 0),
        keep_latest=dashboard_cfg.get("retention_keep_latest", 20),
    )
    if dashboard_cfg.get("require_preview_token") and body.get("confirmation_token") != preview["confirmation_token"]:
        raise ValueError("confirmation_token khong hop le hoac da het han; hay preview lai")
    return jsonify({"restored": store.restore_retention_backup(filename)})
