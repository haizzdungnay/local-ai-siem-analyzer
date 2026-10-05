"""ai_module/blueprints/ip_analysis.py — Active source IP queries and behavior analysis."""

import ipaddress
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request

import dashboard


ip_analysis_bp = Blueprint("ip_analysis", __name__)

_IP_LOOKBACKS = frozenset({300, 900, 1800, 3600, 7200, 21600, 43200, 86400, 259200, 604800, 2592000})


def _build_empty_ip_payload(source_ip: str, lookback_seconds: int, language: str) -> dict:
    is_vi = language == "vi"
    if not source_ip:
        summary = "Không có cảnh báo nào trong khoảng thời gian đã chọn." if is_vi else "No alerts were found in the selected time range."
        next_step = "Tiếp tục giám sát." if is_vi else "Continue monitoring."
    else:
        summary = f"Không có cảnh báo nào từ IP {source_ip} trong khoảng thời gian đã chọn." if is_vi else f"No alerts from IP {source_ip} were found in the selected time range."
        next_step = "Tiếp tục giám sát IP này." if is_vi else "Continue monitoring this IP."

    return {
        "source_ip": source_ip or "None",
        "total_alerts": 0,
        "lookback_seconds": lookback_seconds,
        "first_seen": "",
        "last_seen": "",
        "analysis": {
            "summary": summary,
            "intent": "Không phát hiện hoạt động" if is_vi else "No activity detected",
            "severity": "low",
            "kill_chain_stages": ["Không phát hiện giai đoạn tấn công" if is_vi else "No attack stage detected"],
            "targeted_assets": [],
            "mitre": [],
            "next_steps": [next_step],
            "response_language": language,
            "confidence": 100.0,
            "assessment_basis": {
                "observed_facts": [
                    "Không tìm thấy alert trong Wazuh Indexer."
                    if is_vi else "No alert was found in Wazuh Indexer."
                ],
                "inferences": [],
                "uncertainties": [],
                "limitations": [],
            },
        },
    }


def _resolve_target_ip(body: dict, cfg: dict, start: datetime, now: datetime) -> str:
    source_ip = body.get("source_ip")
    auto_mode = body.get("auto", False) is True

    if auto_mode or not source_ip or not str(source_ip).strip():
        top_ips = dashboard.fetch_active_source_ips(cfg, start=start, end=now, limit=1)
        source_ip = top_ips[0]["ip"] if top_ips else ""

    if source_ip:
        try:
            parsed_ip = ipaddress.ip_address(str(source_ip).strip())
            if parsed_ip.version != 4:
                raise ValueError("Chỉ hỗ trợ địa chỉ IPv4")
            source_ip = str(parsed_ip)
        except ValueError as exc:
            raise ValueError(f"Địa chỉ IP không hợp lệ: {source_ip}") from exc
    return source_ip


def _fetch_and_aggregate_ip_alerts(cfg: dict, dashboard_cfg: dict, source_ip: str, start: datetime, now: datetime) -> dict:
    fetched = dashboard.fetch_alerts_window(
        cfg,
        start=start,
        end=now,
        source_ip=source_ip,
        max_alerts=dashboard_cfg.get("max_window_alerts", 2000),
        summary_only=False,
    )
    if fetched.get("analysis_mode") == "aggregate":
        return dashboard.aggregate_rule_buckets(fetched)
    return dashboard.aggregate_alerts(fetched.get("alerts", []))


def _format_ip_analysis_payload(source_ip: str, lookback_seconds: int, aggregate: dict, result: dict) -> dict:
    groups = aggregate.get("groups") or []
    first_seen = min((group.get("first_seen", "") for group in groups if group.get("first_seen")), default="")
    last_seen = max((group.get("last_seen", "") for group in groups if group.get("last_seen")), default="")
    return {
        "source_ip": source_ip,
        "total_alerts": aggregate.get("total_alerts", 0),
        "unique_rules": aggregate.get("unique_rules", 0),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "lookback_seconds": lookback_seconds,
        "analysis": result["analysis"],
        "coverage": result["coverage"],
        "provenance": result["provenance"],
    }


@ip_analysis_bp.get("/api/active-ips")
def get_active_ips():
    cfg = current_app.config["DASHBOARD_CFG"]
    lookback_seconds = request.args.get("lookback_seconds", 604800)
    try:
        lookback_seconds = int(lookback_seconds)
    except (ValueError, TypeError):
        lookback_seconds = 604800
    if lookback_seconds not in _IP_LOOKBACKS:
        lookback_seconds = 604800
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=lookback_seconds)
    try:
        ips = dashboard.fetch_active_source_ips(cfg, start=start, end=now, limit=50)
    except Exception:
        ips = []
    return jsonify({"ips": ips, "lookback_seconds": lookback_seconds})


@ip_analysis_bp.post("/api/ip-analysis")
def analyze_ip_behavior():
    dashboard._validate_origin()
    body = dashboard._json_body()
    cfg = current_app.config["DASHBOARD_CFG"]
    dashboard_cfg = cfg.get("dashboard", {})
    analysis_service = current_app.config["DASHBOARD_ANALYSIS_SERVICE"]

    lookback_seconds = body.get("lookback_seconds", 604800)
    if (
        not isinstance(lookback_seconds, int)
        or isinstance(lookback_seconds, bool)
        or lookback_seconds not in _IP_LOOKBACKS
    ):
        raise ValueError("Khoảng suy luận IP phải từ 5 phút đến tối đa 30 ngày")

    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=lookback_seconds)
    source_ip = _resolve_target_ip(body, cfg, start, now)

    model = body.get("model", cfg.get("ollama", {}).get("model", "qwen2.5:7b"))
    if model not in dashboard._allowed_models(cfg):
        raise ValueError("Model không thuộc dashboard.allowed_models")

    language = dashboard._resolve_language(body, dashboard_cfg)
    if not source_ip:
        return jsonify(_build_empty_ip_payload("", lookback_seconds, language))

    aggregate = _fetch_and_aggregate_ip_alerts(cfg, dashboard_cfg, source_ip, start, now)
    if not aggregate.get("total_alerts"):
        return jsonify(_build_empty_ip_payload(source_ip, lookback_seconds, language))

    result = analysis_service.analyze_ip_profile_aggregate(
        aggregate=aggregate,
        source_ip=source_ip,
        model=model,
        language=language,
    )
    return jsonify(_format_ip_analysis_payload(source_ip, lookback_seconds, aggregate, result))
