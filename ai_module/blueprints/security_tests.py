"""ai_module/blueprints/security_tests.py — Security test catalog and run execution."""

import re

from flask import Blueprint, current_app, jsonify

from security_test_runner import SecurityTestBusyError, SecurityTestConfigurationError
import dashboard


security_tests_bp = Blueprint("security_tests", __name__)


@security_tests_bp.get("/api/security-tests/catalog")
def security_test_catalog():
    security_test_runner = current_app.config["SECURITY_TEST_RUNNER"]
    return jsonify(security_test_runner.catalog())


@security_tests_bp.post("/api/security-tests/runs")
def create_security_test_run():
    dashboard._validate_origin()
    body = dashboard._json_body()
    cfg = current_app.config["DASHBOARD_CFG"]
    security_test_runner = current_app.config["SECURITY_TEST_RUNNER"]

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
        return dashboard._error(str(exc), 409)
    except SecurityTestConfigurationError as exc:
        return dashboard._error(str(exc), 422)
    return jsonify({"run": run}), 202


@security_tests_bp.get("/api/security-tests/runs/<run_id>")
def get_security_test_run(run_id):
    security_test_runner = current_app.config["SECURITY_TEST_RUNNER"]
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        return dashboard._error("Invalid security test run ID", 404)
    run = security_test_runner.get_run(run_id)
    if not run:
        return dashboard._error("Không tìm thấy security test run", 404)
    return jsonify({"run": run})
