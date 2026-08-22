import json
from pathlib import Path

import dashboard
import dashboard_store


def make_cfg(tmp_path):
    return {
        "ollama": {
            "base_url": "http://localhost:11434", "model": "qwen2.5:3b", "timeout": 5,
        },
        "wazuh_indexer": {
            "host": "siem.invalid", "port": 9200, "protocol": "https",
            "user": "reader", "password": "secret", "verify_ssl": False,
        },
        "extractor": {"fields": ["rule.id", "full_log"]},
        "rag": {"enabled": False},
        # Keep tests independent from an operator's ignored local notification files.
        "notifications": {
            "telegram": {"env_file": "telegram.test-missing.env"},
            "gmail": {"env_file": "gmail.test-missing.env"},
        },
        "dashboard": {
            "host": "127.0.0.1", "port": 8765,
            "database_path": str(tmp_path / "dashboard.db"),
            "allowed_models": ["qwen2.5:3b", "qwen2.5:7b"],
            "max_pending_jobs": 2, "max_job_history": 50,
        },
    }


def test_app_serves_ui_and_security_headers(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    response = app.test_client().get("/")

    assert response.status_code == 200
    assert b"Wazuh AI Analyst" in response.data
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Permissions-Policy"] == dashboard.DEFAULT_PERMISSIONS_POLICY
    assert "Strict-Transport-Security" not in response.headers

    security_page = app.test_client().get("/security-tests")
    security_script = app.test_client().get("/assets/test.js")
    dashboard_script = app.test_client().get("/assets/app.js")
    dashboard_style = app.test_client().get("/assets/styles.css")
    assert security_page.headers["Cache-Control"] == "no-store"
    assert security_script.headers["Cache-Control"] == "no-store"
    assert response.headers["Cache-Control"] == "no-store"
    assert dashboard_script.headers["Cache-Control"] == "no-store"
    assert dashboard_style.headers["Cache-Control"] == "no-store"


def test_ip_analysis_validates_window_and_returns_localized_empty_result(tmp_path, monkeypatch):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    monkeypatch.setattr(
        dashboard,
        "fetch_alerts_window",
        lambda *args, **kwargs: {"analysis_mode": "full", "alerts": []},
    )
    client = app.test_client()

    result = client.post(
        "/api/ip-analysis",
        json={
            "source_ip": "192.168.100.30",
            "lookback_seconds": 2592000,
            "model": "qwen2.5:7b",
            "language": "vi",
        },
    )
    assert result.status_code == 200
    assert result.headers["Cache-Control"] == "no-store"
    assert result.get_json()["lookback_seconds"] == 2592000
    assert "Không có cảnh báo" in result.get_json()["analysis"]["summary"]

    too_long = client.post(
        "/api/ip-analysis",
        json={
            "source_ip": "192.168.100.30",
            "lookback_seconds": 2678400,
            "model": "qwen2.5:7b",
            "language": "vi",
        },
    )
    ipv6 = client.post(
        "/api/ip-analysis",
        json={
            "source_ip": "2001:db8::1",
            "lookback_seconds": 604800,
            "model": "qwen2.5:7b",
            "language": "vi",
        },
    )
    assert too_long.status_code == 422
    assert ipv6.status_code == 422


def test_status_tolerates_sqlite_sidecar_disappearing_during_size_check(tmp_path, monkeypatch):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    sidecar = Path(f"{store.path}-shm")
    original_stat = dashboard_store.Path.stat

    def race_stat(path, *args, **kwargs):
        if str(path) == str(sidecar):
            raise FileNotFoundError("SQLite removed the transient sidecar")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(dashboard_store.Path, "stat", race_stat)

    response = app.test_client().get("/api/status")

    assert response.status_code == 200
    assert response.get_json()["database"] == "ok"
    assert isinstance(response.get_json()["database_bytes"], int)


def test_security_test_page_and_api_are_local_allowlist_only(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["security_tests"] = {
        "enabled": False,
        "attacker_host": "192.168.100.30",
        "attacker_user": "kali",
        "victim_host": "192.168.100.20",
        "ssh_identity_path": "",
    }
    client = dashboard.create_app(cfg=cfg, start_runtime=False).test_client()

    assert client.get("/security-tests").status_code == 200
    catalog = client.get("/api/security-tests/catalog").get_json()
    assert len(catalog["scenarios"]) == 18
    assert catalog["enabled"] is False
    assert catalog["default_model"] == "qwen2.5:7b"
    assert catalog["allowed_models"] == ["qwen2.5:3b", "qwen2.5:7b"]
    assert client.post(
        "/api/security-tests/runs",
        json={"scenario_id": "sql-injection", "confirm": True, "target": "outside"},
    ).status_code == 422
    disabled = client.post(
        "/api/security-tests/runs",
        json={"scenario_id": "sql-injection", "confirm": True},
    )
    assert disabled.status_code == 422
    assert "verified Wazuh telemetry contract" in disabled.get_json()["error"]
    for field, value in {
        "command": "curl outside", "payload": "x", "filter": {"match_all": {}},
        "source_ip": "198.51.100.2", "agent_ip": "198.51.100.3",
    }.items():
        response = client.post(
            "/api/security-tests/runs",
            json={"scenario_id": "file-inclusion", "confirm": True, field: value},
        )
        assert response.status_code == 422


def test_security_test_api_passes_selected_model_and_rejects_disallowed_model(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cfg["security_tests"] = {
        "enabled": False,
        "analysis_model": "qwen2.5:7b",
        "allowed_analysis_models": ["qwen2.5:3b", "qwen2.5:7b"],
        "attacker_host": "192.168.100.30", "attacker_user": "kali",
        "victim_host": "192.168.100.20", "ssh_identity_path": "",
    }
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    runner = app.config["SECURITY_TEST_RUNNER"]
    captured = []

    def start(scenario_id, *, model=None):
        captured.append((scenario_id, model))
        if model not in {"qwen2.5:3b", "qwen2.5:7b"}:
            raise dashboard.SecurityTestConfigurationError("Selected AI model is not allowed for security tests.")
        return {"id": "a" * 32, "scenario_id": scenario_id, "analysis_model": model}

    monkeypatch.setattr(runner, "start", start)
    client = app.test_client()

    selected = client.post(
        "/api/security-tests/runs",
        json={"scenario_id": "file-inclusion", "model": "qwen2.5:3b", "confirm": True},
    )
    defaulted = client.post(
        "/api/security-tests/runs",
        json={"scenario_id": "file-inclusion", "confirm": True},
    )
    rejected = client.post(
        "/api/security-tests/runs",
        json={"scenario_id": "file-inclusion", "model": "other:latest", "confirm": True},
    )
    malformed = client.post(
        "/api/security-tests/runs",
        json={"scenario_id": "file-inclusion", "model": None, "confirm": True},
    )

    assert selected.status_code == 202
    assert selected.json["run"]["analysis_model"] == "qwen2.5:3b"
    assert defaulted.status_code == 202
    assert rejected.status_code == 422
    assert malformed.status_code == 422
    assert captured == [
        ("file-inclusion", "qwen2.5:3b"),
        ("file-inclusion", "qwen2.5:7b"),
    ]


def test_security_catalog_intersects_allowlist_with_installed_models_and_start_rechecks(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cfg["security_tests"] = {
        "enabled": False, "analysis_model": "qwen2.5:7b",
        "allowed_analysis_models": ["qwen2.5:3b", "qwen2.5:7b"],
        "attacker_host": "192.168.100.30", "attacker_user": "kali",
        "victim_host": "192.168.100.20", "ssh_identity_path": "",
    }
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    runner = app.config["SECURITY_TEST_RUNNER"]
    runner.model_provider = lambda: ["qwen2.5:3b"]

    catalog = runner.catalog()

    # Disabled runner still exposes the configured choices for diagnosis; the
    # enabled-path preflight behavior is covered directly by model resolution.
    assert catalog["allowed_models"] == ["qwen2.5:3b", "qwen2.5:7b"]
    assert runner._resolve_analysis_model("qwen2.5:3b") == "qwen2.5:3b"
    try:
        runner._resolve_analysis_model("qwen2.5:7b")
    except dashboard.SecurityTestConfigurationError as exc:
        assert "not installed" in str(exc)
    else:
        raise AssertionError("configured but unavailable model must fail before SSH")


def test_security_test_model_config_must_be_a_dashboard_allowlist_subset(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["security_tests"] = {
        "enabled": False, "analysis_model": "qwen2.5:7b",
        "allowed_analysis_models": ["qwen2.5:7b", "other:latest"],
    }

    try:
        dashboard.create_app(cfg=cfg, start_runtime=False)
    except ValueError as exc:
        assert "subset of dashboard.allowed_models" in str(exc)
    else:
        raise AssertionError("security-test models outside the dashboard allowlist must fail startup")

    cfg = make_cfg(tmp_path)
    cfg["security_tests"] = {
        "enabled": False, "analysis_model": "qwen2.5:7b",
        "allowed_analysis_models": ["qwen2.5:3b"],
    }
    try:
        dashboard.create_app(cfg=cfg, start_runtime=False)
    except ValueError as exc:
        assert "analysis_model must be in security_tests.allowed_analysis_models" in str(exc)
    else:
        raise AssertionError("security-test default must be selectable")


def test_security_headers_allow_policy_override_and_only_send_hsts_over_https(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"]["security_headers"] = {
        "permissions_policy": "geolocation=(), camera=()",
        "hsts": "max-age=31536000; includeSubDomains",
    }
    cfg["dashboard"]["trust_proxy_headers"] = True
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    client = app.test_client()

    http = client.get("/")
    assert http.headers["Permissions-Policy"] == "geolocation=(), camera=()"
    assert "Strict-Transport-Security" not in http.headers

    https = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert https.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


def test_permissions_policy_can_be_explicitly_disabled(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"]["security_headers"] = {"permissions_policy": None}
    response = dashboard.create_app(cfg=cfg, start_runtime=False).test_client().get("/")

    assert "Permissions-Policy" not in response.headers


def test_hsts_only_configuration_keeps_permissions_policy_baseline(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"]["security_headers"] = {"hsts": "max-age=60"}
    response = dashboard.create_app(cfg=cfg, start_runtime=False).test_client().get("/")

    assert response.headers["Permissions-Policy"] == dashboard.DEFAULT_PERMISSIONS_POLICY


def test_untrusted_forwarded_proto_cannot_enable_hsts(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"].update(trust_proxy_headers=False, security_headers={"hsts": "max-age=60"})
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    response = app.test_client().get("/", headers={"X-Forwarded-Proto": "https"})

    assert "Strict-Transport-Security" not in response.headers


def test_optional_security_header_config_rejects_crlf(tmp_path):
    for field in ("permissions_policy", "hsts"):
        cfg = make_cfg(tmp_path)
        cfg["dashboard"]["security_headers"] = {field: "safe\r\nInjected: value"}
        try:
            dashboard.create_app(cfg=cfg, start_runtime=False)
        except ValueError as exc:
            assert field in str(exc)
        else:
            raise AssertionError("CRLF security header value must be rejected")


def test_create_job_validates_model_json_and_origin(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    client = app.test_client()

    response = client.post("/api/jobs", data="not json")
    assert response.status_code == 422
    response = client.post("/api/jobs", json={"preset_seconds": 300, "model": "arbitrary"})
    assert response.status_code == 422
    response = client.post(
        "/api/jobs", json={"preset_seconds": 300, "model": "qwen2.5:3b"},
        headers={"Origin": "http://evil.invalid"},
    )
    assert response.status_code == 422
    response = client.post(
        "/api/jobs",
        json={"preset_seconds": 300, "model": "qwen2.5:3b", "language": "fr"},
    )
    assert response.status_code == 422


def test_dashboard_accepts_tunnel_origin_and_uses_exact_cors_allowlist(tmp_path):
    cfg = make_cfg(tmp_path)
    tunnel_origin = "https://bagging-escargot-repaint.ngrok-free.dev"
    cfg["dashboard"]["cors_allowed_origins"] = [tunnel_origin]
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    client = app.test_client()

    # A loopback-only Waitress process may trust its single local tunnel proxy.
    forwarded = {
        "Origin": tunnel_origin,
        "X-Forwarded-Host": "bagging-escargot-repaint.ngrok-free.dev",
        "X-Forwarded-Proto": "https",
    }
    accepted = client.post(
        "/api/jobs",
        json={"preset_seconds": 300, "model": "qwen2.5:3b"},
        headers=forwarded,
    )
    assert accepted.status_code == 202

    preflight = client.options(
        "/api/schedule",
        headers={
            "Origin": tunnel_origin,
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["Access-Control-Allow-Origin"] == tunnel_origin
    assert "PUT" in preflight.headers["Access-Control-Allow-Methods"]
    assert preflight.headers["Access-Control-Allow-Headers"] == "Content-Type"
    assert preflight.headers["Vary"] == "Origin"

    rejected = client.put(
        "/api/schedule",
        json={"enabled": True, "interval_seconds": 300, "model": "qwen2.5:3b"},
        headers={"Origin": "https://evil.invalid"},
    )
    assert rejected.status_code == 422
    assert "Access-Control-Allow-Origin" not in rejected.headers


def test_forwarded_host_cannot_spoof_same_origin_without_allowlist(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    response = app.test_client().post(
        "/api/jobs",
        json={"preset_seconds": 300, "model": "qwen2.5:3b"},
        headers={
            "Origin": "https://evil.invalid",
            "X-Forwarded-Host": "evil.invalid",
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.status_code == 422
    assert "Cross-origin" in response.json["error"]


def test_create_job_accepts_preset_and_never_accepts_index_dsl(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    client = app.test_client()
    response = client.post(
        "/api/jobs",
        json={
            "preset_seconds": 300, "model": "qwen2.5:3b",
            "index": ".opendistro_security", "query": {"match_all": {}},
        },
    )

    assert response.status_code == 202
    job = client.get(f"/api/jobs/{response.json['job_id']}").json
    assert job["job_type"] == "manual_window"
    assert job["language"] == "vi"
    assert ".opendistro_security" not in str(job)


def test_create_job_persists_validated_advanced_llm_snapshot_without_prompt_in_api(tmp_path):
    cfg = make_cfg(tmp_path)
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    response = app.test_client().post(
        "/api/jobs",
        json={
            "preset_seconds": 300, "model": "qwen2.5:3b",
            "llm_parameters": {
                "temperature": 0.25, "top_p": 0.8, "max_tokens": 512,
                "system_prompt": "Prioritize endpoint telemetry.",
            },
        },
    )
    assert response.status_code == 202
    detail = app.test_client().get(f"/api/jobs/{response.json['job_id']}").json
    assert detail["llm_parameters"]["temperature"] == 0.25
    assert detail["llm_parameters"]["has_custom_system_prompt"] is True
    assert "Prioritize endpoint telemetry." not in json.dumps(detail)

    invalid = app.test_client().post(
        "/api/jobs",
        json={
            "preset_seconds": 300, "model": "qwen2.5:3b",
            "llm_parameters": {"max_tokens": 8},
        },
    )
    assert invalid.status_code == 400


def test_invalid_manual_llm_parameters_return_400_without_creating_jobs(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    client = app.test_client()
    store = app.config["DASHBOARD_STORE"]
    invalid_parameters = [
        {"temperature": -1}, {"temperature": 3},
        {"top_p": 0.04}, {"top_p": 1.01},
        {"max_tokens": 63}, {"max_tokens": 8193},
        {"system_prompt": "x" * 4001},
        {"system_prompt": "authorization: Bearer should-not-be-stored"},
    ]

    for parameters in invalid_parameters:
        response = client.post(
            "/api/jobs",
            json={
                "preset_seconds": 300,
                "model": "qwen2.5:3b",
                "llm_parameters": parameters,
            },
        )

        assert response.status_code == 400
        assert response.json["error"].startswith("Invalid LLM parameters:")
        assert store.active_job_count() == 0
        if "system_prompt" in parameters:
            assert parameters["system_prompt"] not in response.get_data(as_text=True)


def test_models_intersects_ollama_with_allowlist(monkeypatch, tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"models": [
                {"name": "qwen2.5:3b", "digest": "a", "details": {"parameter_size": "3B"}},
                {"name": "other:latest", "digest": "b", "details": {}},
            ]}

    monkeypatch.setattr(dashboard.requests, "get", lambda *args, **kwargs: Response())
    response = app.test_client().get("/api/models")

    assert response.status_code == 200
    assert [model["name"] for model in response.json["models"]] == ["qwen2.5:3b"]


def test_schedule_validates_fixed_interval_and_model(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    client = app.test_client()
    bad = client.put(
        "/api/schedule", json={"enabled": True, "interval_seconds": 42, "model": "qwen2.5:3b"}
    )
    assert bad.status_code == 422

    good = client.put(
        "/api/schedule", json={
            "enabled": True, "interval_seconds": 300,
            "model": "qwen2.5:7b", "language": "en",
        }
    )
    assert good.status_code == 200
    assert good.json["enabled"] == 1
    assert good.json["model"] == "qwen2.5:7b"
    assert good.json["language"] == "en"


def test_schedule_snapshots_llm_parameters_and_keeps_custom_prompt_private(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    client = app.test_client()
    payload = {
        "enabled": True, "interval_seconds": 300, "model": "qwen2.5:7b",
        "llm_parameters": {
            "temperature": 0.4, "top_p": 0.75, "max_tokens": 768,
            "system_prompt": "Prioritize endpoint telemetry.",
        },
    }
    saved = client.put("/api/schedule", json=payload)
    assert saved.status_code == 200
    assert saved.json["llm_parameters"]["max_tokens"] == 768
    assert saved.json["llm_parameters"]["has_custom_system_prompt"] is True
    assert "Prioritize endpoint telemetry." not in json.dumps(saved.json)

    # An omitted nested object preserves hidden schedule guidance on later edits.
    updated = client.put(
        "/api/schedule",
        json={"enabled": True, "interval_seconds": 900, "model": "qwen2.5:7b"},
    )
    assert updated.status_code == 200
    runtime = app.config["DASHBOARD_RUNTIME"]
    assert runtime.store.get_schedule(include_llm_parameters=True)["llm_parameters"]["system_prompt"] == (
        "Prioritize endpoint telemetry."
    )


def test_invalid_schedule_llm_parameters_return_400_without_mutating_schedule(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    client = app.test_client()
    store = app.config["DASHBOARD_STORE"]
    initial = store.get_schedule(include_llm_parameters=True)
    invalid_parameters = [
        {"temperature": -1}, {"temperature": 3},
        {"top_p": 0.04}, {"top_p": 1.01},
        {"max_tokens": 63}, {"max_tokens": 8193},
        {"system_prompt": "x" * 4001},
        {"system_prompt": "token=should-not-be-stored"},
    ]

    for parameters in invalid_parameters:
        response = client.put(
            "/api/schedule",
            json={
                "enabled": True,
                "interval_seconds": 300,
                "model": "qwen2.5:3b",
                "llm_parameters": parameters,
            },
        )

        assert response.status_code == 400
        assert response.json["error"].startswith("Invalid LLM parameters:")
        assert store.get_schedule(include_llm_parameters=True) == initial
        if "system_prompt" in parameters:
            assert parameters["system_prompt"] not in response.get_data(as_text=True)


def test_telegram_delivery_channel_is_opt_in_and_requires_configuration(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    client = app.test_client()

    unavailable = client.post(
        "/api/jobs", json={"preset_seconds": 300, "model": "qwen2.5:3b", "delivery_channel": "telegram"}
    )
    assert unavailable.status_code == 422
    assert client.get("/api/notifications/status").json["telegram"]["configured"] is False

    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "123456789")
    cfg["notifications"] = {"telegram": {"enabled": True}}
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    client = app.test_client()
    response = client.post(
        "/api/jobs", json={"preset_seconds": 300, "model": "qwen2.5:3b", "delivery_channel": "telegram"}
    )
    assert response.status_code == 202
    job = client.get(f"/api/jobs/{response.json['job_id']}").json
    assert job["delivery_channel"] == "telegram"
    assert job["delivery"] is None


def test_telegram_test_route_requires_confirmation_and_does_not_return_secret(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cfg["notifications"] = {"telegram": {"enabled": True}}
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "123456789")
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    runtime = app.config["DASHBOARD_RUNTIME"]
    called = {}
    monkeypatch.setattr(runtime.telegram_notifier, "send_test", lambda: called.update(done=True) or {"message_id": "7"})
    client = app.test_client()

    assert client.post("/api/notifications/telegram/test", json={}).status_code == 422
    response = client.post("/api/notifications/telegram/test", json={"confirm": True})
    assert response.status_code == 202
    assert response.json == {"status": "sent", "message_id": "7"}
    assert called == {"done": True}
    assert "TEST_TOKEN" not in response.get_data(as_text=True)


def test_telegram_settings_route_requires_confirmation_and_hides_credentials(tmp_path, monkeypatch):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    runtime = app.config["DASHBOARD_RUNTIME"]
    captured = {}
    monkeypatch.setattr(
        runtime.telegram_notifier,
        "configure_local",
        lambda **kwargs: captured.update(kwargs) or {
            "channel": "telegram", "enabled": True, "configured": True,
            "max_message_chars": 3500,
        },
    )
    client = app.test_client()

    assert client.post("/api/notifications/telegram/settings", json={}).status_code == 422
    response = client.post(
        "/api/notifications/telegram/settings",
        json={
            "confirm": True,
            "bot_token": "123456:TEST_TOKEN_SHOULD_NOT_LEAK",
            "chat_id": "-100123456",
        },
    )

    assert response.status_code == 201
    assert captured == {
        "token": "123456:TEST_TOKEN_SHOULD_NOT_LEAK", "chat_id": "-100123456",
    }
    assert response.json == {
        "status": "saved",
        "telegram": {
            "channel": "telegram", "enabled": True, "configured": True,
            "max_message_chars": 3500,
        },
    }
    body = response.get_data(as_text=True)
    assert "TEST_TOKEN" not in body
    assert "-100123456" not in body


def test_gmail_delivery_channel_is_opt_in_and_requires_configuration(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    client = app.test_client()

    unavailable = client.post(
        "/api/jobs", json={"preset_seconds": 300, "model": "qwen2.5:3b", "delivery_channel": "gmail"}
    )
    assert unavailable.status_code == 422
    assert client.get("/api/notifications/status").json["gmail"]["configured"] is False

    monkeypatch.setenv("SIEM_GMAIL_SENDER_EMAIL", "sender@example.com")
    monkeypatch.setenv("SIEM_GMAIL_APP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setenv("SIEM_GMAIL_RECIPIENT_EMAIL", "recipient@example.com")
    cfg["notifications"] = {"gmail": {"enabled": True}}
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    client = app.test_client()
    response = client.post(
        "/api/jobs", json={"preset_seconds": 300, "model": "qwen2.5:3b", "delivery_channel": "gmail"}
    )
    assert response.status_code == 202
    job = client.get(f"/api/jobs/{response.json['job_id']}").json
    assert job["delivery_channel"] == "gmail"


def test_gmail_test_and_settings_routes_hide_secret_and_address(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cfg["notifications"] = {"gmail": {"enabled": True}}
    monkeypatch.setenv("SIEM_GMAIL_SENDER_EMAIL", "sender@example.com")
    monkeypatch.setenv("SIEM_GMAIL_APP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setenv("SIEM_GMAIL_RECIPIENT_EMAIL", "recipient@example.com")
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    runtime = app.config["DASHBOARD_RUNTIME"]
    captured = {}
    monkeypatch.setattr(
        runtime.gmail_notifier,
        "configure_local",
        lambda **kwargs: captured.update(kwargs) or {
            "channel": "gmail", "enabled": True, "configured": True, "max_body_chars": 20_000,
        },
    )
    called = {}
    monkeypatch.setattr(runtime.gmail_notifier, "send_test", lambda: called.update(done=True) or {"message_id": "mail-7"})
    client = app.test_client()

    assert client.post("/api/notifications/gmail/settings", json={}).status_code == 422
    saved = client.post(
        "/api/notifications/gmail/settings",
        json={
            "confirm": True,
            "sender_email": "sender@example.com",
            "app_password": "abcdefghijklmnop",
            "recipient_email": "recipient@example.com",
        },
    )
    assert saved.status_code == 201
    assert captured == {
        "sender_email": "sender@example.com",
        "app_password": "abcdefghijklmnop",
        "recipient_email": "recipient@example.com",
    }
    assert saved.json["gmail"] == {
        "channel": "gmail", "enabled": True, "configured": True, "max_body_chars": 20_000,
    }
    assert "abcdefghijklmnop" not in saved.get_data(as_text=True)
    assert "recipient@example.com" not in saved.get_data(as_text=True)

    assert client.post("/api/notifications/gmail/test", json={}).status_code == 422
    tested = client.post("/api/notifications/gmail/test", json={"confirm": True})
    assert tested.status_code == 202
    assert tested.json == {"status": "sent", "message_id": "mail-7"}
    assert called == {"done": True}


def test_terminal_job_can_queue_one_manual_telegram_delivery(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cfg["notifications"] = {"telegram": {"enabled": True}}
    monkeypatch.setenv("SIEM_TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setenv("SIEM_TELEGRAM_CHAT_ID", "123456789")
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-07-30T10:00:00.000Z", "2026-07-30T11:00:00.000Z",
        "qwen2.5:3b", "dashboard-v5",
    )
    store.complete_job(job_id, "succeeded")
    client = app.test_client()

    rejected = client.post(f"/api/jobs/{job_id}/delivery", json={"channel": "telegram"})
    queued = client.post(
        f"/api/jobs/{job_id}/delivery", json={"channel": "telegram", "confirm": True}
    )
    duplicate = client.post(
        f"/api/jobs/{job_id}/delivery", json={"channel": "telegram", "confirm": True}
    )

    assert rejected.status_code == 422
    assert queued.status_code == 202
    assert duplicate.status_code == 202
    assert queued.json["delivery"]["id"] == duplicate.json["delivery"]["id"]
    assert store.get_job_detail(job_id)["delivery"]["status"] == "pending"


def test_delivery_resend_route_requires_explicit_force_for_sent_item(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-07-30T10:00:00.000Z", "2026-07-30T11:00:00.000Z",
        "qwen2.5:3b", "dashboard-v6", delivery_channel="gmail",
    )
    store.complete_job(job_id, "succeeded")
    delivery = store.enqueue_delivery(job_id, "gmail")
    claimed = store.claim_next_delivery()
    store.mark_delivery_sent(claimed["id"], payload_sha256="a" * 64, provider_message_id="mail-1")
    client = app.test_client()

    rejected = client.post(f"/api/deliveries/{delivery['id']}/retry", json={"confirm": True})
    malformed = client.post(
        f"/api/deliveries/{delivery['id']}/retry", json={"confirm": True, "force": "yes"}
    )
    resent = client.post(
        f"/api/deliveries/{delivery['id']}/retry", json={"confirm": True, "force": True}
    )

    assert rejected.status_code == 422
    assert malformed.status_code == 422
    assert resent.status_code == 202
    assert resent.json["delivery"]["status"] == "pending"


def test_full_alert_route_uses_server_side_reference(monkeypatch, tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:3b", "dashboard-v1",
    )
    store.replace_job_data(job_id, {
        "groups": [{"group_key": "g", "count": 1}],
        "alerts": [{
            "_index": "wazuh-alerts-4.x-2026.07.30", "_id": "abc",
            "timestamp": "2026-07-30T11:30:00Z", "rule_id": "5503", "rule_level": 5,
            "description": "PAM failed", "agent": "victim", "source_ip": "192.0.2.30",
            "group_key": "g",
        }],
    })
    row_id = store.get_job_detail(job_id)["alerts"][0]["id"]
    called = {}

    def fake_fetch(cfg, index_name, document_id):
        called.update(index=index_name, document=document_id)
        return {"_index": index_name, "_id": document_id, "_source": {"full_log": "safe"}}

    monkeypatch.setattr(dashboard, "fetch_alert_document", fake_fetch)
    response = app.test_client().get(f"/api/job-alerts/{row_id}?index=.opendistro_security")

    assert response.status_code == 200
    assert called == {"index": "wazuh-alerts-4.x-2026.07.30", "document": "abc"}
    assert "_source" not in response.json
    assert response.json["redactions"]["raw_source"] is True


def test_json_request_size_limit_rejects_before_endpoint_parsing(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"]["max_json_request_bytes"] = 64
    app = dashboard.create_app(cfg=cfg, start_runtime=False)

    response = app.test_client().post(
        "/api/jobs",
        data=b'{"model":"qwen2.5:3b","padding":"' + (b"x" * 80) + b'"}',
        content_type="application/json",
    )

    assert response.status_code == 413
    assert response.json == {"error": "JSON request body is too large"}


def test_status_reports_rag_lifecycle_without_initializing_on_health_check(monkeypatch, tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["rag"] = {"enabled": True, "data_dir": "rag_data", "embedding_model": "embed"}
    app = dashboard.create_app(cfg=cfg, start_runtime=False)

    status = app.test_client().get("/api/status").get_json()
    assert status["rag"] == "not_initialized"
    assert status["rag_reason"] is None

    class ReadyRAG:
        def __init__(self, **kwargs):
            pass

        def ensure_indexed(self):
            return 0

    monkeypatch.setattr("analysis_service.RuleRAG", ReadyRAG)
    service = app.config["DASHBOARD_RUNTIME"].analysis_service
    assert service._ensure_rag() is not None
    assert app.test_client().get("/api/status").get_json()["rag"] == "ready"


def test_status_reports_disabled_and_sanitized_rag_initialization_failure(monkeypatch, tmp_path):
    disabled = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    assert disabled.test_client().get("/api/status").get_json()["rag"] == "disabled"

    cfg = make_cfg(tmp_path)
    cfg["rag"] = {"enabled": True, "data_dir": "rag_data", "embedding_model": "embed"}
    app = dashboard.create_app(cfg=cfg, start_runtime=False)

    class PrivateFailure(Exception):
        pass

    class BrokenRAG:
        def __init__(self, **kwargs):
            raise PrivateFailure("token=super-secret")

    monkeypatch.setattr("analysis_service.RuleRAG", BrokenRAG)
    service = app.config["DASHBOARD_RUNTIME"].analysis_service
    assert service._ensure_rag() is None
    status = app.test_client().get("/api/status").get_json()
    assert status["rag"] == "unavailable"
    assert status["rag_reason"] == "PrivateFailure"


def test_alert_detail_dto_masks_pii_and_excludes_raw_source(monkeypatch, tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:3b", "dashboard-v1",
    )
    store.replace_job_data(job_id, {
        "groups": [{"group_key": "g", "count": 1}],
        "alerts": [{
            "_index": "wazuh-alerts-4.x-2026.07.30", "_id": "abc",
            "timestamp": "2026-07-30T11:30:00Z", "rule_id": "5503", "rule_level": 5,
            "description": "PAM failed", "agent": "victim", "source_ip": "192.0.2.30",
            "group_key": "g",
        }],
    })
    row_id = store.get_job_detail(job_id)["alerts"][0]["id"]

    monkeypatch.setattr(dashboard, "fetch_alert_document", lambda *args: {
        "_index": "wazuh-alerts-4.x-2026.07.30",
        "_id": "abc",
        "_source": {
            "timestamp": "2026-07-30T11:30:00Z",
            "rule": {
                "id": "5503", "level": 5, "description": "PAM password=hidden failed",
                "mitre": {"id": ["T1110"]},
            },
            "agent": {"id": "agent-007", "name": "Alice-Laptop", "ip": "192.0.2.12"},
            "data": {"srcip": "203.0.113.85", "password": "DO_NOT_EXPOSE"},
            "full_log": "Bearer VERY_SECRET_TOKEN user=alice",
        },
    })

    response = app.test_client().get(f"/api/job-alerts/{row_id}")
    payload = response.get_json()
    serialized = response.get_data(as_text=True)

    assert response.status_code == 200
    assert payload["schema_version"] == "local-ai-siem-alert-detail/v1"
    assert payload["rule"] == {
        "id": "5503", "level": 5, "description": "PAM password=[redacted] failed",
        "mitre_ids": ["T1110"],
    }
    assert payload["agent"]["reference"].startswith("agent-")
    assert payload["network"]["source_ip"] == "203.0.113.0/24"
    assert '"_source":' not in serialized
    for unsafe_value in ("VERY_SECRET_TOKEN", "DO_NOT_EXPOSE", "Alice-Laptop", "203.0.113.85"):
        assert unsafe_value not in serialized


def test_job_history_uses_configured_server_cap(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"]["max_job_history"] = 1
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    first = store.create_job(
        "manual_window", "2026-07-30T10:00:00.000Z", "2026-07-30T11:00:00.000Z",
        "qwen2.5:3b", "dashboard-v1",
    )
    newest = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:3b", "dashboard-v1",
    )
    store.replace_job_data(newest, {
        "alerts": [{
            "_index": "wazuh-alerts-4.x-2026.07.30", "_id": "abc",
            "timestamp": "2026-07-30T11:30:00Z", "rule_id": "31105",
            "rule_level": 7, "description": "XSS attempt", "agent": "victim",
            "source_ip": "192.0.2.30", "group_key": "web-group",
        }],
        "groups": [{"group_key": "web-group", "count": 1}],
    })
    store.save_result(
        newest, "window", "window",
        {"severity": "high", "summary": "Web attack attempt detected"},
    )

    response = app.test_client().get("/api/jobs?limit=200")

    assert response.status_code == 200
    assert [job["id"] for job in response.json["jobs"]] == [newest]
    expected_metrics = {
        "alert_count": 1,
        "group_count": 1,
        "rule_count": 1,
        "agent_count": 1,
        "max_level": 7,
        "ai_severity": "high",
        "ai_summary": "Web attack attempt detected",
    }
    for field, value in expected_metrics.items():
        assert response.json["jobs"][0][field] == value
    assert first != newest


def test_job_history_supports_server_pagination_and_filters(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"]["max_job_history"] = 1  # Legacy calls still have this cap.
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_ids = []
    for index in range(3):
        job_id = store.create_job(
            "manual_window", f"2026-07-30T{10 + index}:00:00.000Z",
            f"2026-07-30T{11 + index}:00:00.000Z", "qwen2.5:3b", "dashboard-v1",
            language="vi" if index != 1 else "en",
        )
        store.replace_job_data(job_id, {"alerts": [{
            "_index": "wazuh-alerts", "_id": str(job_id), "timestamp": "2026-07-30T10:30:00Z",
            "rule_id": "31105", "rule_level": 12 if index == 1 else 5,
            "description": "pagination test", "agent": "host", "source_ip": "192.0.2.1", "group_key": "g",
        }], "groups": [{"group_key": "g", "count": 1}]})
        if index == 1:
            store.save_result(job_id, "window", "window", {"summary": "Needle in history", "severity": "high"})
            store.add_review_event(job_id, status="acknowledged", tags=["needle"])
        job_ids.append(job_id)

    client = app.test_client()
    page = client.get("/api/jobs?page=1&page_size=2")
    assert page.status_code == 200
    assert page.json["total"] == 3 and page.json["pages"] == 2
    assert page.json["page"] == 1 and len(page.json["jobs"]) == 2
    assert [job["id"] for job in page.json["jobs"]] == [job_ids[2], job_ids[1]]
    assert client.get("/api/jobs?page=2&page_size=2").json["jobs"][0]["id"] == job_ids[0]
    assert client.get("/api/jobs?page=1&page_size=2&review=none").json["total"] == 2
    assert client.get("/api/jobs?page=1&page_size=2&severity=12").json["jobs"][0]["id"] == job_ids[1]
    assert client.get("/api/jobs?page=1&page_size=2&search=needle").json["total"] == 1
    empty = client.get("/api/jobs?page=1&page_size=2&status=failed").json
    assert empty["jobs"] == [] and empty["total"] == 0 and empty["pages"] == 1
    assert client.get("/api/jobs?page=99&page_size=2").json["page"] == 2
    assert client.get("/api/jobs?page=1&page_size=2&language=fr").status_code == 400
    assert client.get("/api/jobs?page=0&page_size=2").status_code == 400
    assert client.get("/api/jobs?page=1&page_size=201").status_code == 400
    assert client.get("/api/jobs?page=1&page_size=2&severity=high").status_code == 400


def test_dashboard_rejects_invalid_history_cap(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"]["max_job_history"] = 0

    try:
        dashboard.create_app(cfg=cfg, start_runtime=False)
    except ValueError as exc:
        assert "max_job_history" in str(exc)
    else:
        raise AssertionError("invalid history cap phải bị từ chối")


def test_job_cancel_and_bounded_retry_routes(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    client = app.test_client()
    pending = store.create_job(
        "manual_window", "2026-07-30T10:00:00.000Z", "2026-07-30T11:00:00.000Z",
        "qwen2.5:3b", "dashboard-v1",
    )

    cancelled = client.post(f"/api/jobs/{pending}/cancel", json={})

    assert cancelled.status_code == 202
    assert store.get_job(pending)["cancel_requested"] == 1

    failed = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:3b", "dashboard-v1",
    )
    for retry_count in range(3):
        store.complete_job(failed, "failed", error="controlled failure")
        response = client.post(f"/api/jobs/{failed}/retry", json={})
        assert response.status_code == 202
        assert store.get_job(failed)["retry_count"] == retry_count + 1
    store.complete_job(failed, "failed", error="controlled failure")

    exhausted = client.post(f"/api/jobs/{failed}/retry", json={})

    assert exhausted.status_code == 422
    assert store.get_job(failed)["retry_count"] == 3


def test_blocked_schedule_retry_and_skip_routes(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    client = app.test_client()
    store.configure_schedule(
        enabled=True, interval_seconds=300, model="qwen2.5:3b",
        next_window_start="2026-07-30T10:00:00.000Z",
    )
    store.block_schedule("controlled failure")

    retried = client.post("/api/schedule/retry", json={})

    assert retried.status_code == 200
    assert retried.json["state"] == "active"
    store.block_schedule("controlled failure")
    before = store.get_schedule()

    skipped = client.post("/api/schedule/skip", json={})

    assert skipped.status_code == 200
    assert skipped.json["state"] == "active"
    assert skipped.json["gap_windows"] == before["gap_windows"] + 1
    assert skipped.json["next_window_start"] != before["next_window_start"]


def test_job_export_downloads_reusable_json_with_recorded_ollama_provenance(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-08-04T02:00:00.000Z", "2026-08-04T03:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3", language="vi",
    )
    store.claim_next_job()
    store.replace_job_data(job_id, {
        "analysis_mode": "full",
        "alerts": [{
            "_index": "wazuh-alerts-4.x-2026.08.04", "_id": "abc",
            "timestamp": "2026-08-04T02:30:00Z", "rule_id": "5503",
            "rule_level": 5, "description": "PAM failed", "agent": "victim",
            "source_ip": "192.0.2.30", "group_key": "ssh",
        }],
        "groups": [{
            "group_key": "ssh", "rule_id": "5503", "count": 1,
            "max_level": 5, "sample_log": "raw log must not be exported",
        }],
    })
    analysis = {
        "summary": "Qwen local report", "severity": "medium",
        "key_findings": ["One SSH failure"], "mitre": ["T1110"],
        "next_steps": ["Review source"],
        "confidence": "medium", "response_language": "en",
        "assessment_basis": {
            "observed_facts": ["One rule 5503 alert"],
            "inferences": ["Authentication activity needs review"],
            "uncertainties": ["No login outcome supplied"],
            "limitations": ["One alert in the selected window"],
        },
    }
    store.save_result(
        job_id, "window", "window", analysis,
        coverage={"total_alerts": 1}, latency_s=2.25,
        provenance={
            "provider": "ollama", "transport": "ollama.Client.chat",
            "requested_model": "qwen2.5:7b", "response_model": "qwen2.5:7b",
            "output_origin": "ollama_model", "eval_count": 31,
            "response_content_sha256": "a" * 64,
            "model_digest": "sha256:example",
            "model_digest_source": "ollama.Client.list.post_chat",
            "model_digest_observed_at": "2026-08-04T03:00:01.000Z",
            "prompt_version": "soc-prompt-v1",
            "prompt_sha256": "b" * 64,
            "request_data_sha256": "c" * 64,
            "output_schema_sha256": "d" * 64,
            "requested_language": "vi", "response_language": "en",
            "language_compliance": "partial",
            "ollama_options": {"temperature": 0, "seed": 20260804},
        },
    )
    store.complete_job(job_id, "succeeded", progress_current=1, progress_total=1)

    response = app.test_client().get(f"/api/jobs/{job_id}/export")
    report = response.get_json()

    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert response.headers["Content-Disposition"] == (
        f'attachment; filename="wazuh-ai-job-{job_id}.json"'
    )
    assert report["schema_version"] == "local-ai-siem-report/v2"
    assert report["audit"]["model"]["evidence_status"] == "recorded"
    assert report["audit"]["model"]["provider"] == "ollama"
    assert report["audit"]["model"]["response_model"] == "qwen2.5:7b"
    assert report["audit"]["model"]["model_digest"] == "sha256:example"
    assert report["audit"]["model"]["model_digest_source"] == "ollama.Client.list.post_chat"
    assert report["audit"]["model"]["model_digest_observed_at"] == "2026-08-04T03:00:01.000Z"
    assert report["audit"]["model"]["options"] == {"temperature": 0, "seed": 20260804}
    assert report["audit"]["prompt"]["version"] == "soc-prompt-v1"
    assert report["audit"]["prompt"]["system_prompt_sha256"] == "b" * 64
    assert report["audit"]["input"] == {
        "request_data_sha256": "c" * 64, "output_schema_sha256": "d" * 64,
    }
    assert report["audit"]["language"] == {
        "requested": "vi", "effective": "en", "compliance": "partial",
    }
    assert report["analysis"] == analysis
    assert report["assessment_basis"] == analysis["assessment_basis"]
    assert len(report["analysis_sha256"]) == 64
    assert "sample_log" not in report["groups"][0]
    assert "raw log must not be exported" not in response.get_data(as_text=True)

    v1 = app.test_client().get(f"/api/jobs/{job_id}/export?schema=v1")
    assert v1.status_code == 200
    assert v1.json["schema_version"] == "local-ai-siem-report/v1"
    assert v1.json["model_call"]["wall_latency_s"] == 2.25


def test_job_export_rejects_unknown_schema_and_never_exports_prompt_or_reasoning(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-08-04T02:00:00.000Z", "2026-08-04T03:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3", language="en",
    )
    store.save_result(
        job_id, "window", "window",
        {
            "summary": "Safe result", "severity": "low", "key_findings": [],
            "mitre": [], "next_steps": [], "raw_prompt": "must not export",
            "assessment_basis": {"observed_facts": ["Rule 1"], "reasoning": "hidden"},
        },
        provenance={"system_prompt": "must not export", "language_compliance": "full"},
    )

    invalid = app.test_client().get(f"/api/jobs/{job_id}/export?schema=v999")
    response = app.test_client().get(f"/api/jobs/{job_id}/export")

    assert invalid.status_code == 422
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "must not export" not in text
    assert "hidden" not in text


def test_job_review_is_validated_append_only_and_exported_only_in_v2(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-08-04T02:00:00.000Z", "2026-08-04T03:00:00.000Z",
        "qwen2.5:7b", "dashboard-v4",
    )
    client = app.test_client()

    invalid = client.post(f"/api/jobs/{job_id}/review", json={"status": "closed"})
    review = client.post(f"/api/jobs/{job_id}/review", json={
        "status": "investigating", "severity": "high", "tags": ["ssh", "needs-review"],
        "note": "Validate the source before containment.",
    })
    detail = client.get(f"/api/jobs/{job_id}")
    v2 = client.get(f"/api/jobs/{job_id}/export")
    v1 = client.get(f"/api/jobs/{job_id}/export?schema=v1")

    assert invalid.status_code == 422
    assert review.status_code == 201
    assert review.json["actor"] == "local_analyst"
    assert detail.json["review"] == review.json
    assert detail.json["review_history"] == [review.json]
    assert v2.json["review"] == review.json
    assert v2.json["review_history"] == [review.json]
    assert "review" not in v1.json


def test_bulk_job_review_appends_events_atomically(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    first = store.create_job("manual_window", "2026-08-04T02:00:00.000Z", "2026-08-04T03:00:00.000Z", "qwen2.5:3b", "dashboard-v3")
    second = store.create_job("manual_window", "2026-08-04T03:00:00.000Z", "2026-08-04T04:00:00.000Z", "qwen2.5:3b", "dashboard-v3")
    response = app.test_client().post("/api/jobs/review/bulk", json={
        "job_ids": [first, second], "status": "acknowledged", "severity": "inherit",
        "tags": ["batch"], "note": "Reviewed together",
    })
    assert response.status_code == 201
    assert [event["job_id"] for event in response.json["events"]] == [first, second]
    assert store.get_job_detail(first)["review"]["status"] == "acknowledged"
    assert store.get_job_detail(second)["review"]["tags"] == ["batch"]


def test_maintenance_requires_confirmation_and_status_is_ui_compatible(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"].update(retention_days=1, retention_keep_latest=0)
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2020-01-01T00:00:00.000Z", "2020-01-01T01:00:00.000Z",
        "qwen2.5:7b", "dashboard-v4",
    )
    store.complete_job(job_id, "succeeded")
    with store.transaction() as connection:
        connection.execute("UPDATE jobs SET finished_at='2020-01-01T00:00:00.000Z' WHERE id=?", (job_id,))
    client = app.test_client()

    before = client.get("/api/maintenance")
    rejected = client.post("/api/maintenance/prune", json={"confirm": False})
    pruned = client.post("/api/maintenance/prune", json={"confirm": True})
    status = client.get("/api/status")

    assert before.status_code == 200
    assert before.json["retention_enabled"] is True
    assert before.json["policy"] == {"retention_days": 1, "retention_keep_latest": 0}
    assert rejected.status_code == 422
    assert pruned.json["result"]["deleted_jobs"] == 1
    assert store.get_job(job_id) is None
    assert isinstance(status.json["queue"], int)
    assert status.json["database"] == "ok"
    assert isinstance(status.json["review_events"], int)


def test_retention_preview_is_non_mutating_and_token_is_checked_when_enabled(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg["dashboard"].update(retention_days=1, retention_keep_latest=0, require_preview_token=True)
    app = dashboard.create_app(cfg=cfg, start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job("manual_window", "2020-01-01T00:00:00.000Z", "2020-01-01T01:00:00.000Z", "qwen2.5:7b", "dashboard-v4")
    store.complete_job(job_id, "succeeded")
    with store.transaction() as connection:
        connection.execute("UPDATE jobs SET finished_at='2020-01-01T00:00:00.000Z' WHERE id=?", (job_id,))
    client = app.test_client()
    preview = client.get("/api/maintenance/preview")
    assert preview.status_code == 200
    assert preview.json["candidate_count"] == 1
    assert preview.json["candidate_ids"] == [job_id]
    assert store.get_job(job_id) is not None
    stale = client.post("/api/maintenance/prune", json={"confirm": True, "confirmation_token": "retention-v1:stale"})
    assert stale.status_code == 422
    pruned = client.post("/api/maintenance/prune", json={"confirm": True, "confirmation_token": preview.json["confirmation_token"]})
    assert pruned.status_code == 200
    assert pruned.json["result"]["confirmed"] is True
    assert store.get_job(job_id) is None


def test_dependencies_probes_ollama_and_indexer_without_exposing_credentials(monkeypatch, tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)

    class Response:
        status_code = 200

        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            return None

        def json(self):
            return self.body

    def fake_get(url, **kwargs):
        if url.endswith("/api/tags"):
            return Response({"models": [{"name": "qwen2.5:3b"}]})
        assert url.endswith("/_cluster/health")
        assert kwargs["auth"] == ("reader", "secret")
        return Response({"status": "yellow", "number_of_nodes": 1, "secret": "do not return"})

    monkeypatch.setattr(dashboard.requests, "get", fake_get)
    response = app.test_client().get("/api/dependencies")

    assert response.status_code == 200
    assert response.json["ollama"]["details"] == {"model_count": 1}
    assert response.json["indexer"]["details"] == {"status": "yellow", "number_of_nodes": 1}
    assert "secret" not in response.get_data(as_text=True)


def test_export_scrubs_legacy_local_fallback_preview(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-08-04T02:00:00.000Z", "2026-08-04T03:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3", language="vi",
    )
    store.save_result(
        job_id, "window", "window",
        {
            "summary": "SECRET_RAW_LOG private chain of thought",
            "severity": "unknown", "key_findings": [], "mitre": [], "next_steps": [],
        },
        provenance={"output_origin": "local_fallback"},
    )

    for schema in ("v1", "v2"):
        response = app.test_client().get(f"/api/jobs/{job_id}/export?schema={schema}")
        assert response.status_code == 200
        assert "SECRET_RAW_LOG" not in response.get_data(as_text=True)
        assert "private chain of thought" not in response.get_data(as_text=True)


def test_export_redacts_credential_values_keeps_operational_ids_and_declares_scope(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    job_id = store.create_job(
        "manual_window", "2026-08-04T02:00:00.000Z", "2026-08-04T03:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3", language="vi",
    )
    store.replace_job_data(job_id, {
        "analysis_mode": "full",
        "alerts": [{"_index": "wazuh-alerts", "_id": "alert-5503",
                     "timestamp": "2026-08-04T02:30:00Z", "rule_id": "5503",
                     "rule_level": 5, "description": "token=do-not-leak; thất bại",
                     "agent": "agent-đỏ", "source_ip": "192.0.2.30", "group_key": "ssh"}],
        "groups": [{"group_key": "ssh", "rule_id": "5503", "count": 1,
                     "max_level": 5, "sample_log": "raw secret"}],
    })
    store.save_result(job_id, "window", "window", {
        "summary": "password=do-not-leak; Báo cáo tiếng Việt",
        "severity": "medium", "key_findings": ["rule 5503"],
        "mitre": ["T1110"], "next_steps": [],
        "chat_config": {"token": "do-not-leak"},
        "assessment_basis": {"observed_facts": ["rule 5503"], "inferences": [],
                              "uncertainties": [], "limitations": []},
    })
    store.complete_job(job_id, "succeeded", progress_current=1, progress_total=1)

    response = app.test_client().get(f"/api/jobs/{job_id}/export")
    payload = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.json["export_metadata"]["scope"] == "selected-job-window"
    assert response.json["export_metadata"]["page"] == "single-job"
    assert "do-not-leak" not in payload
    assert "raw secret" not in payload
    assert "5503" in payload
    assert "192.0.2.30" in payload
    assert "Báo cáo tiếng Việt" in payload
    assert "chat_config" not in payload


def test_active_ips_endpoint_aggregates_top_source_ips(tmp_path, monkeypatch):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    monkeypatch.setattr(
        dashboard,
        "fetch_active_source_ips",
        lambda *args, **kwargs: [{"ip": "192.168.100.30", "count": 15}, {"ip": "192.168.100.20", "count": 3}],
    )
    client = app.test_client()
    res = client.get("/api/active-ips?lookback_seconds=86400")
    assert res.status_code == 200
    data = res.get_json()
    assert data["lookback_seconds"] == 86400
    assert len(data["ips"]) == 2
    assert data["ips"][0]["ip"] == "192.168.100.30"


def test_ip_analysis_auto_mode_selects_top_active_ip(tmp_path, monkeypatch):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    monkeypatch.setattr(
        dashboard,
        "fetch_active_source_ips",
        lambda *args, **kwargs: [{"ip": "192.168.100.30", "count": 42}],
    )
    monkeypatch.setattr(
        dashboard,
        "fetch_alerts_window",
        lambda *args, **kwargs: {"analysis_mode": "full", "alerts": []},
    )
    client = app.test_client()
    res = client.post(
        "/api/ip-analysis",
        json={
            "auto": True,
            "lookback_seconds": 604800,
            "model": "qwen2.5:7b",
            "language": "vi",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["source_ip"] == "192.168.100.30"


def test_attack_chain_option_is_persisted_for_manual_jobs_and_schedule(tmp_path):
    app = dashboard.create_app(cfg=make_cfg(tmp_path), start_runtime=False)
    store = app.config["DASHBOARD_STORE"]
    client = app.test_client()

    rejected = client.post("/api/jobs", json={
        "preset_seconds": 300, "model": "qwen2.5:7b", "attack_chain": "yes",
    })
    assert rejected.status_code == 422

    bad_window = client.post("/api/jobs", json={
        "preset_seconds": 300, "model": "qwen2.5:7b",
        "attack_chain": True, "attack_chain_seconds": 77,
    })
    assert bad_window.status_code == 422

    created = client.post("/api/jobs", json={
        "preset_seconds": 300, "model": "qwen2.5:7b", "language": "vi",
        "attack_chain": True, "attack_chain_seconds": 86400,
    })
    assert created.status_code == 202
    job = store.get_job(created.get_json()["job_id"])
    assert job["attack_chain"] == 1
    assert job["attack_chain_seconds"] == 86400
    assert job["analysis_kind"] == "window"

    saved = client.put("/api/schedule", json={
        "enabled": True, "interval_seconds": 300, "model": "qwen2.5:7b",
        "language": "vi", "attack_chain": True, "attack_chain_seconds": 3600,
    })
    assert saved.status_code == 200
    assert saved.get_json()["attack_chain"] == 1
    assert saved.get_json()["attack_chain_seconds"] == 3600
