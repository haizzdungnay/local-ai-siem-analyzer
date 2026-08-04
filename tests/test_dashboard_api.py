from pathlib import Path

import dashboard


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
