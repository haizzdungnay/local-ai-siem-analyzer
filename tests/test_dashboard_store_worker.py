import json
import sqlite3
from datetime import datetime, timezone

import dashboard_worker
from dashboard_store import DashboardStore


def test_store_migrates_v1_jobs_and_schedule_columns(tmp_path):
    path = tmp_path / "dashboard.db"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE jobs (id INTEGER PRIMARY KEY);
            CREATE TABLE schedule (singleton INTEGER PRIMARY KEY);
            CREATE TABLE analysis_results (id INTEGER PRIMARY KEY);
            PRAGMA user_version=1;
        """)

    DashboardStore(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        job_columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
        schedule_columns = {row[1] for row in connection.execute("PRAGMA table_info(schedule)")}
        result_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(analysis_results)")
        }
    assert {"language", "analysis_mode", "metrics_json", "timeline_json", "phase"} <= job_columns
    assert "language" in schedule_columns
    assert "provenance_json" in result_columns
    assert connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='job_review_events'"
    ).fetchone()


def test_store_read_connections_release_windows_file_handles(tmp_path):
    path = tmp_path / "dashboard.db"
    store = DashboardStore(path)
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v4",
    )
    store.get_job(job_id)
    store.list_jobs()
    store.get_job_detail(job_id)
    store.get_schedule()
    store.maintenance_stats()

    # SQLite connections must close explicitly on Windows before cleanup/retention.
    path.unlink()


def test_store_migrates_v3_to_v4_without_losing_jobs(tmp_path):
    path = tmp_path / "dashboard.db"
    store = DashboardStore(path)
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3",
    )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER job_review_events_no_update")
        connection.execute("DROP TABLE job_review_events")
        connection.execute("PRAGMA user_version=3")

    migrated = DashboardStore(path)

    assert migrated.get_job(job_id)["id"] == job_id
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='job_review_events'"
        ).fetchone()


def test_store_migrates_v2_to_v4_without_losing_jobs(tmp_path):
    path = tmp_path / "dashboard.db"
    store = DashboardStore(path)
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v2",
    )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER job_review_events_no_update")
        connection.execute("DROP TABLE job_review_events")
        connection.execute("PRAGMA user_version=2")

    migrated = DashboardStore(path)

    assert migrated.get_job(job_id)["analysis_version"] == "dashboard-v2"
    assert migrated.get_job_detail(job_id)["review_history"] == []


def test_review_history_is_append_only_and_visible_in_list_and_detail(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v4",
    )
    first = store.add_review_event(
        job_id, status="acknowledged", tags=["ssh", "priority"], note="Initial review",
    )
    latest = store.add_review_event(
        job_id, status="investigating", severity="high", tags=["ssh"], note="Collect evidence",
    )

    detail = store.get_job_detail(job_id)
    listed = store.list_jobs()[0]

    assert detail["review"] == latest
    assert detail["review_history"] == [first, latest]
    assert listed["review"] == latest
    with sqlite3.connect(tmp_path / "dashboard.db") as connection:
        try:
            connection.execute("UPDATE job_review_events SET note='changed' WHERE id=?", (first["id"],))
        except sqlite3.DatabaseError as exc:
            assert "immutable" in str(exc)
        else:
            raise AssertionError("review events must not be updateable")


def test_store_recovers_jobs_and_never_persists_raw_source(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v1",
    )
    assert store.claim_next_job()["status"] == "running"
    assert store.recover_running_jobs() == 1
    assert store.get_job(job_id)["status"] == "pending"

    aggregate = {
        "alerts": [{
            "_index": "wazuh-alerts-4.x-2026.07.30", "_id": "abc",
            "timestamp": "2026-07-30T11:30:00Z", "rule_id": "5503",
            "rule_level": 5, "description": "PAM failed", "agent": "victim",
            "source_ip": "192.0.2.30", "group_key": "group",
            "_source": {"full_log": "RAW_SOURCE_SENTINEL"},
        }],
        "groups": [{"group_key": "group", "count": 1, "sample_log": "RAW_GROUP_SENTINEL"}],
    }
    store.replace_job_data(job_id, aggregate)
    payload = (tmp_path / "dashboard.db").read_bytes()
    assert b"RAW_SOURCE_SENTINEL" not in payload
    assert b"RAW_GROUP_SENTINEL" not in payload
    detail = store.get_job_detail(job_id)
    assert detail["groups"][0].get("sample_log") is None
    assert detail["metrics"]["search_terms"] == ["192.0.2.30", "5503", "victim"]


def test_manual_prune_removes_only_old_terminal_jobs_and_keeps_latest(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    old_job = store.create_job(
        "manual_window", "2026-01-01T00:00:00.000Z", "2026-01-01T01:00:00.000Z",
        "qwen2.5:7b", "dashboard-v4",
    )
    latest_job = store.create_job(
        "manual_window", "2026-07-30T10:00:00.000Z", "2026-07-30T11:00:00.000Z",
        "qwen2.5:7b", "dashboard-v4",
    )
    pending_job = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v4",
    )
    store.complete_job(old_job, "succeeded")
    store.complete_job(latest_job, "failed", error="controlled")
    with store.transaction() as connection:
        connection.execute("UPDATE jobs SET finished_at=? WHERE id=?", ("2020-01-01T00:00:00.000Z", old_job))

    disabled = store.prune_terminal_jobs(retention_days=0, keep_latest=0)
    pruned = store.prune_terminal_jobs(retention_days=1, keep_latest=1)

    assert disabled == {"deleted_jobs": 0, "enabled": False}
    assert pruned["deleted_jobs"] == 1
    assert store.get_job(old_job) is None
    assert store.get_job(latest_job) is not None
    assert store.get_job(pending_job)["status"] == "pending"


def test_store_deduplicates_scheduled_window(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    values = (
        "scheduled_window", "2026-07-30T11:00:00.000Z", "2026-07-30T11:05:00.000Z",
        "qwen2.5:7b", "dashboard-v1",
    )
    store.create_job(*values, schedule_generation=1)
    try:
        store.create_job(*values, schedule_generation=1)
    except Exception as exc:
        assert "UNIQUE" in str(exc)
    else:
        raise AssertionError("Scheduled window trùng phải bị từ chối")


def test_store_retry_is_bounded(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v1",
    )
    for retry in range(3):
        store.claim_next_job()
        store.complete_job(job_id, "failed", error="transient")
        store.retry_job(job_id)
        assert store.get_job(job_id)["retry_count"] == retry + 1
    store.claim_next_job()
    store.complete_job(job_id, "failed", error="transient")
    try:
        store.retry_job(job_id)
    except ValueError as exc:
        assert "tối đa 3" in str(exc)
    else:
        raise AssertionError("Retry thứ tư phải bị từ chối")


def test_due_windows_applies_delay_and_keeps_newest_bounded_catchup():
    schedule = {
        "enabled": 1,
        "state": "active",
        "next_window_start": "2026-07-30T10:00:00.000Z",
        "interval_seconds": 300,
        "ingest_delay_seconds": 120,
        "max_catchup_windows": 2,
    }
    windows, overflow = dashboard_worker.due_windows(
        schedule, datetime(2026, 7, 30, 10, 22, tzinfo=timezone.utc)
    )

    assert overflow == 2
    assert windows == [
        ("2026-07-30T10:10:00.000Z", "2026-07-30T10:15:00.000Z"),
        ("2026-07-30T10:15:00.000Z", "2026-07-30T10:20:00.000Z"),
    ]


def test_worker_empty_window_skips_llm(monkeypatch, tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v1",
    )
    monkeypatch.setattr(
        dashboard_worker, "fetch_alerts_range",
        lambda *args, **kwargs: {"total": 0, "alerts": []},
    )

    class Service:
        def analyze_aggregate(self, *args, **kwargs):
            raise AssertionError("Empty window không được gọi LLM")

    runtime = dashboard_worker.DashboardRuntime(
        store,
        {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}},
        Service(),
    )
    job = store.claim_next_job()
    runtime._run_job(job)

    assert store.get_job(job_id)["status"] == "succeeded"
    assert store.get_job_detail(job_id)["results"] == []


def test_worker_persists_window_result_and_partial_status(monkeypatch, tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v1",
    )
    hit = {
        "_index": "wazuh-alerts-4.x-2026.07.30", "_id": "abc",
        "_source": {
            "timestamp": "2026-07-30T11:30:00Z",
            "rule": {"id": "5503", "level": 5, "description": "PAM failed"},
            "agent": {"id": "001", "name": "victim"},
            "full_log": "Failed password",
        },
    }
    monkeypatch.setattr(
        dashboard_worker, "fetch_alerts_range",
        lambda *args, **kwargs: {"total": 1, "alerts": [hit]},
    )

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi"):
            assert store.get_job(job_id)["phase"] == "calling_ollama"
            return {
                "analysis": {
                    "summary": "summary", "severity": "medium", "key_findings": ["x"],
                    "mitre": [], "next_steps": ["verify"],
                },
                "coverage": {
                    "included_groups": 1, "total_groups": 1,
                    "represented_alerts": 1, "total_alerts": 1, "truncated": False,
                },
                "partial": False,
                "provenance": {
                    "provider": "ollama", "requested_model": model,
                    "response_model": model, "output_origin": "ollama_model",
                    "language_compliance": "pass", "effective_language": language,
                    "prompt_version": "soc-prompt-v1", "system_prompt_sha256": "a" * 64,
                    "ollama_options": {"temperature": 0, "seed": 42},
                },
            }

    runtime = dashboard_worker.DashboardRuntime(
        store,
        {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}},
        Service(),
    )
    job = store.claim_next_job()
    runtime._run_job(job)
    detail = store.get_job_detail(job_id)

    assert detail["status"] == "succeeded", detail["error"]
    assert detail["phase"] == "completed"
    assert detail["progress_current"] == 1
    assert detail["results"][0]["result"]["severity"] == "medium"
    assert detail["results"][0]["provenance"]["provider"] == "ollama"
    assert detail["results"][0]["provenance"]["language_compliance"] == "full"
    assert detail["results"][0]["provenance"]["options"] == {"temperature": 0, "seed": 42}
    assert detail["results"][0]["provenance"]["prompt_version"] == "soc-prompt-v1"
    assert len(detail["alerts"]) == 1
    assert len(detail["groups"]) == 1


def test_store_exposes_aggregate_metrics_timeline_and_language(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v2", language="en",
    )
    aggregate = {
        "analysis_mode": "aggregate",
        "total_alerts": 5737,
        "total_groups": 1,
        "unique_rules": 1,
        "unique_agents": 1,
        "unique_source_ips": 0,
        "alerts": [],
        "groups": [{
            "group_key": "rule-31101", "rule_id": "31101", "count": 5737,
            "max_level": 5,
        }],
        "timeline": [{
            "start": "2026-07-30T11:55:00.000Z",
            "end": "2026-07-30T11:56:00.000Z",
            "count": 5737,
        }],
    }

    store.replace_job_data(job_id, aggregate)
    listed = store.list_jobs()[0]
    detail = store.get_job_detail(job_id)

    assert listed["alert_count"] == 5737
    assert listed["analysis_mode"] == "aggregate"
    assert listed["language"] == "en"
    assert detail["metrics"]["total_alerts"] == 5737
    assert detail["timeline"][0]["count"] == 5737
    assert detail["alerts"] == []


def test_worker_analyzes_over_cap_window_from_rule_buckets(monkeypatch, tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v2", language="en",
    )
    fetched = {
        "analysis_mode": "aggregate",
        "total": 5737,
        "alerts": [],
        "rule_buckets": [{
            "rule_id": "31101", "count": 5737, "max_level": 5,
            "first_seen": "2026-07-30T11:55:00.000Z",
            "last_seen": "2026-07-30T11:55:59.000Z",
            "sample": {"rule": {"description": "Web error"}},
        }],
        "timeline": [{
            "start": "2026-07-30T11:55:00.000Z",
            "end": "2026-07-30T11:56:00.000Z",
            "count": 5737,
        }],
        "rules_truncated": False,
        "unique_rules": 1,
        "unique_agents": 1,
        "unique_source_ips": 0,
    }
    monkeypatch.setattr(dashboard_worker, "fetch_alerts_range", lambda *args, **kwargs: fetched)
    captured = {}

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi"):
            captured.update(aggregate=aggregate, model=model, language=language)
            return {
                "analysis": {
                    "summary": "Web alert burst", "severity": "high",
                    "key_findings": ["5737 alerts"], "mitre": [],
                    "next_steps": ["Review source"],
                },
                "coverage": {
                    "included_groups": 1, "total_groups": 1,
                    "represented_alerts": 5737, "total_alerts": 5737,
                    "truncated": False,
                },
                "partial": False,
                "provenance": {"language_compliance": "full"},
            }

    runtime = dashboard_worker.DashboardRuntime(
        store,
        {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}},
        Service(),
    )
    job = store.claim_next_job()
    runtime._run_job(job)
    detail = store.get_job_detail(job_id)

    assert detail["status"] == "succeeded"
    assert detail["analysis_mode"] == "aggregate"
    assert detail["progress_total"] == 5737
    assert detail["alerts"] == []
    assert captured["language"] == "en"
    assert "Aggregate-only" in detail["results"][0]["warnings"][0]


def test_worker_marks_language_noncompliance_partial(monkeypatch, tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3", language="vi",
    )
    monkeypatch.setattr(
        dashboard_worker, "fetch_alerts_range",
        lambda *args, **kwargs: {"total": 1, "alerts": [{
            "_index": "idx", "_id": "id", "_source": {
                "timestamp": "2026-07-30T11:30:00Z",
                "rule": {"id": "1", "level": 2, "description": "x"},
                "agent": {"name": "a"},
            },
        }]},
    )

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi"):
            return {
                "analysis": {
                    "summary": "mixed", "severity": "low", "key_findings": [],
                    "mitre": [], "next_steps": [], "response_language": "en",
                },
                "coverage": {"truncated": False}, "partial": False,
                "provenance": {
                    "requested_language": language, "effective_language": "en",
                    "language_compliance": "partial",
                },
            }

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service(),
    )
    runtime._run_job(store.claim_next_job())
    detail = store.get_job_detail(job_id)

    assert detail["status"] == "partial"
    result = detail["results"][0]
    assert result["provenance"]["language_compliance"] == "partial"
    assert any("Language compliance" in warning for warning in result["warnings"])
