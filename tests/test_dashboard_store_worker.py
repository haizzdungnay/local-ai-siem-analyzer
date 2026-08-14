import json
import sqlite3
from datetime import datetime, timezone

import dashboard_store
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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 8
        job_columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
        schedule_columns = {row[1] for row in connection.execute("PRAGMA table_info(schedule)")}
        result_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(analysis_results)")
        }
    assert {"language", "analysis_mode", "metrics_json", "timeline_json", "phase", "delivery_channel", "llm_params_json", "correlation_json"} <= job_columns
    assert {"language", "delivery_channel", "llm_params_json"} <= schedule_columns
    assert "provenance_json" in result_columns
    assert connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='job_review_events'"
    ).fetchone()


def test_llm_snapshot_is_private_in_public_job_and_schedule_payloads(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    parameters = {
        "temperature": 0.4, "top_p": 0.8, "max_tokens": 512,
        "system_prompt": "Focus on endpoint evidence.",
    }
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3", llm_parameters=parameters,
    )
    public = store.get_job_detail(job_id)
    assert public["llm_parameters"]["has_custom_system_prompt"] is True
    assert "Focus on endpoint evidence." not in json.dumps(public)
    claimed = store.claim_next_job()
    assert claimed["llm_parameters"] == parameters

    store.configure_schedule(
        enabled=True, interval_seconds=300, model="qwen2.5:7b",
        next_window_start="2026-07-30T11:00:00.000Z", llm_parameters=parameters,
    )
    assert "Focus on endpoint evidence." not in json.dumps(store.get_schedule())
    assert store.get_schedule(include_llm_parameters=True)["llm_parameters"] == parameters


def test_store_rejects_invalid_llm_snapshots_before_persistence(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")

    for callback in (
        lambda: store.create_job(
            "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
            "qwen2.5:7b", "dashboard-v3", llm_parameters={"max_tokens": 63},
        ),
        lambda: store.configure_schedule(
            enabled=True, interval_seconds=300, model="qwen2.5:7b",
            next_window_start="2026-07-30T11:00:00.000Z", llm_parameters={"top_p": 0},
        ),
    ):
        try:
            callback()
        except ValueError:
            pass
        else:
            raise AssertionError("invalid LLM parameters must not be persisted")

    assert store.active_job_count() == 0
    assert store.get_schedule(include_llm_parameters=True)["generation"] == 0


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


def test_maintenance_stats_tolerates_sqlite_sidecar_disappearing_during_size_check(tmp_path, monkeypatch):
    store = DashboardStore(tmp_path / "dashboard.db")
    wal = tmp_path / "dashboard.db-wal"
    wal.write_bytes(b"transient")
    original_stat = dashboard_store.Path.stat
    calls = {"wal": 0}

    def race_stat(path, *args, **kwargs):
        if str(path) == str(wal):
            calls["wal"] += 1
            if calls["wal"] == 1:
                raise FileNotFoundError("sidecar removed by SQLite")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(dashboard_store.Path, "stat", race_stat)

    stats = store.maintenance_stats()

    assert stats["database"]["bytes"] >= 0
    assert calls["wal"] == 1


def test_store_migrates_v3_to_v5_without_losing_jobs(tmp_path):
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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 8
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='job_review_events'"
        ).fetchone()
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_deliveries'"
        ).fetchone()


def test_store_migrates_v5_delivery_checks_to_gmail_without_losing_audit(tmp_path):
    path = tmp_path / "dashboard.db"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE jobs (
                id INTEGER PRIMARY KEY,
                job_type TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL DEFAULT 'queued',
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                model TEXT NOT NULL,
                analysis_version TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT 'vi',
                delivery_channel TEXT NOT NULL DEFAULT 'none' CHECK(delivery_channel IN ('none','telegram')),
                analysis_mode TEXT NOT NULL DEFAULT 'full',
                metrics_json TEXT NOT NULL DEFAULT '{}',
                timeline_json TEXT NOT NULL DEFAULT '[]',
                schedule_generation INTEGER,
                progress_current INTEGER NOT NULL DEFAULT 0,
                progress_total INTEGER NOT NULL DEFAULT 0,
                retry_count INTEGER NOT NULL DEFAULT 0,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT
            );
            CREATE TABLE schedule (
                singleton INTEGER PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                generation INTEGER NOT NULL DEFAULT 0,
                interval_seconds INTEGER NOT NULL DEFAULT 300,
                model TEXT NOT NULL DEFAULT '',
                language TEXT NOT NULL DEFAULT 'vi',
                delivery_channel TEXT NOT NULL DEFAULT 'none' CHECK(delivery_channel IN ('none','telegram')),
                next_window_start TEXT,
                ingest_delay_seconds INTEGER NOT NULL DEFAULT 120,
                max_catchup_windows INTEGER NOT NULL DEFAULT 24,
                state TEXT NOT NULL DEFAULT 'idle',
                error TEXT NOT NULL DEFAULT '',
                gap_windows INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE report_deliveries (
                id INTEGER PRIMARY KEY,
                job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                channel TEXT NOT NULL CHECK(channel IN ('telegram')),
                status TEXT NOT NULL DEFAULT 'pending',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                payload_sha256 TEXT NOT NULL DEFAULT '',
                provider_message_id TEXT NOT NULL DEFAULT '',
                error_code TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sent_at TEXT,
                UNIQUE(job_id, channel)
            );
            CREATE TABLE job_review_events (
                id INTEGER PRIMARY KEY,
                job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                tags_json TEXT NOT NULL DEFAULT '[]',
                note TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT 'local_analyst',
                created_at TEXT NOT NULL
            );
            INSERT INTO jobs(
                id,job_type,status,phase,window_start,window_end,model,analysis_version,
                language,delivery_channel,analysis_mode,created_at
            ) VALUES(
                7,'manual_window','succeeded','completed','2026-07-30T10:00:00.000Z',
                '2026-07-30T11:00:00.000Z','qwen2.5:7b','dashboard-v5','vi',
                'telegram','full','2026-07-30T11:01:00.000Z'
            );
            INSERT INTO schedule(singleton,updated_at) VALUES(1,'2026-07-30T11:01:00.000Z');
            INSERT INTO report_deliveries(
                id,job_id,channel,status,attempt_count,payload_sha256,provider_message_id,
                created_at,updated_at,sent_at
            ) VALUES(
                9,7,'telegram','sent',1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                '1001','2026-07-30T11:01:00.000Z','2026-07-30T11:01:00.000Z','2026-07-30T11:01:00.000Z'
            );
            INSERT INTO job_review_events(id,job_id,status,severity,created_at)
                VALUES(1,7,'acknowledged','inherit','2026-07-30T11:01:00.000Z');
            PRAGMA user_version=5;
        """)

    store = DashboardStore(path)

    assert store.get_delivery(9)["channel"] == "telegram"
    gmail_job = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v6", delivery_channel="gmail",
    )
    assert store.get_job(gmail_job)["delivery_channel"] == "gmail"
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 8
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert "'gmail'" in connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='report_deliveries'"
        ).fetchone()[0]


def test_store_migrates_v2_to_v5_without_losing_jobs(tmp_path):
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


def test_delivery_queue_is_idempotent_and_keeps_only_audit_metadata(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v5", delivery_channel="telegram",
    )
    store.complete_job(job_id, "succeeded")

    first = store.enqueue_delivery(job_id, "telegram")
    second = store.enqueue_delivery(job_id, "telegram")
    assert first["id"] == second["id"]
    assert first["status"] == "pending"

    claimed = store.claim_next_delivery()
    assert claimed["id"] == first["id"]
    assert claimed["attempt_count"] == 1
    store.mark_delivery_sent(
        claimed["id"], payload_sha256="a" * 64, provider_message_id="1001"
    )

    delivery = store.get_job_detail(job_id)["delivery"]
    assert delivery["status"] == "sent"
    assert delivery["payload_sha256"] == "a" * 64
    assert "token" not in str(delivery).lower()


def test_delivery_recovery_marks_inflight_as_uncertain_without_replaying(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v5", delivery_channel="telegram",
    )
    store.complete_job(job_id, "partial")
    delivery = store.enqueue_delivery(job_id, "telegram")
    assert store.claim_next_delivery()["id"] == delivery["id"]

    assert store.recover_sending_deliveries() == 1
    recovered = store.get_delivery(delivery["id"])
    assert recovered["status"] == "uncertain"
    assert recovered["error_code"] == "recovered_in_flight"
    assert store.claim_next_delivery() is None


def test_legacy_partial_telegram_pdf_failure_requires_explicit_retry(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v6", delivery_channel="telegram",
    )
    store.complete_job(job_id, "succeeded")
    delivery = store.enqueue_delivery(job_id, "telegram")
    store.claim_next_delivery()
    store.mark_delivery_problem(
        delivery["id"], status="uncertain", error_code="telegram_partial_timeout", stage="pdf",
    )
    recorded = store.get_delivery(delivery["id"])
    assert recorded["delivery_stage"] == "pdf"
    assert recorded["last_error_at"]
    assert "timeout" in recorded["error_code"]
    retry = store.retry_delivery(delivery["id"], allow_sent=True)
    assert retry["status"] == "pending"
    assert retry["attempt_count"] == 1


def test_delivery_worker_marks_single_document_network_failure_at_pdf_stage(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v7", delivery_channel="telegram",
    )
    store.save_result(job_id, "window", "window", {"summary": "Safe", "severity": "low"})
    store.complete_job(job_id, "succeeded")
    queued = store.enqueue_delivery(job_id, "telegram")
    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, object(),
    )
    delivery = store.claim_next_delivery()

    class Notifier:
        def send_report(self, _job):
            raise dashboard_worker.TelegramDeliveryError("telegram_network_error", uncertain=True)

    runtime.telegram_notifier = Notifier()
    runtime._run_delivery(delivery)

    recorded = store.get_delivery(queued["id"])
    assert recorded["status"] == "uncertain"
    assert recorded["error_code"] == "telegram_network_error"
    assert recorded["delivery_stage"] == "pdf"
    assert store.get_job(job_id)["status"] == "succeeded"
    assert store.claim_next_delivery() is None


def test_sent_delivery_can_be_explicitly_resent_within_attempt_limit(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v6", delivery_channel="gmail",
    )
    store.complete_job(job_id, "succeeded")
    delivery = store.enqueue_delivery(job_id, "gmail")
    claimed = store.claim_next_delivery()
    store.mark_delivery_sent(claimed["id"], payload_sha256="d" * 64, provider_message_id="mail-1")

    try:
        store.retry_delivery(delivery["id"])
    except ValueError as exc:
        assert "lỗi/chưa chắc chắn" in str(exc)
    else:
        raise AssertionError("A sent delivery needs explicit resend confirmation")

    resent = store.retry_delivery(delivery["id"], allow_sent=True)
    assert resent["status"] == "pending"
    assert resent["attempt_count"] == 1
    assert resent["sent_at"] is None


def test_delivery_worker_marks_sent_without_changing_analysis_status(tmp_path, monkeypatch):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v5", delivery_channel="telegram",
    )
    store.save_result(
        job_id, "window", "window",
        {"summary": "Safe summary", "severity": "medium", "next_steps": []},
    )
    store.complete_job(job_id, "succeeded")
    queued = store.enqueue_delivery(job_id, "telegram")

    class Service:
        pass

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service(),
    )
    delivery = store.claim_next_delivery()
    sent = {}

    class Notifier:
        def send_report(self, job):
            sent["job_id"] = job["id"]
            return {"payload_sha256": "b" * 64, "message_id": "321"}

    runtime.telegram_notifier = Notifier()
    runtime._run_delivery(delivery)

    result = store.get_delivery(queued["id"])
    assert sent == {"job_id": job_id}
    assert result["status"] == "sent"
    assert result["provider_message_id"] == "321"
    assert store.get_job(job_id)["status"] == "succeeded"


def test_delivery_worker_routes_gmail_without_changing_analysis_status(tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v6", delivery_channel="gmail",
    )
    store.save_result(
        job_id, "window", "window",
        {"summary": "Safe summary", "severity": "medium", "next_steps": []},
    )
    store.complete_job(job_id, "succeeded")
    queued = store.enqueue_delivery(job_id, "gmail")

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, object(),
    )
    delivery = store.claim_next_delivery()
    sent = {}

    class Notifier:
        def send_report(self, job):
            sent["job_id"] = job["id"]
            return {"payload_sha256": "c" * 64, "message_id": "mail-321"}

    runtime.gmail_notifier = Notifier()
    runtime._run_delivery(delivery)

    result = store.get_delivery(queued["id"])
    assert sent == {"job_id": job_id}
    assert result["status"] == "sent"
    assert result["provider_message_id"] == "mail-321"
    assert store.get_job(job_id)["status"] == "succeeded"


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


def test_worker_cancel_after_llm_does_not_save_success(monkeypatch, tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3",
    )
    monkeypatch.setattr(
        dashboard_worker, "fetch_alerts_range",
        lambda *args, **kwargs: {"total": 1, "alerts": [{
            "_index": "idx", "_id": "id", "_source": {
                "timestamp": "2026-07-30T11:30:00Z",
                "rule": {"id": "1", "level": 3, "description": "x"},
                "agent": {"name": "agent"},
            },
        }]},
    )

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi"):
            store.request_cancel(job_id)
            return {
                "analysis": {
                    "summary": "summary", "severity": "low", "key_findings": [],
                    "mitre": [], "next_steps": [],
                },
                "coverage": {"truncated": False}, "partial": False,
                "provenance": {"language_compliance": "full"},
            }

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service(),
    )
    runtime._run_job(store.claim_next_job())
    detail = store.get_job_detail(job_id)

    assert detail["status"] == "cancelled"
    assert detail["phase"] == "cancelled"
    assert detail["results"] == []


def test_worker_cancel_between_last_check_and_result_commit_discards_result(monkeypatch, tmp_path):
    """A cancellation racing with the persist phase must win without a result row."""
    store = DashboardStore(tmp_path / "dashboard.db")
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "dashboard-v3",
    )
    monkeypatch.setattr(
        dashboard_worker, "fetch_alerts_range",
        lambda *args, **kwargs: {"total": 1, "alerts": [{
            "_index": "idx", "_id": "id", "_source": {
                "timestamp": "2026-07-30T11:30:00Z",
                "rule": {"id": "1", "level": 3, "description": "x"},
                "agent": {"name": "agent"},
            },
        }]},
    )

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi"):
            return {
                "analysis": {
                    "summary": "summary", "severity": "low", "key_findings": [],
                    "mitre": [], "next_steps": ["verify"],
                },
                "coverage": {"truncated": False}, "partial": False,
                "provenance": {"language_compliance": "full"},
            }

    update_phase = store.update_phase

    def request_cancel_at_persist_phase(received_job_id, phase):
        update_phase(received_job_id, phase)
        if phase == "saving_result":
            store.request_cancel(job_id)

    monkeypatch.setattr(store, "update_phase", request_cancel_at_persist_phase)
    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service(),
    )
    runtime._run_job(store.claim_next_job())
    detail = store.get_job_detail(job_id)

    assert detail["status"] == "cancelled"
    assert detail["phase"] == "cancelled"
    assert detail["results"] == []


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


def test_security_job_passes_only_fixed_correlation_and_bounded_ai_policy(monkeypatch, tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    correlation = {
        "security_test_run_id": "a" * 32,
        "scenario_id": "file-inclusion",
        "source_ip": "192.168.100.30",
        "agent_ip": "192.168.100.20",
        "expected_rule_ids": ["31104"],
        "analysis_timeout_seconds": 45,
    }
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "security-test-v1", language="vi", delivery_channel="none",
        llm_parameters={"temperature": 0, "top_p": 1, "max_tokens": 512, "system_prompt": ""},
        correlation=correlation,
    )
    captured = {}

    def fetch(*args, **kwargs):
        captured["fetch"] = kwargs
        return {
            "analysis_mode": "full", "total": 1,
            "alerts": [{"_index": "wazuh-alerts", "_id": "one", "_source": {
                "timestamp": "2026-07-30T11:30:00Z",
                "rule": {"id": "31104", "level": 7, "description": "Traversal"},
                "agent": {"name": "victim"}, "data": {"srcip": "192.168.100.30"},
            }}],
            "timeline": [],
        }

    monkeypatch.setattr(dashboard_worker, "fetch_alerts_range", fetch)

    class Service:
        def analyze_aggregate(self, aggregate, model, language="vi", **kwargs):
            captured.update(aggregate=aggregate, model=model, language=language, analysis=kwargs)
            start = "2026-07-30T11:00:00.000Z"
            end = "2026-07-30T12:00:00.000Z"
            prefix = f"WAZUH_EVIDENCE total_alerts=1; rule_ids=31104; window_utc={start}..{end}."
            return {
                "analysis": {
                    "summary": prefix + " Một cảnh báo traversal Wazuh đã được ghi nhận.",
                    "severity": "medium",
                    "key_findings": [f"1 alert rule 31104 trong {start}..{end}."],
                    "mitre": [], "next_steps": [],
                    "assessment_basis": {
                        "observed_facts": [f"1 Wazuh alert matched rule 31104 in {start}..{end}."],
                        "inferences": ["Rule 31104 may be related to the bounded lab traffic."],
                        "uncertainties": ["Rule 31104 alone does not prove exploit success."],
                        "limitations": [f"Only window {start}..{end} was analyzed."],
                    },
                },
                "coverage": {"truncated": False}, "partial": False,
                "provenance": {"language_compliance": "full"},
            }

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service(),
    )
    runtime._run_job(store.claim_next_job())

    assert captured["fetch"]["source_ip"] == "192.168.100.30"
    assert captured["fetch"]["agent_ip"] == "192.168.100.20"
    assert captured["fetch"]["expected_rule_ids"] == ["31104"]
    assert captured["model"] == "qwen2.5:7b"
    assert captured["analysis"]["timeout_seconds"] == 45
    assert captured["analysis"]["llm_parameters"] == {
        "temperature": 0.0, "top_p": 1.0, "max_tokens": 512, "system_prompt": "",
    }
    assert store.get_job_detail(job_id)["status"] == "succeeded"

    store.complete_job(job_id, "failed", error="controlled")
    try:
        store.retry_job(job_id)
    except ValueError as exc:
        assert "cannot be retried" in str(exc)
    else:
        raise AssertionError("security-test AI job must never be retried")


def test_security_job_marks_generic_model_report_partial(monkeypatch, tmp_path):
    store = DashboardStore(tmp_path / "dashboard.db")
    correlation = {
        "security_test_run_id": "b" * 32,
        "scenario_id": "xss-reflected",
        "source_ip": "192.168.100.30",
        "agent_ip": "192.168.100.20",
        "expected_rule_ids": ["31105"],
        "analysis_timeout_seconds": 45,
    }
    job_id = store.create_job(
        "manual_window", "2026-07-30T11:00:00.000Z", "2026-07-30T12:00:00.000Z",
        "qwen2.5:7b", "security-test-v1", language="vi",
        llm_parameters={"temperature": 0, "top_p": 1, "max_tokens": 512, "system_prompt": ""},
        correlation=correlation,
    )
    monkeypatch.setattr(dashboard_worker, "fetch_alerts_range", lambda *args, **kwargs: {
        "analysis_mode": "full", "total": 2,
        "alerts": [{"_index": "wazuh-alerts", "_id": str(index), "_source": {
            "timestamp": "2026-07-30T11:30:00Z",
            "rule": {"id": "31105", "level": 6, "description": "XSS"},
            "agent": {"name": "victim"}, "data": {"srcip": "192.168.100.30"},
        }} for index in range(2)],
        "timeline": [],
    })

    class Service:
        def analyze_aggregate(self, *args, **kwargs):
            return {
                "analysis": {
                    "summary": "Tổng quan về các cảnh báo và nhóm cảnh báo",
                    "severity": "low", "key_findings": ["Cảnh báo web"],
                    "mitre": [], "next_steps": ["Kiểm tra lại"],
                    "assessment_basis": {
                        "observed_facts": ["Có cảnh báo được phát hiện"],
                        "inferences": [], "uncertainties": [], "limitations": [],
                    },
                },
                "coverage": {"truncated": False}, "partial": False,
                "provenance": {"language_compliance": "full"},
            }

    runtime = dashboard_worker.DashboardRuntime(
        store, {"dashboard": {}, "wazuh_indexer": {}, "ollama": {}}, Service(),
    )
    runtime._run_job(store.claim_next_job())

    detail = store.get_job_detail(job_id)
    assert detail["status"] == "partial"
    assert any("generic" in warning for warning in detail["results"][0]["warnings"])
    assert any("inferences" in warning for warning in detail["results"][0]["warnings"])
    assert any("limitations" in warning for warning in detail["results"][0]["warnings"])


def test_security_quality_gate_rejects_ungrounded_mitre_and_missing_window():
    aggregate = {
        "total_alerts": 1,
        "rule_counts": {"31104": 1},
        "groups": [{"mitre": []}],
        "security_test_correlation": {
            "window_start": "2026-07-30T11:00:00.000Z",
            "window_end": "2026-07-30T12:00:00.000Z",
        },
    }
    analysis = {
        "summary": "1 alert rule 31104",
        "key_findings": ["Rule 31104"],
        "mitre": ["T1190"],
        "assessment_basis": {
            "observed_facts": ["1 alert rule 31104"],
            "inferences": ["Có thể liên quan T1190."],
            "uncertainties": ["Không thể xác nhận exploit."],
            "limitations": ["Chỉ có aggregate."],
        },
    }

    failures = dashboard_worker._security_analysis_quality(aggregate, analysis)

    assert any("window UTC" in failure for failure in failures)
    assert any("MITRE" in failure for failure in failures)


def test_security_quality_gate_requires_exact_evidence_prefix_and_evidence_only_mitre():
    start = "2026-07-30T11:00:00.000Z"
    end = "2026-07-30T12:00:00.000Z"
    prefix = f"WAZUH_EVIDENCE total_alerts=2; rule_ids=31104,31105; window_utc={start}..{end}."
    aggregate = {
        "total_alerts": 2,
        "rule_counts": {"31104": 1, "31105": 1},
        "groups": [{"mitre": ["T1190"]}],
        "security_test_correlation": {"window_start": start, "window_end": end},
    }
    valid = {
        "summary": prefix + " Hai nhom Wazuh web da duoc ghi nhan.",
        "key_findings": [f"Rule 31104 va rule 31105 co tong cong 2 alert trong {start}..{end}."],
        "mitre": ["T1190"],
        "assessment_basis": {
            "observed_facts": [f"2 alert, rule 31104, rule 31105 trong cua so {start}..{end}."],
            "inferences": ["Rule 31104 va 31105 can duoc xem xet theo ngữ canh lab."],
            "uncertainties": ["Rule 31104 va 31105 khong xac nhan ket qua khai thac."],
            "limitations": [f"Chi cua so {start}..{end} duoc phan tich."],
        },
    }

    assert dashboard_worker._security_analysis_quality(aggregate, valid) == []

    missing_prefix = dict(valid, summary="2 alert rule 31104, 31105 trong " + start + " den " + end)
    assert any(
        "prefix" in failure.lower()
        for failure in dashboard_worker._security_analysis_quality(aggregate, missing_prefix)
    )

    ungrounded = dict(valid, mitre=["T1190", "T1059"])
    assert any(
        "MITRE" in failure
        for failure in dashboard_worker._security_analysis_quality(aggregate, ungrounded)
    )

    for summary in (prefix, prefix + " Overview of alerts and alert groups."):
        failures = dashboard_worker._security_analysis_quality(
            aggregate, dict(valid, summary=summary)
        )
        assert any("summary" in failure.lower() for failure in failures)


def test_security_quality_gate_marks_placeholder_basis_partial():
    start = "2026-07-30T11:00:00.000Z"
    end = "2026-07-30T12:00:00.000Z"
    prefix = f"WAZUH_EVIDENCE total_alerts=1; rule_ids=31104; window_utc={start}..{end}."
    aggregate = {
        "total_alerts": 1,
        "rule_counts": {"31104": 1}, "groups": [{"mitre": []}],
        "security_test_correlation": {"window_start": start, "window_end": end},
    }
    analysis = {
        "summary": prefix + " Mot alert traversal da duoc ghi nhan.",
        "key_findings": ["Rule 31104 co 1 alert."], "mitre": [],
        "assessment_basis": {
            "observed_facts": [f"1 alert rule 31104 trong {start}..{end}."],
            "inferences": ["No structured inference is available."],
            "uncertainties": ["No uncertainty was recorded."],
            "limitations": ["No limitation was recorded."],
        },
    }

    failures = dashboard_worker._security_analysis_quality(aggregate, analysis)

    assert any("inferences" in failure for failure in failures)
    assert any("uncertainties" in failure for failure in failures)
    assert any("limitations" in failure for failure in failures)
