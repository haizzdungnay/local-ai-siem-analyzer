"""SQLite persistence for local dashboard jobs and one fixed-window schedule."""
import hashlib
import json
import os
import re
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard_time import format_utc, parse_utc, utc_now
from llm import normalize_llm_parameters


SCHEMA_VERSION = 8
JOB_PHASES = {
    "queued", "fetching_alerts", "preparing_analysis", "calling_ollama",
    "saving_result", "completed", "failed", "cancelled",
}
REVIEW_STATUSES = {"new", "acknowledged", "investigating", "resolved", "false_positive"}
REVIEW_SEVERITIES = {"inherit", "low", "medium", "high", "critical"}
DELIVERY_CHANNELS = {"none", "telegram", "gmail"}
DELIVERY_STATUSES = {"pending", "sending", "sent", "failed", "uncertain"}


def _review_schema(connection):
    """Create the append-only local analyst review ledger."""
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS job_review_events (
            id INTEGER PRIMARY KEY,
            job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK(status IN (
                'new','acknowledged','investigating','resolved','false_positive'
            )),
            severity TEXT NOT NULL CHECK(severity IN (
                'inherit','low','medium','high','critical'
            )),
            tags_json TEXT NOT NULL DEFAULT '[]',
            note TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT 'local_analyst' CHECK(actor='local_analyst'),
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_job_review_events_job_id_id
            ON job_review_events(job_id, id);
        CREATE TRIGGER IF NOT EXISTS job_review_events_no_update
            BEFORE UPDATE ON job_review_events
            BEGIN SELECT RAISE(ABORT, 'job review events are immutable'); END;
    """)


def _delivery_schema(connection):
    """Create the delivery audit queue without persisting report content or secrets."""
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS report_deliveries (
            id INTEGER PRIMARY KEY,
            job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            channel TEXT NOT NULL CHECK(channel IN ('telegram','gmail')),
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN (
                'pending','sending','sent','failed','uncertain'
            )),
            attempt_count INTEGER NOT NULL DEFAULT 0,
            payload_sha256 TEXT NOT NULL DEFAULT '',
            provider_message_id TEXT NOT NULL DEFAULT '',
            error_code TEXT NOT NULL DEFAULT '',
            delivery_stage TEXT NOT NULL DEFAULT 'none',
            last_error_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            sent_at TEXT,
            UNIQUE(job_id, channel)
        );
        CREATE INDEX IF NOT EXISTS idx_report_deliveries_status_id
            ON report_deliveries(status, id);
    """)


def _validate_delivery_channel(channel):
    if channel not in DELIVERY_CHANNELS:
        raise ValueError("delivery_channel không hợp lệ")
    return channel


def _llm_parameters_payload(raw, *, include_system_prompt=False):
    """Decode a stored snapshot; browser-facing payloads never include prompt text."""
    try:
        parameters = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        parameters = {}
    if not isinstance(parameters, dict):
        parameters = {}
    if include_system_prompt:
        return parameters
    system_prompt = parameters.pop("system_prompt", "")
    parameters["has_custom_system_prompt"] = bool(system_prompt)
    return parameters


def _validated_llm_parameters(parameters):
    """Reject malformed snapshots before they reach durable job or schedule state."""
    return {} if parameters is None else normalize_llm_parameters(parameters)


_SECURITY_CORRELATION_KEYS = {
    "security_test_run_id", "scenario_id", "source_ip", "agent_ip",
    "expected_rule_ids", "analysis_timeout_seconds",
}


def _validated_correlation(value):
    """Persist only coordinator-owned, non-sensitive security-test metadata."""
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - _SECURITY_CORRELATION_KEYS:
        raise ValueError("correlation metadata is invalid")
    expected = {
        "security_test_run_id": r"[0-9a-f]{32}",
        "scenario_id": r"[a-z0-9-]{1,64}",
        "source_ip": r"\d{1,3}(?:\.\d{1,3}){3}",
        "agent_ip": r"\d{1,3}(?:\.\d{1,3}){3}",
    }
    cleaned = {}
    for key, pattern in expected.items():
        item = value.get(key)
        if item is None:
            continue
        if not isinstance(item, str) or not re.fullmatch(pattern, item):
            raise ValueError("correlation metadata is invalid")
        cleaned[key] = item
    timeout = value.get("analysis_timeout_seconds")
    if timeout is not None:
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 45:
            raise ValueError("correlation metadata is invalid")
        cleaned["analysis_timeout_seconds"] = timeout
    rule_ids = value.get("expected_rule_ids")
    if rule_ids is not None:
        if not isinstance(rule_ids, (list, tuple)) or not 1 <= len(rule_ids) <= 16:
            raise ValueError("correlation metadata is invalid")
        normalized_rules = []
        for rule_id in rule_ids:
            if not isinstance(rule_id, str) or not re.fullmatch(r"\d{1,12}", rule_id):
                raise ValueError("correlation metadata is invalid")
            if rule_id not in normalized_rules:
                normalized_rules.append(rule_id)
        cleaned["expected_rule_ids"] = normalized_rules
    if cleaned and set(cleaned) != _SECURITY_CORRELATION_KEYS:
        raise ValueError("correlation metadata is incomplete")
    return cleaned


def _correlation_payload(raw, *, internal=False):
    try:
        value = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        value = {}
    try:
        correlation = _validated_correlation(value)
    except ValueError:
        correlation = {}
    if internal or not correlation:
        return correlation
    # Browser-visible data is safe but deliberately omits internal timeout policy.
    return {key: value for key, value in correlation.items() if key != "analysis_timeout_seconds"}


def _review_payload(row):
    if row is None:
        return None
    event = dict(row)
    event["tags"] = json.loads(event.pop("tags_json"))
    return event


def _validate_review(status, severity, tags, note):
    if status not in REVIEW_STATUSES:
        raise ValueError("review.status khong hop le")
    if severity not in REVIEW_SEVERITIES:
        raise ValueError("review.severity khong hop le")
    if not isinstance(tags, list) or len(tags) > 20:
        raise ValueError("review.tags phai la list toi da 20 muc")
    cleaned_tags = []
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip() or len(tag.strip()) > 64:
            raise ValueError("review.tags chi nhan text 1..64 ky tu")
        cleaned_tags.append(tag.strip())
    if not isinstance(note, str) or len(note) > 4000:
        raise ValueError("review.note chi nhan text toi da 4000 ky tu")
    return cleaned_tags, note.strip()


def _search_terms(aggregate):
    """Persist bounded pivot values only; never raw sample log text."""
    terms = set()
    for group in aggregate.get("groups", []):
        for field in ("rule_id", "agent", "source_ip"):
            value = group.get(field, "")
            if isinstance(value, str) and value.strip():
                terms.add(value.strip()[:256])
    for alert in aggregate.get("alerts", []):
        for field in ("rule_id", "agent", "source_ip"):
            value = alert.get(field, "")
            if isinstance(value, str) and value.strip():
                terms.add(value.strip()[:256])
    return sorted(terms)[:60]


class DashboardStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _migrate(self):
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(f"Dashboard DB schema {version} mới hơn app {SCHEMA_VERSION}")
            if version == 0:
                connection.executescript("""
                    CREATE TABLE jobs (
                        id INTEGER PRIMARY KEY,
                        job_type TEXT NOT NULL CHECK(job_type IN ('manual_window','scheduled_window','group','alert')),
                        status TEXT NOT NULL CHECK(status IN ('pending','running','succeeded','partial','failed','cancelled')),
                        phase TEXT NOT NULL DEFAULT 'queued',
                        window_start TEXT NOT NULL,
                        window_end TEXT NOT NULL,
                        model TEXT NOT NULL,
                        analysis_version TEXT NOT NULL,
                        language TEXT NOT NULL DEFAULT 'vi' CHECK(language IN ('vi','en')),
                        delivery_channel TEXT NOT NULL DEFAULT 'none'
                            CHECK(delivery_channel IN ('none','telegram','gmail')),
                        llm_params_json TEXT NOT NULL DEFAULT '{}',
                        correlation_json TEXT NOT NULL DEFAULT '{}',
                        analysis_mode TEXT NOT NULL DEFAULT 'full' CHECK(analysis_mode IN ('full','aggregate')),
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
                        finished_at TEXT,
                        UNIQUE(schedule_generation, window_start, window_end, model, analysis_version)
                    );
                    CREATE TABLE job_alerts (
                        id INTEGER PRIMARY KEY,
                        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        index_name TEXT NOT NULL,
                        document_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        rule_level REAL NOT NULL,
                        description TEXT NOT NULL,
                        agent TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        group_key TEXT NOT NULL,
                        UNIQUE(job_id, index_name, document_id)
                    );
                    CREATE TABLE job_groups (
                        id INTEGER PRIMARY KEY,
                        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        group_key TEXT NOT NULL,
                        group_json TEXT NOT NULL,
                        UNIQUE(job_id, group_key)
                    );
                    CREATE TABLE analysis_results (
                        id INTEGER PRIMARY KEY,
                        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        scope TEXT NOT NULL CHECK(scope IN ('window','group','alert')),
                        scope_key TEXT NOT NULL,
                        result_json TEXT NOT NULL,
                        coverage_json TEXT NOT NULL DEFAULT '{}',
                        warnings_json TEXT NOT NULL DEFAULT '[]',
                        provenance_json TEXT NOT NULL DEFAULT '{}',
                        latency_s REAL NOT NULL DEFAULT 0,
                        revision INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        UNIQUE(job_id, scope, scope_key, revision)
                    );
                    CREATE TABLE schedule (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        enabled INTEGER NOT NULL DEFAULT 0,
                        generation INTEGER NOT NULL DEFAULT 0,
                        interval_seconds INTEGER NOT NULL DEFAULT 300,
                        model TEXT NOT NULL DEFAULT '',
                        language TEXT NOT NULL DEFAULT 'vi' CHECK(language IN ('vi','en')),
                        delivery_channel TEXT NOT NULL DEFAULT 'none'
                            CHECK(delivery_channel IN ('none','telegram','gmail')),
                        llm_params_json TEXT NOT NULL DEFAULT '{}',
                        next_window_start TEXT,
                        ingest_delay_seconds INTEGER NOT NULL DEFAULT 120,
                        max_catchup_windows INTEGER NOT NULL DEFAULT 24,
                        state TEXT NOT NULL DEFAULT 'idle',
                        error TEXT NOT NULL DEFAULT '',
                        gap_windows INTEGER NOT NULL DEFAULT 0,
                        updated_at TEXT NOT NULL
                    );
                    INSERT INTO schedule(singleton, updated_at) VALUES(1, '');
                """)
                _review_schema(connection)
                _delivery_schema(connection)
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            elif version in {1, 2}:
                if version == 1:
                    connection.executescript("""
                        ALTER TABLE jobs ADD COLUMN language TEXT NOT NULL DEFAULT 'en'
                            CHECK(language IN ('vi','en'));
                        ALTER TABLE jobs ADD COLUMN analysis_mode TEXT NOT NULL DEFAULT 'full'
                            CHECK(analysis_mode IN ('full','aggregate'));
                        ALTER TABLE jobs ADD COLUMN metrics_json TEXT NOT NULL DEFAULT '{}';
                        ALTER TABLE jobs ADD COLUMN timeline_json TEXT NOT NULL DEFAULT '[]';
                        ALTER TABLE schedule ADD COLUMN language TEXT NOT NULL DEFAULT 'vi'
                            CHECK(language IN ('vi','en'));
                    """)
                job_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(jobs)")
                }
                if "phase" not in job_columns:
                    connection.execute(
                        "ALTER TABLE jobs ADD COLUMN phase TEXT NOT NULL DEFAULT 'queued'"
                    )
                    if "status" in job_columns:
                        connection.execute(
                            """UPDATE jobs SET phase=CASE
                               WHEN status IN ('succeeded','partial') THEN 'completed'
                               WHEN status='failed' THEN 'failed'
                               WHEN status='cancelled' THEN 'cancelled'
                               ELSE 'queued' END"""
                        )
                result_tables = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='analysis_results'"
                ).fetchone()
                if result_tables:
                    result_columns = {
                        row[1] for row in connection.execute(
                            "PRAGMA table_info(analysis_results)"
                        )
                    }
                    if "provenance_json" not in result_columns:
                        connection.execute(
                            """ALTER TABLE analysis_results ADD COLUMN provenance_json
                               TEXT NOT NULL DEFAULT '{}'"""
                        )
                version = 3
            if version == 3:
                _review_schema(connection)
                version = 4
                connection.execute("PRAGMA user_version=4")
            if version == 4:
                job_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(jobs)")
                }
                if "delivery_channel" not in job_columns:
                    connection.execute(
                        """ALTER TABLE jobs ADD COLUMN delivery_channel TEXT NOT NULL DEFAULT 'none'
                           CHECK(delivery_channel IN ('none','telegram'))"""
                    )
                schedule_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(schedule)")
                }
                if "delivery_channel" not in schedule_columns:
                    connection.execute(
                        """ALTER TABLE schedule ADD COLUMN delivery_channel TEXT NOT NULL DEFAULT 'none'
                           CHECK(delivery_channel IN ('none','telegram'))"""
                    )
                _delivery_schema(connection)
                # Version 5 added Telegram delivery.  The next migration rebuilds
                # these CHECK constraints to admit Gmail without weakening them.
                connection.execute("PRAGMA user_version=5")

        with closing(self._connect()) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 5:
            self._migrate_v5_to_v6()
        with closing(self._connect()) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 6:
            self._ensure_v6_llm_parameter_columns()
            self._ensure_v7_delivery_observability()
        with closing(self._connect()) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 7:
            self._ensure_v8_security_correlation()
        self._ensure_history_indexes()

    def _ensure_history_indexes(self):
        """Indexes used by bounded history pages; safe for every existing schema."""
        with self.transaction() as connection:
            connection.executescript("""
                CREATE INDEX IF NOT EXISTS idx_jobs_history_status_id ON jobs(status, id DESC);
                CREATE INDEX IF NOT EXISTS idx_jobs_history_language_id ON jobs(language, id DESC);
                CREATE INDEX IF NOT EXISTS idx_jobs_history_mode_id ON jobs(analysis_mode, id DESC);
                CREATE INDEX IF NOT EXISTS idx_report_deliveries_job_id_id
                    ON report_deliveries(job_id, id);
            """)

    def _ensure_v6_llm_parameter_columns(self):
        """Add private, per-job LLM snapshots without rewriting existing history."""
        with self.transaction() as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 6:
                return
            job_columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
            schedule_columns = {row[1] for row in connection.execute("PRAGMA table_info(schedule)")}
            if "llm_params_json" not in job_columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN llm_params_json TEXT NOT NULL DEFAULT '{}'")
            if "llm_params_json" not in schedule_columns:
                connection.execute("ALTER TABLE schedule ADD COLUMN llm_params_json TEXT NOT NULL DEFAULT '{}'")

    def _ensure_v7_delivery_observability(self):
        """Keep only safe, stage-aware delivery audit data for operator recovery."""
        with self.transaction() as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 6:
                return
            columns = {row[1] for row in connection.execute("PRAGMA table_info(report_deliveries)")}
            if "delivery_stage" not in columns:
                connection.execute(
                    "ALTER TABLE report_deliveries ADD COLUMN delivery_stage TEXT NOT NULL DEFAULT 'none'"
                )
            if "last_error_at" not in columns:
                connection.execute("ALTER TABLE report_deliveries ADD COLUMN last_error_at TEXT")
            connection.execute("PRAGMA user_version=7")

    def _ensure_v8_security_correlation(self):
        """Store bounded internal correlation metadata without changing old jobs."""
        with self.transaction() as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 7:
                return
            columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
            if "correlation_json" not in columns:
                connection.execute(
                    "ALTER TABLE jobs ADD COLUMN correlation_json TEXT NOT NULL DEFAULT '{}'"
                )
            connection.execute("PRAGMA user_version=8")

    def _migrate_v5_to_v6(self):
        """Rebuild channel-constrained tables because SQLite cannot alter CHECKs."""

        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=OFF")
        try:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 5:
                return
            connection.execute("BEGIN IMMEDIATE")
            connection.executescript("""
                CREATE TABLE jobs_v6 (
                    id INTEGER PRIMARY KEY,
                    job_type TEXT NOT NULL CHECK(job_type IN ('manual_window','scheduled_window','group','alert')),
                    status TEXT NOT NULL CHECK(status IN ('pending','running','succeeded','partial','failed','cancelled')),
                    phase TEXT NOT NULL DEFAULT 'queued',
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    model TEXT NOT NULL,
                    analysis_version TEXT NOT NULL,
                    language TEXT NOT NULL DEFAULT 'vi' CHECK(language IN ('vi','en')),
                    delivery_channel TEXT NOT NULL DEFAULT 'none'
                        CHECK(delivery_channel IN ('none','telegram','gmail')),
                    analysis_mode TEXT NOT NULL DEFAULT 'full' CHECK(analysis_mode IN ('full','aggregate')),
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
                    finished_at TEXT,
                    UNIQUE(schedule_generation, window_start, window_end, model, analysis_version)
                );
                CREATE TABLE schedule_v6 (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    enabled INTEGER NOT NULL DEFAULT 0,
                    generation INTEGER NOT NULL DEFAULT 0,
                    interval_seconds INTEGER NOT NULL DEFAULT 300,
                    model TEXT NOT NULL DEFAULT '',
                    language TEXT NOT NULL DEFAULT 'vi' CHECK(language IN ('vi','en')),
                    delivery_channel TEXT NOT NULL DEFAULT 'none'
                        CHECK(delivery_channel IN ('none','telegram','gmail')),
                    next_window_start TEXT,
                    ingest_delay_seconds INTEGER NOT NULL DEFAULT 120,
                    max_catchup_windows INTEGER NOT NULL DEFAULT 24,
                    state TEXT NOT NULL DEFAULT 'idle',
                    error TEXT NOT NULL DEFAULT '',
                    gap_windows INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE report_deliveries_v6 (
                    id INTEGER PRIMARY KEY,
                    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    channel TEXT NOT NULL CHECK(channel IN ('telegram','gmail')),
                    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN (
                        'pending','sending','sent','failed','uncertain'
                    )),
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    payload_sha256 TEXT NOT NULL DEFAULT '',
                    provider_message_id TEXT NOT NULL DEFAULT '',
                    error_code TEXT NOT NULL DEFAULT '',
                    delivery_stage TEXT NOT NULL DEFAULT 'none',
                    last_error_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    sent_at TEXT,
                    UNIQUE(job_id, channel)
                );
            """)
            def table_columns(table):
                return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}

            def source_expression(columns, name, default):
                return name if name in columns else default

            job_columns = [
                "id", "job_type", "status", "phase", "window_start", "window_end", "model",
                "analysis_version", "language", "delivery_channel", "analysis_mode",
                "metrics_json", "timeline_json", "schedule_generation", "progress_current",
                "progress_total", "retry_count", "cancel_requested", "error", "created_at",
                "started_at", "finished_at",
            ]
            schedule_columns = [
                "singleton", "enabled", "generation", "interval_seconds", "model", "language",
                "delivery_channel", "next_window_start", "ingest_delay_seconds",
                "max_catchup_windows", "state", "error", "gap_windows", "updated_at",
            ]
            delivery_columns = [
                "id", "job_id", "channel", "status", "attempt_count", "payload_sha256",
                "provider_message_id", "error_code", "delivery_stage", "last_error_at", "created_at", "updated_at", "sent_at",
            ]
            job_defaults = {
                "job_type": "'manual_window'", "status": "'pending'", "phase": "'queued'",
                "window_start": "''", "window_end": "''", "model": "''",
                "analysis_version": "''", "language": "'vi'", "delivery_channel": "'none'",
                "analysis_mode": "'full'", "metrics_json": "'{}'", "timeline_json": "'[]'",
                "schedule_generation": "NULL", "progress_current": "0", "progress_total": "0",
                "retry_count": "0", "cancel_requested": "0", "error": "''",
                "created_at": "''", "started_at": "NULL", "finished_at": "NULL",
            }
            schedule_defaults = {
                "enabled": "0", "generation": "0", "interval_seconds": "300", "model": "''",
                "language": "'vi'", "delivery_channel": "'none'", "next_window_start": "NULL",
                "ingest_delay_seconds": "120", "max_catchup_windows": "24", "state": "'idle'",
                "error": "''", "gap_windows": "0", "updated_at": "''",
            }
            delivery_defaults = {
                "job_id": "0", "channel": "'telegram'", "status": "'pending'",
                "attempt_count": "0", "payload_sha256": "''", "provider_message_id": "''",
                "error_code": "''", "delivery_stage": "'none'", "last_error_at": "NULL", "created_at": "''", "updated_at": "''", "sent_at": "NULL",
            }
            old_job_columns = table_columns("jobs")
            old_schedule_columns = table_columns("schedule")
            old_delivery_columns = table_columns("report_deliveries")
            job_select = ",".join(
                source_expression(old_job_columns, name, job_defaults.get(name, "NULL"))
                for name in job_columns
            )
            schedule_select = ",".join(
                source_expression(old_schedule_columns, name, schedule_defaults.get(name, "NULL"))
                for name in schedule_columns
            )
            delivery_select = ",".join(
                source_expression(old_delivery_columns, name, delivery_defaults.get(name, "NULL"))
                for name in delivery_columns
            )
            job_columns_sql = ",".join(job_columns)
            schedule_columns_sql = ",".join(schedule_columns)
            delivery_columns_sql = ",".join(delivery_columns)
            counts = {
                "jobs": connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                "schedule": connection.execute("SELECT COUNT(*) FROM schedule").fetchone()[0],
                "deliveries": connection.execute("SELECT COUNT(*) FROM report_deliveries").fetchone()[0],
            }
            connection.execute(
                f"INSERT INTO jobs_v6({job_columns_sql}) SELECT {job_select} FROM jobs"
            )
            connection.execute(
                f"INSERT INTO schedule_v6({schedule_columns_sql}) SELECT {schedule_select} FROM schedule"
            )
            connection.execute(
                f"INSERT INTO report_deliveries_v6({delivery_columns_sql}) "
                f"SELECT {delivery_select} FROM report_deliveries"
            )
            copied = {
                "jobs": connection.execute("SELECT COUNT(*) FROM jobs_v6").fetchone()[0],
                "schedule": connection.execute("SELECT COUNT(*) FROM schedule_v6").fetchone()[0],
                "deliveries": connection.execute("SELECT COUNT(*) FROM report_deliveries_v6").fetchone()[0],
            }
            if copied != counts:
                raise RuntimeError("Dashboard delivery migration row count mismatch")
            connection.executescript("""
                DROP TABLE report_deliveries;
                DROP TABLE schedule;
                DROP TABLE jobs;
                ALTER TABLE jobs_v6 RENAME TO jobs;
                ALTER TABLE schedule_v6 RENAME TO schedule;
                ALTER TABLE report_deliveries_v6 RENAME TO report_deliveries;
                CREATE INDEX idx_report_deliveries_status_id
                    ON report_deliveries(status, id);
            """)
            if list(connection.execute("PRAGMA foreign_key_check")):
                raise RuntimeError("Dashboard delivery migration foreign key check failed")
            connection.execute("PRAGMA user_version=6")
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.close()

    # Recovery artifacts stay beside the configured database and are never
    # accepted from an arbitrary path supplied by an HTTP client.
    @property
    def retention_backup_dir(self):
        directory = (self.path.parent / "retention_backups").resolve()
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _retention_artifact(self, value, *, suffix):
        if not isinstance(value, str) or not value or Path(value).name != value:
            raise ValueError("backup phai la ten file trong retention_backups")
        path = (self.retention_backup_dir / value).resolve()
        if path.parent != self.retention_backup_dir or path.suffix != suffix:
            raise ValueError("backup path khong hop le")
        if path == self.path.resolve():
            raise ValueError("khong duoc ghi de database dang chay")
        return path

    @staticmethod
    def _sha256_file(path):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _table_counts(connection):
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return {row[0]: connection.execute(f'SELECT COUNT(*) FROM "{row[0]}"').fetchone()[0] for row in tables}

    def create_retention_backup(self, *, filename=None):
        """Create an integrity-checked SQLite snapshot atomically."""
        if filename is None:
            filename = f"retention-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.db"
        target = self._retention_artifact(filename, suffix=".db")
        if target.exists():
            raise ValueError("backup da ton tai; chon ten khac")
        temp = target.with_name(target.name + ".tmp")
        try:
            with closing(self._connect()) as source, closing(sqlite3.connect(temp)) as destination:
                source.backup(destination)
                destination.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                destination.commit()
                integrity = destination.execute("PRAGMA integrity_check").fetchone()[0]
                if integrity != "ok":
                    raise RuntimeError("snapshot integrity_check failed")
                schema_version = destination.execute("PRAGMA user_version").fetchone()[0]
                counts = self._table_counts(destination)
            with temp.open("r+b") as stream:
                os.fsync(stream.fileno())
            os.replace(temp, target)
            manifest = {
                "format": "local-ai-siem-retention-backup-v1",
                "database_path": str(self.path.resolve()),
                "schema_version": schema_version,
                "table_counts": counts,
                "sha256": self._sha256_file(target),
                "created_at": format_utc(datetime.now(timezone.utc)),
                "filename": target.name,
            }
            manifest_path = target.with_suffix(".json")
            manifest_temp = manifest_path.with_name(manifest_path.name + ".tmp")
            with manifest_temp.open("w", encoding="utf-8", newline="\n") as stream:
                json.dump(manifest, stream, ensure_ascii=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(manifest_temp, manifest_path)
            return manifest
        finally:
            if temp.exists():
                temp.unlink()

    def list_retention_backups(self):
        result = []
        for db_path in sorted(self.retention_backup_dir.glob("*.db")):
            manifest_path = db_path.with_suffix(".json")
            if manifest_path.exists():
                try:
                    result.append(json.loads(manifest_path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue
        return result

    def restore_retention_backup(self, filename):
        """Validate a snapshot and atomically restore it over this store."""
        source = self._retention_artifact(filename, suffix=".db")
        manifest_path = source.with_suffix(".json")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("manifest backup khong hop le") from exc
        if manifest.get("format") != "local-ai-siem-retention-backup-v1":
            raise ValueError("format backup khong duoc ho tro")
        if manifest.get("database_path") != str(self.path.resolve()):
            raise ValueError("backup khong thuoc database nay")
        if manifest.get("filename") != source.name or manifest.get("sha256") != self._sha256_file(source):
            raise ValueError("checksum backup khong khop")
        temp = self.path.with_name(self.path.name + ".restore.tmp")
        try:
            with closing(sqlite3.connect(source)) as original, closing(sqlite3.connect(temp)) as restored:
                original.backup(restored)
                restored.commit()
                if restored.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("restore integrity_check failed")
                if restored.execute("PRAGMA user_version").fetchone()[0] != manifest.get("schema_version"):
                    raise ValueError("schema version backup khong khop")
                if self._table_counts(restored) != manifest.get("table_counts"):
                    raise ValueError("table counts backup khong khop")
            os.replace(temp, self.path)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(self.path) + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            return manifest
        finally:
            if temp.exists():
                temp.unlink()

    def create_job(self, job_type, window_start, window_end, model, analysis_version,
                   *, language="vi", delivery_channel="none", llm_parameters=None,
                   schedule_generation=None, correlation=None) -> int:
        if language not in {"vi", "en"}:
            raise ValueError("language phải là vi hoặc en")
        _validate_delivery_channel(delivery_channel)
        llm_parameters = _validated_llm_parameters(llm_parameters)
        correlation = _validated_correlation(correlation)
        with self.transaction() as connection:
            cursor = connection.execute(
                """INSERT INTO jobs(job_type,status,window_start,window_end,model,
                   analysis_version,language,delivery_channel,llm_params_json,correlation_json,schedule_generation,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (job_type, "pending", window_start, window_end, model,
                  analysis_version, language, delivery_channel,
                  json.dumps(llm_parameters or {}, ensure_ascii=False, separators=(",", ":")),
                  json.dumps(correlation, ensure_ascii=True, separators=(",", ":")),
                  schedule_generation, utc_now()),
            )
            return cursor.lastrowid

    def get_job(self, job_id: int):
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not row:
                return None
            job = dict(row)
            job["correlation"] = _correlation_payload(
                job.pop("correlation_json", "{}"), internal=True
            )
            return job

    def add_review_event(self, job_id, *, status, severity="inherit", tags=None,
                         note="", actor="local_analyst"):
        """Append a local analyst review event; previous events are never edited."""
        if actor != "local_analyst":
            raise ValueError("review.actor khong hop le")
        cleaned_tags, cleaned_note = _validate_review(status, severity, tags if tags is not None else [], note)
        with self.transaction() as connection:
            if not connection.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                raise KeyError(job_id)
            cursor = connection.execute(
                """INSERT INTO job_review_events(job_id,status,severity,tags_json,note,actor,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (job_id, status, severity, json.dumps(cleaned_tags, ensure_ascii=False),
                 cleaned_note, actor, utc_now()),
            )
            row = connection.execute(
                "SELECT * FROM job_review_events WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        return _review_payload(row)

    def add_review_events(self, job_ids, *, status, severity="inherit", tags=None,
                          note="", actor="local_analyst"):
        """Append one immutable review event for each selected existing job."""
        if actor != "local_analyst":
            raise ValueError("review.actor khong hop le")
        if not isinstance(job_ids, list) or not job_ids or len(job_ids) > 100:
            raise ValueError("job_ids phai la list 1..100 muc")
        normalized = []
        for job_id in job_ids:
            if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
                raise ValueError("job_ids chi nhan so nguyen duong")
            if job_id not in normalized:
                normalized.append(job_id)
        cleaned_tags, cleaned_note = _validate_review(status, severity, tags if tags is not None else [], note)
        with self.transaction() as connection:
            for job_id in normalized:
                if not connection.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                    raise KeyError(job_id)
            now = utc_now()
            events = []
            for job_id in normalized:
                cursor = connection.execute(
                    """INSERT INTO job_review_events(job_id,status,severity,tags_json,note,actor,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (job_id, status, severity, json.dumps(cleaned_tags, ensure_ascii=False),
                     cleaned_note, actor, now),
                )
                row = connection.execute(
                    "SELECT * FROM job_review_events WHERE id=?", (cursor.lastrowid,)
                ).fetchone()
                events.append(_review_payload(row))
        return events

    def review_event_count(self):
        with closing(self._connect()) as connection:
            return connection.execute("SELECT COUNT(*) FROM job_review_events").fetchone()[0]

    def _list_jobs_legacy_query(self, limit=50):
        if not 1 <= limit <= 200:
            raise ValueError("limit phải nằm trong khoảng 1..200")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """SELECT jobs.*,
                          COALESCE(alerts.alert_count, 0) AS alert_count,
                          COALESCE(alerts.rule_count, 0) AS rule_count,
                          COALESCE(alerts.agent_count, 0) AS agent_count,
                          COALESCE(alerts.max_level, 0) AS max_level,
                          COALESCE(groups.group_count, 0) AS group_count,
                          results.result_json AS ai_result_json,
                          reviews.id AS review_id,
                          reviews.job_id AS review_job_id,
                          reviews.status AS review_status,
                          reviews.severity AS review_severity,
                          reviews.tags_json AS review_tags_json,
                          reviews.note AS review_note,
                          reviews.actor AS review_actor,
                          reviews.created_at AS review_created_at
                   FROM jobs
                   LEFT JOIN (
                       SELECT job_id, COUNT(*) AS alert_count,
                              COUNT(DISTINCT rule_id) AS rule_count,
                              COUNT(DISTINCT NULLIF(agent, '')) AS agent_count,
                              MAX(rule_level) AS max_level
                       FROM job_alerts GROUP BY job_id
                   ) AS alerts ON alerts.job_id = jobs.id
                   LEFT JOIN (
                       SELECT job_id, COUNT(*) AS group_count
                       FROM job_groups GROUP BY job_id
                   ) AS groups ON groups.job_id = jobs.id
                   LEFT JOIN analysis_results AS results ON results.id = (
                       SELECT MAX(candidate.id) FROM analysis_results AS candidate
                       WHERE candidate.job_id = jobs.id AND candidate.scope = 'window'
                   )
                   LEFT JOIN job_review_events AS reviews ON reviews.id = (
                       SELECT MAX(candidate.id) FROM job_review_events AS candidate
                       WHERE candidate.job_id = jobs.id
                   )
                   ORDER BY jobs.id DESC LIMIT ?""",
                (limit,),
            )
            output = []
            for row in rows:
                job = dict(row)
                result_json = job.pop("ai_result_json")
                job["llm_parameters"] = _llm_parameters_payload(job.pop("llm_params_json", "{}"))
                job["correlation"] = _correlation_payload(job.pop("correlation_json", "{}"))
                metrics = json.loads(job.pop("metrics_json") or "{}")
                job.pop("timeline_json", None)
                job["alert_count"] = metrics.get("total_alerts", job["alert_count"])
                job["group_count"] = metrics.get("total_groups", job["group_count"])
                job["rule_count"] = metrics.get("unique_rules", job["rule_count"])
                job["agent_count"] = metrics.get("unique_agents", job["agent_count"])
                job["max_level"] = metrics.get("max_level", job["max_level"])
                job["search_terms"] = metrics.get("search_terms", [])
                result = json.loads(result_json) if result_json else {}
                job["ai_severity"] = result.get("severity", "")
                job["ai_summary"] = result.get("summary", "")
                review_fields = {
                    "id": job.pop("review_id"),
                    "job_id": job.pop("review_job_id"),
                    "status": job.pop("review_status"),
                    "severity": job.pop("review_severity"),
                    "tags_json": job.pop("review_tags_json"),
                    "note": job.pop("review_note"),
                    "actor": job.pop("review_actor"),
                    "created_at": job.pop("review_created_at"),
                }
                job["review"] = _review_payload(review_fields) if review_fields["id"] is not None else None
                deliveries = [dict(delivery) for delivery in connection.execute(
                    "SELECT * FROM report_deliveries WHERE job_id=? ORDER BY id",
                    (job["id"],),
                )]
                job["deliveries"] = deliveries
                job["delivery"] = deliveries[-1] if deliveries else None
                output.append(job)
            return output

    def list_jobs_page(self, page=1, page_size=50, filters=None):
        """Return a filtered page and total count without loading all history."""
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            raise ValueError("page must be a positive integer")
        if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 200:
            raise ValueError("page_size must be between 1 and 200")
        filters = filters or {}
        conditions, params = [], []
        for key, column in (("status", "jobs.status"), ("language", "jobs.language"),
                            ("mode", "jobs.analysis_mode")):
            value = filters.get(key)
            if value:
                conditions.append(f"{column}=?")
                params.append(value)
        review = filters.get("review")
        if review:
            conditions.append("COALESCE(reviews.status, 'none')=?")
            params.append(review)
        severity = filters.get("severity")
        if severity not in (None, ""):
            try:
                severity = float(severity)
            except (TypeError, ValueError) as exc:
                raise ValueError("severity must be numeric") from exc
            conditions.append("CAST(COALESCE(json_extract(jobs.metrics_json, '$.max_level'), alerts.max_level, 0) AS REAL)>=?")
            params.append(severity)
        search = str(filters.get("search", "")).strip().lower()
        if search:
            like = f"%{search}%"
            conditions.append("(LOWER(CAST(jobs.id AS TEXT)) LIKE ? OR LOWER(jobs.model) LIKE ? OR LOWER(jobs.status) LIKE ? OR LOWER(COALESCE(results.result_json,'')) LIKE ? OR LOWER(COALESCE(reviews.note,'')) LIKE ? OR LOWER(COALESCE(reviews.tags_json,'')) LIKE ? OR LOWER(COALESCE(jobs.metrics_json,'')) LIKE ?)")
            params.extend([like] * 7)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        from_sql = """ FROM jobs
            LEFT JOIN (SELECT job_id, COUNT(*) alert_count, COUNT(DISTINCT rule_id) rule_count,
                              COUNT(DISTINCT NULLIF(agent, '')) agent_count, MAX(rule_level) max_level
                       FROM job_alerts GROUP BY job_id) alerts ON alerts.job_id=jobs.id
            LEFT JOIN (SELECT job_id, COUNT(*) group_count FROM job_groups GROUP BY job_id)
                       groups ON groups.job_id=jobs.id
            LEFT JOIN analysis_results results ON results.id=(SELECT MAX(candidate.id) FROM analysis_results candidate
                       WHERE candidate.job_id=jobs.id AND candidate.scope='window')
            LEFT JOIN job_review_events reviews ON reviews.id=(SELECT MAX(candidate.id) FROM job_review_events candidate
                       WHERE candidate.job_id=jobs.id)"""
        select_sql = """SELECT jobs.*, COALESCE(alerts.alert_count,0) alert_count,
            COALESCE(alerts.rule_count,0) rule_count, COALESCE(alerts.agent_count,0) agent_count,
            COALESCE(alerts.max_level,0) max_level, COALESCE(groups.group_count,0) group_count,
            results.result_json ai_result_json, reviews.id review_id, reviews.job_id review_job_id,
            reviews.status review_status, reviews.severity review_severity, reviews.tags_json review_tags_json,
            reviews.note review_note, reviews.actor review_actor, reviews.created_at review_created_at"""
        with closing(self._connect()) as connection:
            total = connection.execute("SELECT COUNT(*)" + from_sql + where, params).fetchone()[0]
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            rows = connection.execute(select_sql + from_sql + where + " ORDER BY jobs.id DESC LIMIT ? OFFSET ?",
                                      params + [page_size, (page - 1) * page_size]).fetchall()
            output = []
            for row in rows:
                job = dict(row)
                result_json = job.pop("ai_result_json")
                job["llm_parameters"] = _llm_parameters_payload(job.pop("llm_params_json", "{}"))
                job["correlation"] = _correlation_payload(job.pop("correlation_json", "{}"))
                metrics = json.loads(job.pop("metrics_json") or "{}")
                job.pop("timeline_json", None)
                job["alert_count"] = metrics.get("total_alerts", job["alert_count"])
                job["group_count"] = metrics.get("total_groups", job["group_count"])
                job["rule_count"] = metrics.get("unique_rules", job["rule_count"])
                job["agent_count"] = metrics.get("unique_agents", job["agent_count"])
                job["max_level"] = metrics.get("max_level", job["max_level"])
                job["search_terms"] = metrics.get("search_terms", [])
                result = json.loads(result_json) if result_json else {}
                job["ai_severity"] = result.get("severity", "")
                job["ai_summary"] = result.get("summary", "")
                review_fields = {"id": job.pop("review_id"), "job_id": job.pop("review_job_id"),
                    "status": job.pop("review_status"), "severity": job.pop("review_severity"),
                    "tags_json": job.pop("review_tags_json"), "note": job.pop("review_note"),
                    "actor": job.pop("review_actor"), "created_at": job.pop("review_created_at")}
                job["review"] = _review_payload(review_fields) if review_fields["id"] is not None else None
                output.append(job)
            if output:
                ids = [job["id"] for job in output]
                marks = ",".join("?" for _ in ids)
                batched = {}
                for delivery in connection.execute(f"SELECT * FROM report_deliveries WHERE job_id IN ({marks}) ORDER BY job_id,id", ids):
                    batched.setdefault(delivery["job_id"], []).append(dict(delivery))
                for job in output:
                    deliveries = batched.get(job["id"], [])
                    job["deliveries"] = deliveries
                    job["delivery"] = deliveries[-1] if deliveries else None
        return {"jobs": output, "page": page, "page_size": page_size, "total": total, "pages": pages}

    def list_jobs(self, limit=50):
        """Backward-compatible capped history list for existing callers."""
        return self.list_jobs_page(page=1, page_size=limit)["jobs"]

    def active_job_count(self):
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('pending','running')"
            ).fetchone()[0]

    def enqueue_delivery(self, job_id, channel):
        """Record one delivery request per job/channel after analysis has completed."""
        if channel == "none":
            return None
        _validate_delivery_channel(channel)
        with self.transaction() as connection:
            job = connection.execute(
                "SELECT status FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if not job:
                raise KeyError(job_id)
            if job["status"] not in {"succeeded", "partial"}:
                raise ValueError("Chỉ gửi report của job succeeded hoặc partial")
            now = utc_now()
            connection.execute(
                """INSERT OR IGNORE INTO report_deliveries(
                       job_id,channel,status,created_at,updated_at
                   ) VALUES(?,?, 'pending', ?, ?)""",
                (job_id, channel, now, now),
            )
            row = connection.execute(
                "SELECT * FROM report_deliveries WHERE job_id=? AND channel=?",
                (job_id, channel),
            ).fetchone()
            return dict(row) if row else None

    def claim_next_delivery(self):
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM report_deliveries WHERE status='pending' ORDER BY id LIMIT 1"
            ).fetchone()
            if not row:
                return None
            now = utc_now()
            changed = connection.execute(
                """UPDATE report_deliveries
                   SET status='sending',attempt_count=attempt_count+1,error_code='',last_error_at=NULL,
                       delivery_stage=CASE WHEN channel='telegram' THEN 'pdf' ELSE 'smtp' END,
                       payload_sha256='',provider_message_id='',sent_at=NULL,updated_at=?
                   WHERE id=? AND status='pending'""",
                (now, row["id"]),
            ).rowcount
            claimed = dict(row)
            claimed.update(status="sending", attempt_count=claimed["attempt_count"] + 1, updated_at=now)
            return claimed if changed else None

    def recover_sending_deliveries(self):
        """Do not replay an in-flight request after restart because Telegram may have accepted it."""
        with self.transaction() as connection:
            now = utc_now()
            return connection.execute(
                """UPDATE report_deliveries
                   SET status='uncertain',error_code='recovered_in_flight',last_error_at=?,updated_at=?
                   WHERE status='sending'""",
                (now, now),
            ).rowcount

    def mark_delivery_sent(self, delivery_id, *, payload_sha256, provider_message_id=""):
        if not isinstance(payload_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", payload_sha256):
            raise ValueError("payload_sha256 không hợp lệ")
        with self.transaction() as connection:
            now = utc_now()
            changed = connection.execute(
                """UPDATE report_deliveries
                   SET status='sent',payload_sha256=?,provider_message_id=?,error_code='',delivery_stage='complete',
                       sent_at=?,updated_at=?
                   WHERE id=? AND status='sending'""",
                (payload_sha256, str(provider_message_id)[:80], now, now, delivery_id),
            ).rowcount
            if not changed:
                raise ValueError("Delivery không ở trạng thái sending")

    def mark_delivery_problem(self, delivery_id, *, status, error_code, stage="none"):
        if status not in {"failed", "uncertain"}:
            raise ValueError("Delivery status không hợp lệ")
        safe_code = re.sub(r"[^a-z0-9_:-]", "_", str(error_code).lower())[:80] or "delivery_error"
        if stage not in {"none", "summary", "pdf", "smtp"}:
            stage = "none"
        with self.transaction() as connection:
            now = utc_now()
            changed = connection.execute(
                """UPDATE report_deliveries
                   SET status=?,error_code=?,delivery_stage=?,last_error_at=?,updated_at=?
                   WHERE id=? AND status='sending'""",
                (status, safe_code, stage, now, now, delivery_id),
            ).rowcount
            if not changed:
                raise ValueError("Delivery không ở trạng thái sending")

    def retry_delivery(self, delivery_id, *, allow_sent=False):
        if not isinstance(allow_sent, bool):
            raise ValueError("allow_sent phải là boolean")
        eligible = "('failed','uncertain','sent')" if allow_sent else "('failed','uncertain')"
        with self.transaction() as connection:
            changed = connection.execute(
                f"""UPDATE report_deliveries
                   SET status='pending',error_code='',delivery_stage='none',last_error_at=NULL,
                       payload_sha256='',provider_message_id='',sent_at=NULL,updated_at=?
                   WHERE id=? AND status IN {eligible} AND attempt_count<3
                     AND (status='sent' OR delivery_stage!='complete')""",
                (utc_now(), delivery_id),
            ).rowcount
            if not changed:
                message = "Chỉ gửi lại delivery đã sent/lỗi/chưa chắc chắn và tối đa 3 lần" if allow_sent else (
                    "Chỉ retry delivery lỗi/chưa chắc chắn và tối đa 3 lần"
                )
                raise ValueError(message)
            row = connection.execute(
                "SELECT * FROM report_deliveries WHERE id=?", (delivery_id,)
            ).fetchone()
            return dict(row)

    def get_delivery(self, delivery_id):
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM report_deliveries WHERE id=?", (delivery_id,)
            ).fetchone()
            return dict(row) if row else None

    def claim_next_job(self):
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE status='pending' ORDER BY id LIMIT 1"
            ).fetchone()
            if not row:
                return None
            started_at = utc_now()
            changed = connection.execute(
                """UPDATE jobs SET status='running',phase='fetching_alerts',started_at=?
                   WHERE id=? AND status='pending'""",
                (started_at, row["id"]),
            ).rowcount
            claimed = dict(row)
            claimed["llm_parameters"] = _llm_parameters_payload(
                claimed.pop("llm_params_json", "{}"), include_system_prompt=True
            )
            claimed["correlation"] = _correlation_payload(
                claimed.pop("correlation_json", "{}"), internal=True
            )
            claimed.update(status="running", phase="fetching_alerts", started_at=started_at)
            return claimed if changed else None

    def recover_running_jobs(self):
        with self.transaction() as connection:
            security_failed = connection.execute(
                """UPDATE jobs SET status='failed',phase='failed',
                   error='Security analysis interrupted; automatic retry is disabled',
                   finished_at=?
                   WHERE status='running' AND correlation_json<>'{}'""",
                (utc_now(),),
            ).rowcount
            generic_requeued = connection.execute(
                """UPDATE jobs SET status='pending',phase='queued',started_at=NULL,
                   error='recovered after restart'
                   WHERE status='running' AND correlation_json='{}'"""
            ).rowcount
            return security_failed + generic_requeued

    def complete_job(self, job_id, status, *, error="", progress_current=None, progress_total=None):
        if status not in {"succeeded", "partial", "failed", "cancelled"}:
            raise ValueError("terminal status không hợp lệ")
        with self.transaction() as connection:
            job = connection.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise KeyError(job_id)
            phase = {
                "succeeded": "completed", "partial": "completed",
                "failed": "failed", "cancelled": "cancelled",
            }[status]
            updates = ["status=?", "phase=?", "error=?", "finished_at=?"]
            values = [status, phase, str(error)[:2000], utc_now()]
            if progress_current is not None:
                updates.append("progress_current=?")
                values.append(progress_current)
            if progress_total is not None:
                updates.append("progress_total=?")
                values.append(progress_total)
            values.append(job_id)
            connection.execute(f"UPDATE jobs SET {','.join(updates)} WHERE id=?", values)

    def update_progress(self, job_id, current, total):
        with self.transaction() as connection:
            connection.execute(
                "UPDATE jobs SET progress_current=?,progress_total=? WHERE id=?",
                (current, total, job_id),
            )

    def update_phase(self, job_id, phase):
        if phase not in JOB_PHASES:
            raise ValueError("Job phase không hợp lệ")
        with self.transaction() as connection:
            changed = connection.execute(
                "UPDATE jobs SET phase=? WHERE id=? AND status='running'",
                (phase, job_id),
            ).rowcount
            if not changed:
                raise ValueError("Chỉ cập nhật phase cho job running")

    def request_cancel(self, job_id):
        with self.transaction() as connection:
            changed = connection.execute(
                "UPDATE jobs SET cancel_requested=1 WHERE id=? AND status IN ('pending','running')",
                (job_id,),
            ).rowcount
            if not changed:
                raise ValueError("Job không ở trạng thái có thể cancel")

    def retry_job(self, job_id):
        with self.transaction() as connection:
            job = connection.execute(
                "SELECT correlation_json FROM jobs WHERE id=?", (job_id,),
            ).fetchone()
            if job and job["correlation_json"] != "{}":
                raise ValueError("Security-test AI jobs cannot be retried")
            changed = connection.execute(
                """UPDATE jobs SET status='pending',phase='queued',retry_count=retry_count+1,error='',
                   cancel_requested=0,started_at=NULL,finished_at=NULL
                   WHERE id=? AND status='failed' AND retry_count<3""",
                (job_id,),
            ).rowcount
            if not changed:
                raise ValueError("Chỉ retry job failed và tối đa 3 lần")

    def replace_job_data(self, job_id, aggregate):
        analysis_mode = aggregate.get("analysis_mode", "full")
        if analysis_mode not in {"full", "aggregate"}:
            raise ValueError("analysis_mode không hợp lệ")
        groups = aggregate.get("groups", [])
        alerts = aggregate.get("alerts", [])
        metrics = {
            "total_alerts": int(aggregate.get("total_alerts", len(alerts))),
            "total_groups": int(aggregate.get("total_groups", len(groups))),
            "unique_rules": int(aggregate.get(
                "unique_rules", len({row.get("rule_id") for row in alerts if row.get("rule_id")})
            )),
            "unique_agents": int(aggregate.get(
                "unique_agents", len({row.get("agent") for row in alerts if row.get("agent")})
            )),
            "unique_source_ips": int(aggregate.get(
                "unique_source_ips", len({row.get("source_ip") for row in alerts if row.get("source_ip")})
            )),
            "max_level": max(
                [group.get("max_level", 0) for group in groups]
                + [row.get("rule_level", 0) for row in alerts],
                default=0,
            ),
            "search_terms": _search_terms(aggregate),
        }
        with self.transaction() as connection:
            connection.execute("DELETE FROM job_alerts WHERE job_id=?", (job_id,))
            connection.execute("DELETE FROM job_groups WHERE job_id=?", (job_id,))
            connection.execute(
                "UPDATE jobs SET analysis_mode=?,metrics_json=?,timeline_json=? WHERE id=?",
                (analysis_mode, json.dumps(metrics),
                 json.dumps(aggregate.get("timeline", []), ensure_ascii=False), job_id),
            )
            connection.executemany(
                """INSERT INTO job_alerts(job_id,index_name,document_id,timestamp,rule_id,
                   rule_level,description,agent,source_ip,group_key)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                [(
                    job_id, row["_index"], row["_id"], row["timestamp"], row["rule_id"],
                    row["rule_level"], row["description"], row["agent"], row["source_ip"],
                    row["group_key"],
                ) for row in aggregate["alerts"]],
            )
            connection.executemany(
                "INSERT INTO job_groups(job_id,group_key,group_json) VALUES(?,?,?)",
                [(job_id, group["group_key"], json.dumps(
                    {key: value for key, value in group.items() if key != "sample_log"},
                    ensure_ascii=False,
                ))
                 for group in aggregate["groups"]],
            )

    def save_result(self, job_id, scope, scope_key, result, *, coverage=None,
                    warnings=None, provenance=None, latency_s=0, revision=1):
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO analysis_results(job_id,scope,scope_key,result_json,
                    coverage_json,warnings_json,provenance_json,latency_s,revision,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (job_id, scope, scope_key, json.dumps(result, ensure_ascii=False),
                  json.dumps(coverage or {}, ensure_ascii=False),
                  json.dumps(warnings or [], ensure_ascii=False),
                  json.dumps(provenance or {}, ensure_ascii=False),
                  latency_s, revision, utc_now()),
            )

    def save_result_and_complete_if_not_cancelled(
            self, job_id, scope, scope_key, result, *, coverage=None, warnings=None,
            provenance=None, latency_s=0, revision=1, status="succeeded",
            progress_current=None, progress_total=None):
        """Atomically persist a terminal result only while cancellation has not won.

        A model call cannot be interrupted portably, so the durable commit is the
        cancellation boundary: a cancel request that is committed first prevents
        both the result row and a success state from being stored.
        """
        if status not in {"succeeded", "partial"}:
            raise ValueError("Result chỉ có thể hoàn tất job succeeded hoặc partial")
        with self.transaction() as connection:
            phase = "completed"
            updates = ["status=?", "phase=?", "error=''", "finished_at=?"]
            values = [status, phase, utc_now()]
            if progress_current is not None:
                updates.append("progress_current=?")
                values.append(progress_current)
            if progress_total is not None:
                updates.append("progress_total=?")
                values.append(progress_total)
            values.extend([job_id])
            changed = connection.execute(
                f"""UPDATE jobs SET {','.join(updates)}
                    WHERE id=? AND status='running' AND cancel_requested=0""",
                values,
            ).rowcount
            if not changed:
                return False
            connection.execute(
                """INSERT INTO analysis_results(job_id,scope,scope_key,result_json,
                   coverage_json,warnings_json,provenance_json,latency_s,revision,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (job_id, scope, scope_key, json.dumps(result, ensure_ascii=False),
                 json.dumps(coverage or {}, ensure_ascii=False),
                 json.dumps(warnings or [], ensure_ascii=False),
                 json.dumps(provenance or {}, ensure_ascii=False),
                 latency_s, revision, utc_now()),
            )
            return True

    def get_job_detail(self, job_id):
        with closing(self._connect()) as connection:
            job_row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job_row:
                return None
            job = dict(job_row)
            job["llm_parameters"] = _llm_parameters_payload(job.pop("llm_params_json", "{}"))
            job["correlation"] = _correlation_payload(job.pop("correlation_json", "{}"))
            job["metrics"] = json.loads(job.pop("metrics_json"))
            job["timeline"] = json.loads(job.pop("timeline_json"))
            results = [dict(row) for row in connection.execute(
                "SELECT * FROM analysis_results WHERE job_id=? ORDER BY id", (job_id,)
            )]
            for result in results:
                for field in (
                    "result_json", "coverage_json", "warnings_json", "provenance_json",
                ):
                    result[field.removesuffix("_json")] = json.loads(result.pop(field))
            job["results"] = results
            job["groups"] = [json.loads(row[0]) for row in connection.execute(
                "SELECT group_json FROM job_groups WHERE job_id=? ORDER BY id", (job_id,)
            )]
            job["alerts"] = [dict(row) for row in connection.execute(
                "SELECT * FROM job_alerts WHERE job_id=? ORDER BY timestamp,id", (job_id,)
            )]
            job["review_history"] = [_review_payload(row) for row in connection.execute(
                "SELECT * FROM job_review_events WHERE job_id=? ORDER BY id", (job_id,)
            )]
            job["review"] = job["review_history"][-1] if job["review_history"] else None
            deliveries = [dict(delivery) for delivery in connection.execute(
                "SELECT * FROM report_deliveries WHERE job_id=? ORDER BY id",
                (job_id,),
            )]
            job["deliveries"] = deliveries
            job["delivery"] = deliveries[-1] if deliveries else None
        return job

    def maintenance_stats(self):
        """Return local-only runtime counts without exposing database contents or paths."""
        with closing(self._connect()) as connection:
            queue = dict(connection.execute("""
                SELECT
                    SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) AS running,
                    MIN(CASE WHEN status='pending' THEN created_at END) AS oldest_pending_at
                FROM jobs
            """).fetchone())
            total_jobs = connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            terminal_jobs = connection.execute("""
                SELECT COUNT(*) FROM jobs
                WHERE status IN ('succeeded','partial','failed','cancelled')
            """).fetchone()[0]
            review_events = connection.execute("SELECT COUNT(*) FROM job_review_events").fetchone()[0]
        database_bytes = 0
        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            try:
                database_bytes += candidate.stat().st_size
            except FileNotFoundError:
                # SQLite creates and removes WAL sidecars between calls; their
                # disappearance must not make the status endpoint fail.
                continue
        return {
            "queue": {
                "pending": int(queue["pending"] or 0),
                "running": int(queue["running"] or 0),
                "oldest_pending_at": queue["oldest_pending_at"],
            },
            "database": {
                "bytes": database_bytes,
                "job_count": total_jobs,
                "terminal_job_count": terminal_jobs,
            },
            "reviews": {"event_count": review_events},
        }

    def prune_terminal_jobs(self, *, retention_days, keep_latest, backup=True):
        """Delete only old terminal jobs, preserving the requested newest audit records."""
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 0:
            raise ValueError("retention_days phai la so nguyen khong am")
        if isinstance(keep_latest, bool) or not isinstance(keep_latest, int) or not 0 <= keep_latest <= 10000:
            raise ValueError("retention_keep_latest phai nam trong khoang 0..10000")
        if retention_days == 0:
            return {"deleted_jobs": 0, "enabled": False}
        snapshot = self.create_retention_backup() if backup else None
        cutoff = format_utc(datetime.now(timezone.utc) - timedelta(days=retention_days))
        with self.transaction() as connection:
            deleted = connection.execute("""
                DELETE FROM jobs
                WHERE id IN (
                    SELECT id FROM jobs
                    WHERE status IN ('succeeded','partial','failed','cancelled')
                      AND finished_at IS NOT NULL AND finished_at < ?
                      AND id NOT IN (
                          SELECT id FROM jobs
                          WHERE status IN ('succeeded','partial','failed','cancelled')
                          ORDER BY finished_at DESC, id DESC LIMIT ?
                      )
                )
            """, (cutoff, keep_latest)).rowcount
        result = {"deleted_jobs": deleted, "enabled": True, "cutoff": cutoff}
        if snapshot:
            result["backup"] = snapshot
        return result

    def retention_preview(self, *, retention_days, keep_latest, sample_limit=50):
        """Describe a prune without mutating SQLite; identifiers are deliberately bounded."""
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 0:
            raise ValueError("retention_days phai la so nguyen khong am")
        if isinstance(keep_latest, bool) or not isinstance(keep_latest, int) or not 0 <= keep_latest <= 10000:
            raise ValueError("retention_keep_latest phai nam trong khoang 0..10000")
        if isinstance(sample_limit, bool) or not isinstance(sample_limit, int) or not 1 <= sample_limit <= 100:
            raise ValueError("sample_limit phai nam trong khoang 1..100")
        cutoff = format_utc(datetime.now(timezone.utc) - timedelta(days=retention_days)) if retention_days else None
        terminal_where = "status IN ('succeeded','partial','failed','cancelled')"
        with closing(self._connect()) as connection:
            terminal_count = connection.execute(f"SELECT COUNT(*) FROM jobs WHERE {terminal_where}").fetchone()[0]
            if cutoff is None:
                candidates = []
            else:
                candidates = connection.execute(f"""
                    SELECT id, finished_at FROM jobs WHERE {terminal_where}
                      AND finished_at IS NOT NULL AND finished_at < ?
                      AND id NOT IN (SELECT id FROM jobs WHERE {terminal_where}
                                     ORDER BY finished_at DESC, id DESC LIMIT ?)
                    ORDER BY finished_at, id
                """, (cutoff, keep_latest)).fetchall()
        candidate_ids = [row["id"] for row in candidates]
        generation = hashlib.sha256(json.dumps({
            "policy": [retention_days, keep_latest],
            "terminal_count": terminal_count, "candidates": [(row["id"], row["finished_at"]) for row in candidates],
        }, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
        return {
            "enabled": retention_days > 0,
            "policy": {"retention_days": retention_days, "retention_keep_latest": keep_latest},
            "cutoff": cutoff,
            "candidate_count": len(candidates),
            "candidate_ids": candidate_ids[:sample_limit],
            "candidate_ids_truncated": len(candidate_ids) > sample_limit,
            "candidate_range": ({"oldest_finished_at": candidates[0]["finished_at"], "newest_finished_at": candidates[-1]["finished_at"]} if candidates else None),
            "retained_terminal_count": terminal_count - len(candidates),
            "estimated_database_bytes_reclaimed": None,
            "confirmation_token": f"retention-v1:{generation}",
        }

    def get_alert_row(self, row_id):
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM job_alerts WHERE id=?", (row_id,)).fetchone()
            return dict(row) if row else None

    def get_schedule(self, *, include_llm_parameters=False):
        with closing(self._connect()) as connection:
            schedule = dict(connection.execute("SELECT * FROM schedule WHERE singleton=1").fetchone())
            schedule["llm_parameters"] = _llm_parameters_payload(
                schedule.pop("llm_params_json", "{}"), include_system_prompt=include_llm_parameters
            )
            return schedule

    def configure_schedule(self, *, enabled, interval_seconds, model, next_window_start,
                           language="vi", delivery_channel="none", llm_parameters=None,
                           ingest_delay_seconds=120, max_catchup_windows=24):
        if language not in {"vi", "en"}:
            raise ValueError("language phải là vi hoặc en")
        _validate_delivery_channel(delivery_channel)
        llm_parameters = _validated_llm_parameters(llm_parameters)
        with self.transaction() as connection:
            connection.execute(
                """UPDATE schedule SET enabled=?,generation=generation+1,interval_seconds=?,
                   model=?,language=?,delivery_channel=?,llm_params_json=?,next_window_start=?,ingest_delay_seconds=?,max_catchup_windows=?,
                   state=?,error='',gap_windows=0,updated_at=? WHERE singleton=1""",
                (int(enabled), interval_seconds, model, language, delivery_channel,
                 json.dumps(llm_parameters or {}, ensure_ascii=False, separators=(",", ":")), next_window_start,
                 ingest_delay_seconds, max_catchup_windows,
                 "active" if enabled else "idle", utc_now()),
            )
        return self.get_schedule()

    def advance_schedule(self, next_window_start, *, gap_windows=0):
        with self.transaction() as connection:
            connection.execute(
                """UPDATE schedule SET next_window_start=?,gap_windows=gap_windows+?,
                   state='active',error='',updated_at=? WHERE singleton=1""",
                (next_window_start, gap_windows, utc_now()),
            )

    def block_schedule(self, error):
        with self.transaction() as connection:
            connection.execute(
                "UPDATE schedule SET state='blocked',error=?,updated_at=? WHERE singleton=1",
                (str(error)[:2000], utc_now()),
            )

    def unblock_schedule(self):
        with self.transaction() as connection:
            connection.execute(
                "UPDATE schedule SET state='active',error='',updated_at=? WHERE singleton=1",
                (utc_now(),),
            )

    def skip_schedule_window(self):
        schedule = self.get_schedule()
        if schedule["state"] != "blocked" or not schedule["next_window_start"]:
            raise ValueError("Schedule không có blocked window để skip")
        next_start = parse_utc(schedule["next_window_start"]) + timedelta(
            seconds=schedule["interval_seconds"]
        )
        self.advance_schedule(format_utc(next_start), gap_windows=1)
        return self.get_schedule()
