"""SQLite persistence for local dashboard jobs and one fixed-window schedule."""
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard_time import format_utc, parse_utc, utc_now


SCHEMA_VERSION = 4
JOB_PHASES = {
    "queued", "fetching_alerts", "preparing_analysis", "calling_ollama",
    "saving_result", "completed", "failed", "cancelled",
}
REVIEW_STATUSES = {"new", "acknowledged", "investigating", "resolved", "false_positive"}
REVIEW_SEVERITIES = {"inherit", "low", "medium", "high", "critical"}


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
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def create_job(self, job_type, window_start, window_end, model, analysis_version,
                   *, language="vi", schedule_generation=None) -> int:
        if language not in {"vi", "en"}:
            raise ValueError("language phải là vi hoặc en")
        with self.transaction() as connection:
            cursor = connection.execute(
                """INSERT INTO jobs(job_type,status,window_start,window_end,model,
                   analysis_version,language,schedule_generation,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (job_type, "pending", window_start, window_end, model,
                 analysis_version, language, schedule_generation, utc_now()),
            )
            return cursor.lastrowid

    def get_job(self, job_id: int):
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            return dict(row) if row else None

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

    def review_event_count(self):
        with closing(self._connect()) as connection:
            return connection.execute("SELECT COUNT(*) FROM job_review_events").fetchone()[0]

    def list_jobs(self, limit=50):
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
                output.append(job)
            return output

    def active_job_count(self):
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('pending','running')"
            ).fetchone()[0]

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
            claimed.update(status="running", phase="fetching_alerts", started_at=started_at)
            return claimed if changed else None

    def recover_running_jobs(self):
        with self.transaction() as connection:
            return connection.execute(
                """UPDATE jobs SET status='pending',phase='queued',started_at=NULL,
                   error='recovered after restart'
                   WHERE status='running'"""
            ).rowcount

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

    def get_job_detail(self, job_id):
        with closing(self._connect()) as connection:
            job_row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job_row:
                return None
            job = dict(job_row)
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
        database_bytes = sum(
            candidate.stat().st_size for candidate in (
                self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm"),
            ) if candidate.exists()
        )
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

    def prune_terminal_jobs(self, *, retention_days, keep_latest):
        """Delete only old terminal jobs, preserving the requested newest audit records."""
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 0:
            raise ValueError("retention_days phai la so nguyen khong am")
        if isinstance(keep_latest, bool) or not isinstance(keep_latest, int) or not 0 <= keep_latest <= 10000:
            raise ValueError("retention_keep_latest phai nam trong khoang 0..10000")
        if retention_days == 0:
            return {"deleted_jobs": 0, "enabled": False}
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
        return {"deleted_jobs": deleted, "enabled": True, "cutoff": cutoff}

    def get_alert_row(self, row_id):
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM job_alerts WHERE id=?", (row_id,)).fetchone()
            return dict(row) if row else None

    def get_schedule(self):
        with closing(self._connect()) as connection:
            return dict(connection.execute("SELECT * FROM schedule WHERE singleton=1").fetchone())

    def configure_schedule(self, *, enabled, interval_seconds, model, next_window_start,
                           language="vi",
                           ingest_delay_seconds=120, max_catchup_windows=24):
        if language not in {"vi", "en"}:
            raise ValueError("language phải là vi hoặc en")
        with self.transaction() as connection:
            connection.execute(
                """UPDATE schedule SET enabled=?,generation=generation+1,interval_seconds=?,
                   model=?,language=?,next_window_start=?,ingest_delay_seconds=?,max_catchup_windows=?,
                   state=?,error='',gap_windows=0,updated_at=? WHERE singleton=1""",
                (int(enabled), interval_seconds, model, language, next_window_start,
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
