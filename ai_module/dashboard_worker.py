"""Single-worker execution and fixed-window scheduling for local dashboard."""
import threading
import time
from datetime import datetime, timedelta, timezone

from analysis_service import ANALYSIS_VERSION, aggregate_alerts, aggregate_rule_buckets
from dashboard_time import format_utc, parse_utc
from reader import fetch_alerts_window

# Kept as a seam for existing worker tests and local integrations; it now
# points at the cap-aware reader rather than the old fail-closed fetcher.
fetch_alerts_range = fetch_alerts_window


PRESET_SECONDS = {300, 900, 1800, 3600, 7200, 21600, 43200, 86400}


def due_windows(schedule: dict, now: datetime) -> tuple[list[tuple[str, str]], int]:
    """Return due fixed windows, constructing at most the explicit catch-up cap."""
    if not schedule["enabled"] or schedule["state"] == "blocked" or not schedule["next_window_start"]:
        return [], 0
    interval = timedelta(seconds=schedule["interval_seconds"])
    delay = timedelta(seconds=schedule["ingest_delay_seconds"])
    cursor = parse_utc(schedule["next_window_start"])
    last_due_end = now - delay
    if cursor + interval > last_due_end:
        return [], 0
    due_count = int((last_due_end - cursor) // interval)
    overflow = max(0, due_count - schedule["max_catchup_windows"])
    cursor += interval * overflow
    due = [
        (format_utc(cursor + interval * index), format_utc(cursor + interval * (index + 1)))
        for index in range(due_count - overflow)
    ]
    return due, overflow


class DashboardRuntime:
    def __init__(self, store, cfg, analysis_service, *, poll_seconds=1):
        self.store = store
        self.cfg = cfg
        self.analysis_service = analysis_service
        self.poll_seconds = poll_seconds
        self.stop_event = threading.Event()
        self.wakeup_event = threading.Event()
        self.worker_thread = None
        self.scheduler_thread = None
        self.store.recover_running_jobs()

    def start(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, name="dashboard-worker", daemon=True)
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, name="dashboard-scheduler", daemon=True)
        self.worker_thread.start()
        self.scheduler_thread.start()

    def stop(self, timeout=5):
        self.stop_event.set()
        self.wakeup_event.set()
        for thread in (self.worker_thread, self.scheduler_thread):
            if thread:
                thread.join(timeout)

    def notify(self):
        self.wakeup_event.set()

    def _worker_loop(self):
        while not self.stop_event.is_set():
            job = self.store.claim_next_job()
            if not job:
                self.wakeup_event.wait(self.poll_seconds)
                self.wakeup_event.clear()
                continue
            self._run_job(job)

    def _run_job(self, job):
        try:
            if self.store.get_job(job["id"])["cancel_requested"]:
                self.store.complete_job(job["id"], "cancelled")
                return
            dashboard_cfg = self.cfg.get("dashboard", {})
            fetched = fetch_alerts_range(
                self.cfg, job["window_start"], job["window_end"],
                max_alerts=dashboard_cfg.get("max_alerts_per_job", 2000),
                max_rule_buckets=dashboard_cfg.get("max_aggregate_rule_buckets", 1000),
                max_timeline_buckets=dashboard_cfg.get("max_timeline_buckets", 96),
            )
            self.store.update_progress(job["id"], 0, fetched["total"])
            self.store.update_phase(job["id"], "preparing_analysis")
            if fetched.get("analysis_mode", "full") == "aggregate":
                aggregate = aggregate_rule_buckets(fetched)
            else:
                aggregate = aggregate_alerts(
                    fetched["alerts"],
                    sample_log_chars=dashboard_cfg.get("max_sample_log_chars", 1000),
                )
                aggregate["timeline"] = fetched.get("timeline", [])
            self.store.replace_job_data(job["id"], aggregate)
            if self.store.get_job(job["id"])["cancel_requested"]:
                self.store.complete_job(job["id"], "cancelled")
                return
            if not aggregate["total_alerts"]:
                self.store.complete_job(job["id"], "succeeded", progress_current=0, progress_total=0)
                self._advance_schedule_for_job(job)
                return
            self.store.update_phase(job["id"], "calling_ollama")
            started = time.perf_counter()
            result = self.analysis_service.analyze_aggregate(
                aggregate, job["model"], job.get("language", "vi")
            )
            latency = time.perf_counter() - started
            self.store.update_phase(job["id"], "saving_result")
            warnings = ["Prompt coverage bị rút gọn"] if result["coverage"]["truncated"] else []
            if aggregate.get("analysis_mode") == "aggregate":
                warnings.append(
                    f"Aggregate-only: {aggregate['total_alerts']} alert vượt detail cap; không tải full log"
                )
            if result["analysis"]["severity"] == "unknown":
                warnings.append("LLM trả fallback/unknown")
            provenance = dict(result.get("provenance") or {})
            if provenance.get("redacted_exact_sample_log_echoes", 0):
                warnings.append("Đã loại trích đoạn sample log bị model lặp lại khỏi kết quả lưu")
            provenance.setdefault("requested_language", job.get("language", "vi"))
            provenance.setdefault(
                "effective_language",
                provenance.get("response_language", result["analysis"].get("response_language", "")),
            )
            provenance.setdefault("language_compliance", "unknown")
            provenance.setdefault("options", provenance.get("ollama_options", {}))
            language_compliance = provenance["language_compliance"]
            # Accept the earlier draft value while persisting the public contract enum.
            if language_compliance == "pass":
                language_compliance = "full"
                provenance["language_compliance"] = language_compliance
            elif language_compliance not in {"full", "partial", "unknown"}:
                language_compliance = "unknown"
                provenance["language_compliance"] = language_compliance
            if language_compliance != "full":
                warnings.append(
                    "Language compliance is partial or unknown; review the natural-language fields"
                )
            self.store.save_result(
                job["id"], "window", "window", result["analysis"],
                coverage=result["coverage"], warnings=warnings,
                provenance=provenance, latency_s=latency,
            )
            status = "partial" if result["partial"] or language_compliance != "full" else "succeeded"
            self.store.complete_job(
                job["id"], status,
                progress_current=aggregate["total_alerts"],
                progress_total=aggregate["total_alerts"],
            )
            self._advance_schedule_for_job(job)
        except Exception as exc:
            current = self.store.get_job(job["id"])
            if current and current["cancel_requested"]:
                self.store.complete_job(job["id"], "cancelled")
                return
            # ponytail: retry thủ công ở MVP; thêm transient classifier/backoff khi live test có lỗi cụ thể.
            self.store.complete_job(job["id"], "failed", error=f"{type(exc).__name__}: {exc}")
            if job["job_type"] == "scheduled_window":
                self.store.block_schedule(f"{type(exc).__name__}: {exc}")

    def _advance_schedule_for_job(self, job):
        if job["job_type"] != "scheduled_window":
            return
        schedule = self.store.get_schedule()
        if schedule["generation"] != job["schedule_generation"]:
            return
        self.store.advance_schedule(job["window_end"])

    def _scheduler_loop(self):
        while not self.stop_event.wait(self.poll_seconds):
            schedule = self.store.get_schedule()
            now = datetime.now(timezone.utc)
            windows, overflow = due_windows(schedule, now)
            if overflow:
                interval = timedelta(seconds=schedule["interval_seconds"])
                first_kept = parse_utc(windows[0][0]) if windows else parse_utc(schedule["next_window_start"]) + interval * overflow
                self.store.advance_schedule(format_utc(first_kept), gap_windows=overflow)
                schedule = self.store.get_schedule()
            if not windows:
                continue
            start, end = windows[0]
            try:
                self.store.create_job(
                    "scheduled_window", start, end, schedule["model"], ANALYSIS_VERSION,
                    language=schedule.get("language", "vi"),
                    schedule_generation=schedule["generation"],
                )
            except Exception as exc:
                # Duplicate means job already exists; any other persistent error blocks schedule visibly.
                if "UNIQUE constraint failed" not in str(exc):
                    self.store.block_schedule(f"{type(exc).__name__}: {exc}")
            self.notify()
