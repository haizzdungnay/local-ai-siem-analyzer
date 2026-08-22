"""Single-worker execution and fixed-window scheduling for local dashboard."""
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from analysis_service import (
    ANALYSIS_VERSION,
    aggregate_alerts,
    aggregate_rule_buckets,
    security_test_evidence_contract,
    security_test_summary_prefix,
)
from dashboard_time import format_utc, parse_utc
from gmail_notifier import GMAIL_CHANNEL, GmailConfigurationError, GmailDeliveryError, GmailNotifier
from reader import fetch_active_source_ips, fetch_alerts_window
from telegram_notifier import TELEGRAM_CHANNEL, TelegramConfigurationError, TelegramDeliveryError, TelegramNotifier

# Kept as a seam for existing worker tests and local integrations; it now
# points at the cap-aware reader rather than the old fail-closed fetcher.
fetch_alerts_range = fetch_alerts_window


PRESET_SECONDS = {300, 900, 1800, 3600, 7200, 21600, 43200, 86400, 259200, 604800, 2592000}
LOGGER = logging.getLogger(__name__)

_GENERIC_BASIS_PHRASES = {
    "không có suy luận có cấu trúc trong kết quả này",
    "không có bất định được ghi nhận",
    "không có giới hạn được ghi nhận",
    "no structured inference is available",
    "no uncertainty was recorded",
    "no limitation was recorded",
}


def _normalized_quality_text(value: str) -> str:
    return re.sub(r"[.!?]+$", "", re.sub(r"\s+", " ", value).strip().lower())


def _security_analysis_quality(aggregate: dict, analysis: dict) -> list[str]:
    """Require a security-test summary to name observed Wazuh evidence."""
    if not aggregate.get("security_test_correlation"):
        return []
    summary = analysis.get("summary") if isinstance(analysis, dict) else ""
    findings = analysis.get("key_findings") if isinstance(analysis, dict) else []
    summary_text = re.sub(r"\s+", " ", summary).strip().lower() if isinstance(summary, str) else ""
    finding_text = " ".join(item for item in findings if isinstance(item, str))
    normalized = re.sub(r"\s+", " ", f"{summary_text} {finding_text}").strip().lower()
    generic_phrases = {
        "tổng quan về các cảnh báo và nhóm cảnh báo",
        "analysis of alerts",
        "overview of alerts and alert groups",
    }
    failures = []
    try:
        evidence = security_test_evidence_contract(aggregate)
        required_prefix = security_test_summary_prefix(aggregate)
    except ValueError:
        return ["Trusted Wazuh evidence contract is invalid"]
    if not isinstance(summary, str) or not summary.startswith(required_prefix):
        failures.append("AI summary does not begin with the exact WAZUH_EVIDENCE prefix")
    narrative = summary[len(required_prefix):].strip() if (
        isinstance(summary, str) and summary.startswith(required_prefix)
    ) else summary_text
    narrative_text = _normalized_quality_text(narrative)
    if not narrative_text or narrative_text in generic_phrases:
        failures.append("AI summary is generic and does not summarize Wazuh evidence")
    rule_ids = evidence["rule_ids"]
    if rule_ids and not any(rule_id.lower() in summary_text for rule_id in rule_ids):
        failures.append("AI summary does not identify any observed Wazuh rule ID")
    total = str(aggregate.get("total_alerts", ""))
    if total and total not in summary_text:
        failures.append("AI summary does not identify the observed alert count")
    window_start = evidence["window_start"]
    window_end = evidence["window_end"]
    if not window_start or not window_end or window_start not in summary or window_end not in summary:
        failures.append("AI summary does not identify the correlation window UTC")
    basis = analysis.get("assessment_basis") if isinstance(analysis, dict) else None
    observed = basis.get("observed_facts") if isinstance(basis, dict) else None
    observed_text = " ".join(item for item in observed or [] if isinstance(item, str)).lower()
    if (
        not observed_text
        or total not in observed_text
        or any(rule_id.lower() not in observed_text for rule_id in rule_ids)
        or window_start.lower() not in observed_text
        or window_end.lower() not in observed_text
    ):
        failures.append(
            "AI observed facts do not cite the Wazuh alert count, rule IDs, and exact window"
        )
    finding_text_lower = finding_text.lower()
    if (
        not finding_text_lower
        or total not in finding_text_lower
        or any(rule_id.lower() not in finding_text_lower for rule_id in rule_ids)
        or window_start.lower() not in finding_text_lower
        or window_end.lower() not in finding_text_lower
    ):
        failures.append(
            "AI key findings do not cite the Wazuh alert count, rule IDs, and exact window"
        )
    evidence_anchors = [*rule_ids, window_start, window_end]
    for field in ("inferences", "uncertainties", "limitations"):
        values = basis.get(field) if isinstance(basis, dict) else None
        normalized_values = [
            _normalized_quality_text(item)
            for item in values or [] if isinstance(item, str) and item.strip()
        ]
        if not normalized_values or all(value in _GENERIC_BASIS_PHRASES for value in normalized_values):
            failures.append(f"AI {field} are empty or generic")
        elif not any(
            any(anchor.lower() in value for anchor in evidence_anchors)
            for value in normalized_values
        ):
            failures.append(f"AI {field} do not cite a Wazuh rule ID or exact window")
    observed_mitre = set(evidence["observed_mitre_ids"])
    natural_values = [analysis.get("summary", ""), *analysis.get("key_findings", [])]
    for values in (basis or {}).values():
        if isinstance(values, list):
            natural_values.extend(values)
    mentioned_mitre = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", " ".join(
        value for value in natural_values if isinstance(value, str)
    )))
    output_mitre = {
        value for value in analysis.get("mitre", [])
        if isinstance(value, str) and value
    }
    if (mentioned_mitre | output_mitre) - observed_mitre:
        failures.append("AI report contains MITRE IDs not present in Wazuh evidence")
    return failures


def _sanitize_security_aggregate(aggregate: dict) -> dict:
    """Keep only aggregate evidence needed by the one-pass security-test prompt."""
    if not aggregate.get("security_test_correlation"):
        return aggregate
    for group in aggregate.get("groups", []):
        if not isinstance(group, dict):
            continue
        group["sample_log"] = ""
        group["syscheck_path"] = ""
        group["agent"] = "[fixed-victim]"
    for alert in aggregate.get("alerts", []):
        if isinstance(alert, dict):
            alert["agent"] = "[fixed-victim]"
    return aggregate


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
        self.delivery_wakeup_event = threading.Event()
        self.worker_thread = None
        self.scheduler_thread = None
        self.delivery_thread = None
        self.telegram_notifier = TelegramNotifier(cfg)
        self.gmail_notifier = GmailNotifier(cfg)
        self.store.recover_running_jobs()
        self.store.recover_sending_deliveries()

    def start(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, name="dashboard-worker", daemon=True)
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, name="dashboard-scheduler", daemon=True)
        self.delivery_thread = threading.Thread(
            target=self._delivery_loop, name="dashboard-delivery", daemon=True
        )
        self.worker_thread.start()
        self.scheduler_thread.start()
        self.delivery_thread.start()

    def stop(self, timeout=5):
        self.stop_event.set()
        self.wakeup_event.set()
        self.delivery_wakeup_event.set()
        for thread in (self.worker_thread, self.scheduler_thread, self.delivery_thread):
            if thread:
                thread.join(timeout)

    def notify(self):
        self.wakeup_event.set()
        self.delivery_wakeup_event.set()

    def notify_delivery(self):
        self.delivery_wakeup_event.set()

    def _worker_loop(self):
        while not self.stop_event.is_set():
            job = self.store.claim_next_job()
            if not job:
                self.wakeup_event.wait(self.poll_seconds)
                self.wakeup_event.clear()
                continue
            self._run_job(job)

    def _delivery_loop(self):
        while not self.stop_event.is_set():
            delivery = self.store.claim_next_delivery()
            if not delivery:
                self.delivery_wakeup_event.wait(self.poll_seconds)
                self.delivery_wakeup_event.clear()
                continue
            try:
                self._run_delivery(delivery)
            except Exception:
                # Keep the independent delivery worker alive if the audit row is
                # removed or a persistence error occurs while recording a result.
                LOGGER.error("Report delivery worker could not finalize delivery %s", delivery["id"])
                try:
                    # A send may already have reached Telegram, so never turn an
                    # unrecorded outcome into an automatic retry.
                    self.store.mark_delivery_problem(
                        delivery["id"], status="uncertain", error_code="finalization_error"
                    )
                except Exception:
                    pass

    def _notifier_for_channel(self, channel):
        if channel == TELEGRAM_CHANNEL:
            return self.telegram_notifier
        if channel == GMAIL_CHANNEL:
            return self.gmail_notifier
        return None

    def _run_delivery(self, delivery):
        job = self.store.get_job_detail(delivery["job_id"])
        if not job or job.get("status") not in {"succeeded", "partial"}:
            self.store.mark_delivery_problem(
                delivery["id"], status="failed", error_code="job_not_terminal"
            )
            return
        notifier = self._notifier_for_channel(delivery.get("channel"))
        if notifier is None:
            self.store.mark_delivery_problem(
                delivery["id"], status="failed", error_code="unsupported_channel"
            )
            return
        try:
            result = notifier.send_report(job)
        except (TelegramDeliveryError, GmailDeliveryError) as exc:
            stage = "smtp" if delivery.get("channel") == GMAIL_CHANNEL else "none"
            # Telegram reports are one sendDocument request containing both
            # caption and PDF. A transport ambiguity is safe to expose for an
            # explicit retry, but it is never replayed automatically.
            if delivery.get("channel") == TELEGRAM_CHANNEL:
                stage = "pdf"
            self.store.mark_delivery_problem(
                delivery["id"],
                status="uncertain" if exc.uncertain else "failed",
                error_code=exc.code,
                stage=stage,
            )
        except (TelegramConfigurationError, GmailConfigurationError):
            self.store.mark_delivery_problem(
                delivery["id"], status="failed", error_code="configuration"
            )
        except Exception:
            # Do not expose provider responses, credentials, or recipient data.
            LOGGER.error("Report delivery failed for job %s", delivery["job_id"])
            self.store.mark_delivery_problem(
                delivery["id"], status="failed", error_code="unexpected_error"
            )
        else:
            self.store.mark_delivery_sent(
                delivery["id"],
                payload_sha256=result["payload_sha256"],
                provider_message_id=result.get("message_id", ""),
            )

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
                **({
                    "source_ip": job["correlation"]["source_ip"],
                    "agent_ip": job["correlation"]["agent_ip"],
                    "expected_rule_ids": job["correlation"]["expected_rule_ids"],
                } if job.get("correlation") else {}),
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
            if job.get("correlation"):
                aggregate["security_test_correlation"] = dict(job["correlation"])
                aggregate["security_test_correlation"].update({
                    "window_start": job["window_start"],
                    "window_end": job["window_end"],
                })
                aggregate = _sanitize_security_aggregate(aggregate)
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
            analysis_kwargs = {}
            if job.get("llm_parameters"):
                analysis_kwargs["llm_parameters"] = job["llm_parameters"]
            timeout_seconds = (job.get("correlation") or {}).get("analysis_timeout_seconds")
            if timeout_seconds is not None:
                analysis_kwargs["timeout_seconds"] = timeout_seconds
            result = self.analysis_service.analyze_aggregate(
                aggregate, job["model"], job.get("language", "vi"), **analysis_kwargs,
            )
            latency = time.perf_counter() - started
            # An in-flight Ollama request cannot be forcibly stopped, but a cancel
            # received while it ran must not create a successful saved result.
            if self.store.get_job(job["id"])["cancel_requested"]:
                self.store.complete_job(job["id"], "cancelled")
                return
            self.store.update_phase(job["id"], "saving_result")
            warnings = ["Prompt coverage bị rút gọn"] if result["coverage"]["truncated"] else []
            if aggregate.get("analysis_mode") == "aggregate":
                warnings.append(
                    f"Aggregate-only: {aggregate['total_alerts']} alert vượt detail cap; không tải full log"
                )
            if result["coverage"].get("unique_counts_approximate"):
                warnings.append(
                    "Unique rule/agent/source-IP counts are approximate OpenSearch cardinalities"
                )
            if result["analysis"]["severity"] == "unknown":
                warnings.append("LLM trả fallback/unknown")
            quality_failures = _security_analysis_quality(aggregate, result["analysis"])
            warnings.extend(quality_failures)
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
            status = "partial" if (
                result["partial"] or language_compliance != "full" or quality_failures
            ) else "succeeded"
            chain = self._attack_chain_result(job)
            if chain:
                warnings.extend(chain["warnings"])
                if chain["status"] == "partial":
                    status = "partial"
            saved = self.store.save_result_and_complete_if_not_cancelled(
                job["id"], "window", "window", result["analysis"],
                coverage=result["coverage"], warnings=warnings,
                provenance=provenance, latency_s=latency, status=status,
                progress_current=aggregate["total_alerts"],
                progress_total=aggregate["total_alerts"],
                extra_results=[chain["row"]] if chain else None,
            )
            if not saved:
                current = self.store.get_job(job["id"])
                if current and current["cancel_requested"]:
                    self.store.complete_job(job["id"], "cancelled")
                    return
                raise RuntimeError("Job không thể hoàn tất vì trạng thái đã thay đổi")
            delivery_channel = job.get("delivery_channel", "none")
            if delivery_channel != "none":
                try:
                    self.store.enqueue_delivery(job["id"], delivery_channel)
                    self.notify_delivery()
                except Exception:
                    # Analysis success is independent from outbound delivery;
                    # a durable queue error must not rewrite the AI result.
                    LOGGER.error("Could not enqueue report delivery for job %s", job["id"])
            self._advance_schedule_for_job(job)
        except Exception as exc:
            current = self.store.get_job(job["id"])
            if current and current["cancel_requested"]:
                self.store.complete_job(job["id"], "cancelled")
                return
            # ponytail: retry thủ công ở MVP; thêm transient classifier/backoff khi live test có lỗi cụ thể.
            error = (
                f"Security analysis failed: {type(exc).__name__}"
                if job.get("correlation") else f"{type(exc).__name__}: {exc}"
            )
            self.store.complete_job(job["id"], "failed", error=error)
            if job["job_type"] == "scheduled_window":
                self.store.block_schedule(f"{type(exc).__name__}: {exc}")

    def _attack_chain_result(self, job):
        """Analyse the busiest source IP of the same window as part of this job.

        The chain profile is a second result row on the same job, so one queued
        analysis always yields one report instead of a detached follow-up job."""
        if not job.get("attack_chain"):
            return None
        seconds = int(job.get("attack_chain_seconds") or 0)
        if seconds in PRESET_SECONDS:
            window_end = parse_utc(job["window_end"])
            chain_start = format_utc(window_end - timedelta(seconds=seconds))
            chain_end = format_utc(window_end)
        else:
            chain_start, chain_end = job["window_start"], job["window_end"]
        try:
            self.store.update_phase(job["id"], "analyzing_attack_chain")
            active = fetch_active_source_ips(self.cfg, chain_start, chain_end, limit=1)
            if not active:
                return {
                    "row": None, "status": "succeeded",
                    "warnings": ["Attack chain: khong co source IP trong cua so da chon"],
                }
            source_ip = active[0]["ip"]
            dashboard_cfg = self.cfg.get("dashboard", {})
            fetched = fetch_alerts_window(
                self.cfg, chain_start, chain_end, source_ip=source_ip,
                max_alerts=dashboard_cfg.get("max_alerts_per_job", 2000),
                max_rule_buckets=dashboard_cfg.get("max_aggregate_rule_buckets", 1000),
                max_timeline_buckets=dashboard_cfg.get("max_timeline_buckets", 96),
            )
            if fetched.get("analysis_mode", "full") == "aggregate":
                aggregate = aggregate_rule_buckets(fetched)
            else:
                aggregate = aggregate_alerts(
                    fetched["alerts"],
                    sample_log_chars=dashboard_cfg.get("max_sample_log_chars", 1000),
                )
                aggregate["timeline"] = fetched.get("timeline", [])
            if not aggregate["total_alerts"]:
                return {
                    "row": None, "status": "succeeded",
                    "warnings": [f"Attack chain: khong co alert cho {source_ip}"],
                }
            analysis_kwargs = {}
            if job.get("llm_parameters"):
                analysis_kwargs["llm_parameters"] = job["llm_parameters"]
            started = time.perf_counter()
            result = self.analysis_service.analyze_ip_profile_aggregate(
                aggregate=aggregate, source_ip=source_ip, model=job["model"],
                language=job.get("language", "vi"), **analysis_kwargs,
            )
            latency = time.perf_counter() - started
            analysis = result["analysis"]
            warnings = list(result.get("warnings") or [])
            warnings.append(f"Attack chain profile for source IP {source_ip}")
            provenance = dict(result.get("provenance") or {})
            provenance["attack_chain_source_ip"] = source_ip
            provenance["attack_chain_window"] = f"{chain_start}..{chain_end}"
            degraded = analysis.get("severity") == "unknown"
            return {
                "row": {
                    "scope": "window", "scope_key": "attack_chain", "result": analysis,
                    "coverage": result["coverage"], "warnings": warnings,
                    "provenance": provenance, "latency_s": latency,
                },
                "status": "partial" if degraded else "succeeded",
                # A successful chain profile is not a quality problem, so it must not
                # raise the window report's quality-gate banner.
                "warnings": [
                    f"Attack chain cho {source_ip} tra fallback/unknown"
                ] if degraded else [],
            }
        except Exception as exc:
            # The window report is the primary deliverable; a chain failure is
            # reported as a warning instead of discarding the window analysis.
            LOGGER.error("Attack-chain analysis failed for job %s", job["id"])
            return {
                "row": None, "status": "partial",
                "warnings": [f"Attack chain that bai: {type(exc).__name__}"],
            }

    def _advance_schedule_for_job(self, job):
        if job["job_type"] != "scheduled_window":
            return
        schedule = self.store.get_schedule(include_llm_parameters=True)
        if schedule["generation"] != job["schedule_generation"]:
            return
        self.store.advance_schedule(job["window_end"])

    def _scheduler_loop(self):
        while not self.stop_event.wait(self.poll_seconds):
            schedule = self.store.get_schedule(include_llm_parameters=True)
            now = datetime.now(timezone.utc)
            windows, overflow = due_windows(schedule, now)
            if overflow:
                interval = timedelta(seconds=schedule["interval_seconds"])
                first_kept = parse_utc(windows[0][0]) if windows else parse_utc(schedule["next_window_start"]) + interval * overflow
                self.store.advance_schedule(format_utc(first_kept), gap_windows=overflow)
                schedule = self.store.get_schedule(include_llm_parameters=True)
            if not windows:
                continue
            start, end = windows[0]
            try:
                self.store.create_job(
                    "scheduled_window", start, end, schedule["model"], ANALYSIS_VERSION,
                    language=schedule.get("language", "vi"),
                    delivery_channel=schedule.get("delivery_channel", "none"),
                    llm_parameters=schedule.get("llm_parameters"),
                    attack_chain=bool(schedule.get("attack_chain")),
                    schedule_generation=schedule["generation"],
                )
            except Exception as exc:
                # Duplicate means job already exists; any other persistent error blocks schedule visibly.
                if "UNIQUE constraint failed" not in str(exc):
                    self.store.block_schedule(f"{type(exc).__name__}: {exc}")
            self.notify()
