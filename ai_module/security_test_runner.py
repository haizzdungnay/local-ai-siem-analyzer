"""Bounded remote runners for the isolated DVWA/Wazuh test lab.

The browser can select only a catalog scenario. It never supplies a target,
command, script path, credentials, or payload to subprocess.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from dashboard_time import format_utc, parse_utc
from reader import fetch_alerts_window


LAB_ATTACKER_IP = "192.168.100.30"
LAB_VICTIM_IP = "192.168.100.20"
LAB_ATTACKER_USER = "kali"
MAX_OUTPUT_CHARS = 6000
MAX_RUN_HISTORY = 50
# Keep every browser-triggered lab action short and predictable.  This is a
# source-level cap; the browser cannot increase it through the API.
MAX_SCENARIO_TIMEOUT_SECONDS = 20
MAX_SSH_CONNECT_TIMEOUT_SECONDS = 5
MAX_SCRIPT_PREVIEW_CHARS = 6000
MAX_INGEST_WAIT_SECONDS = 15
MAX_INDEXER_TIMEOUT_SECONDS = 5
MAX_ANALYSIS_TIMEOUT_SECONDS = 45
ANALYSIS_WINDOW_BEFORE_SECONDS = 30
ANALYSIS_WINDOW_AFTER_SECONDS = 10
REPO_ROOT = Path(__file__).resolve().parents[1]
ATTACK_SCRIPTS_DIR = REPO_ROOT / "scripts" / "attacks"
_END_UTC_RE = re.compile(
    r"(?m)^SCENARIO=(?P<scenario>[a-z0-9-]{1,64})\s+"
    r"TARGET=(?P<target>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"END_UTC=(?P<end_utc>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*$"
)


class SecurityTestBusyError(RuntimeError):
    """Raised when another bounded lab scenario is already executing."""


class SecurityTestConfigurationError(ValueError):
    """Raised when the local-only runner configuration is incomplete or unsafe."""


def _scenario(identifier, title, category, description, script, arguments, timeout_seconds=MAX_SCENARIO_TIMEOUT_SECONDS):
    timeout_seconds = min(int(timeout_seconds), MAX_SCENARIO_TIMEOUT_SECONDS)
    return {
        "id": identifier,
        "title": title,
        "category": category,
        "description": description,
        "script": script,
        "arguments": tuple(arguments),
        "timeout_seconds": timeout_seconds,
    }


# Every item is fixed in source. The UI receives the display fields only.
SCENARIOS = {
    item["id"]: item
    for item in (
        _scenario(
            "brute-force", "Brute Force (DVWA login)", "DVWA authentication",
            "Sends 300 fixed invalid-credential POSTs in bounded batches to the fixed DVWA login endpoint.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "brute-force"),
        ),
        _scenario(
            "command-injection", "Command Injection", "DVWA input validation",
            "Sends one fixed command-injection-shaped request to the DVWA lab.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "command-injection"),
        ),
        _scenario(
            "csrf", "CSRF", "DVWA browser/web",
            "Sends one bounded CSRF-shaped request using only lab values.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "csrf"),
        ),
        _scenario(
            "file-inclusion", "File Inclusion", "DVWA input validation",
            "Sends one traversal-shaped request; it never requests a system file.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "file-inclusion"),
        ),
        _scenario(
            "file-upload", "File Upload", "DVWA file handling",
            "Uploads a harmless temporary marker file to the lab endpoint.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "file-upload"),
        ),
        _scenario(
            "insecure-captcha", "Insecure CAPTCHA", "DVWA browser/web",
            "Sends one fixed CAPTCHA validation test request.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "insecure-captcha"),
        ),
        _scenario(
            "sql-injection", "SQL Injection", "DVWA input validation",
            "Sends one fixed SQL injection-shaped query to DVWA.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "sql-injection"),
        ),
        _scenario(
            "sql-injection-blind", "SQL Injection (Blind)", "DVWA input validation",
            "Sends one fixed blind SQL injection-shaped query to DVWA.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "sql-injection-blind"),
        ),
        _scenario(
            "weak-session-ids", "Weak Session IDs", "DVWA session",
            "Sends a bounded weak-session test request; no user session is collected.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "weak-session-ids"),
        ),
        _scenario(
            "xss-dom", "XSS (DOM)", "DVWA browser/web",
            "Sends one fixed DOM XSS-shaped request to the lab endpoint.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "xss-dom"),
        ),
        _scenario(
            "xss-reflected", "XSS (Reflected)", "DVWA input validation",
            "Sends one fixed reflected XSS-shaped query to DVWA.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "xss-reflected"),
        ),
        _scenario(
            "xss-stored", "XSS (Stored)", "DVWA browser/web",
            "Posts a harmless marker to the DVWA lab endpoint.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "xss-stored"),
        ),
        _scenario(
            "csp-bypass", "CSP Bypass", "DVWA browser/web",
            "Sends one fixed CSP test request to the DVWA lab endpoint.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "csp-bypass"),
        ),
        _scenario(
            "javascript-attacks", "JavaScript Attacks", "DVWA browser/web",
            "Sends one fixed client-side validation test request.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "javascript-attacks"),
        ),
        _scenario(
            "authorisation-bypass", "Authorisation Bypass", "DVWA access control",
            "Sends one fixed access-control test request with lab-only identifiers.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "authorisation-bypass"),
        ),
        _scenario(
            "open-http-redirect", "Open HTTP Redirect", "DVWA redirect",
            "Sends one redirect test whose destination remains inside the lab.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "open-http-redirect"),
        ),
        _scenario(
            "cryptography", "Cryptography", "DVWA crypto",
            "Sends one fixed weak-crypto test request to the DVWA lab endpoint.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "cryptography"),
        ),
        _scenario(
            "api", "API", "DVWA API",
            "Sends a bounded API test request using a fake object identifier.",
            "dvwa-module-test.sh", (LAB_VICTIM_IP, "api"),
        ),
    )
}

# Only these scenarios have a verified Wazuh telemetry contract in this lab.
# The remaining catalog entries stay visible but cannot consume traffic or AI
# tokens until their own evidence contract is validated.
TELEMETRY_CONTRACTS = {
    "brute-force": ("100121",),
    "file-inclusion": ("31104",),
    "xss-reflected": ("31105",),
    "api": ("31101",),
}


def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_output(value: str) -> str:
    value = re.sub(
        r"(?i)\b(password|passwd|token|secret|authorization|cookie)\b\s*([=:])\s*[^,\s;]+",
        r"\1\2[redacted]",
        value,
    )
    value = "".join(character for character in value if character in "\n\r\t" or ord(character) >= 32)
    return value[-MAX_OUTPUT_CHARS:]


def _safe_error(value) -> str:
    """Return a stable browser-safe failure message without local paths or URLs."""
    message = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    message = re.sub(r"[A-Za-z]:[\\/][^\s]+|/[A-Za-z0-9_./:-]+", "[redacted]", message)
    message = _safe_output(message)
    return message[:300] or "Security-test follow-up failed."


def _parse_attack_end_utc(output: str, *, expected_scenario: str, expected_target: str) -> datetime:
    matches = list(_END_UTC_RE.finditer(output or ""))
    if len(matches) != 1:
        raise ValueError("The approved script did not return one valid END_UTC marker.")
    marker = matches[0]
    if (
        marker.group("scenario") != expected_scenario
        or marker.group("target") != expected_target
    ):
        raise ValueError("The approved script returned an unexpected correlation marker.")
    return parse_utc(marker.group("end_utc"), "END_UTC")


def _terminal_command(scenario: dict, port: int, connect_timeout: int) -> str:
    """Render the fixed SSH invocation without exposing the local key path."""
    remote_args = " ".join(scenario["arguments"])
    return (
        f"ssh -o BatchMode=yes -o ConnectTimeout={connect_timeout} "
        f"-i [local-ssh-key-hidden] -p {port} "
        f'{LAB_ATTACKER_USER}@{LAB_ATTACKER_IP} "bash -s -- {remote_args}"'
    )


def _script_preview(scenario: dict) -> str:
    """Return a bounded, redacted preview of the approved script sent to Kali."""
    script_path = ATTACK_SCRIPTS_DIR / scenario["script"]
    try:
        source = script_path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    except OSError:
        return "Approved script preview is unavailable."
    preview = source.decode("utf-8", errors="replace")[:MAX_SCRIPT_PREVIEW_CHARS]
    if len(source) > MAX_SCRIPT_PREVIEW_CHARS:
        preview += "\n# [preview truncated]"
    return _safe_output(preview)


class SecurityTestRunner:
    """One-at-a-time SSH executor for fixed scripts in the isolated lab."""

    def __init__(
        self, cfg: dict, *, store=None, runtime=None,
        analysis_version="security-test-v1", model_provider=None,
    ):
        self.root_cfg = cfg
        self.cfg = dict(cfg.get("security_tests") or {})
        self.store = store
        self.runtime = runtime
        self.analysis_version = analysis_version
        self.model_provider = model_provider
        self._lock = threading.Lock()
        self._runs: dict[str, dict] = {}
        self._active_run_id: str | None = None

    def _configuration_error(self) -> str | None:
        if self.cfg.get("enabled") is not True:
            return "Security test runner is disabled in local config."
        if self.cfg.get("attacker_host") != LAB_ATTACKER_IP:
            return "Security test runner requires the fixed Kali lab address."
        if self.cfg.get("victim_host") != LAB_VICTIM_IP:
            return "Security test runner requires the fixed DVWA Victim address."
        if self.cfg.get("attacker_user", LAB_ATTACKER_USER) != LAB_ATTACKER_USER:
            return "Security test runner requires the fixed Kali lab user."
        identity = self.cfg.get("ssh_identity_path")
        if not isinstance(identity, str) or not identity.strip():
            return "A local SSH identity file is required before tests can run."
        identity_path = Path(identity)
        if identity_path.name == "id_ed25519" and identity_path.parent.name == ".ssh":
            identity_path = Path.home() / ".ssh" / "id_ed25519"
        if not identity_path.is_file():
            return "A local SSH identity file is required before tests can run."
        port = self.cfg.get("ssh_port", 22)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return "Security test SSH port is invalid."
        connect_timeout = self.cfg.get("connect_timeout_seconds", MAX_SSH_CONNECT_TIMEOUT_SECONDS)
        if (
            isinstance(connect_timeout, bool)
            or not isinstance(connect_timeout, int)
            or not 1 <= connect_timeout <= MAX_SSH_CONNECT_TIMEOUT_SECONDS
        ):
            return "Security test SSH connection timeout is invalid."
        if shutil.which("ssh") is None:
            return "OpenSSH client is unavailable on this host."
        if self.store is not None and self.runtime is None:
            return "Security test analysis coordinator is unavailable."
        default_model = self.cfg.get("analysis_model")
        allowed_models = self.cfg.get("allowed_analysis_models") or [default_model]
        if (
            not isinstance(default_model, str) or not default_model
            or not isinstance(allowed_models, list) or not allowed_models
            or default_model not in allowed_models
            or not all(isinstance(model, str) and model for model in allowed_models)
        ):
            return "Security test AI model allowlist is invalid."
        return None

    def _resolve_analysis_model(self, model: str) -> str:
        selected = model
        allowed = self.cfg.get("allowed_analysis_models") or [self.cfg.get("analysis_model")]
        if not isinstance(selected, str) or not selected or selected not in allowed:
            raise SecurityTestConfigurationError(
                "Selected AI model is not allowed for security tests."
            )
        if selected not in self._available_analysis_models():
            raise SecurityTestConfigurationError(
                "Selected AI model is not installed or available in local Ollama."
            )
        return selected

    def _available_analysis_models(self) -> list[str]:
        configured = list(
            self.cfg.get("allowed_analysis_models") or [self.cfg.get("analysis_model")]
        )
        if self.model_provider is None:
            return configured
        try:
            installed = self.model_provider()
        except Exception as exc:
            raise SecurityTestConfigurationError(
                "Local Ollama model preflight is unavailable."
            ) from exc
        if not isinstance(installed, (list, tuple, set)):
            raise SecurityTestConfigurationError("Local Ollama model preflight is invalid.")
        installed_names = {item for item in installed if isinstance(item, str)}
        return [model for model in configured if model in installed_names]

    def catalog(self) -> dict:
        error = self._configuration_error()
        default_model = self.cfg.get("analysis_model", "")
        if error:
            allowed_models = list(
                self.cfg.get("allowed_analysis_models") or ([default_model] if default_model else [])
            )
        else:
            try:
                allowed_models = self._available_analysis_models()
            except SecurityTestConfigurationError as exc:
                allowed_models = []
                error = str(exc)
            if not allowed_models and not error:
                error = "No allowed security-test AI model is installed in local Ollama."
        with self._lock:
            active = self._public_run(self._runs.get(self._active_run_id)) if self._active_run_id else None
        scenarios = []
        for scenario in SCENARIOS.values():
            contract = TELEMETRY_CONTRACTS.get(scenario["id"])
            disabled_reason = error or (
                "Another test is already running." if active else (
                    "Telemetry contract has not been verified for this scenario."
                    if contract is None else ""
                )
            )
            scenarios.append({
                "id": scenario["id"],
                "title": scenario["title"],
                "category": scenario["category"],
                "description": scenario["description"],
                "timeout_seconds": scenario["timeout_seconds"],
                "expected_rule_ids": list(contract or ()),
                "enabled": error is None and active is None and contract is not None,
                "disabled_reason": disabled_reason,
            })
        return {
            "enabled": error is None,
            "reason": error or "",
            "source_ip": LAB_ATTACKER_IP,
            "target_ip": LAB_VICTIM_IP,
            "default_model": default_model,
            "allowed_models": allowed_models,
            "active_run": active,
            "scenarios": scenarios,
        }

    def start(self, scenario_id: str, *, model: str | None = None) -> dict:
        if scenario_id not in SCENARIOS:
            raise SecurityTestConfigurationError("Unknown security test scenario.")
        if scenario_id not in TELEMETRY_CONTRACTS:
            raise SecurityTestConfigurationError(
                "This scenario needs a verified Wazuh telemetry contract before it can run."
            )
        error = self._configuration_error()
        if error:
            raise SecurityTestConfigurationError(error)
        analysis_model = self._resolve_analysis_model(
            self.cfg.get("analysis_model") if model is None else model
        )
        with self._lock:
            if self._active_run_id:
                raise SecurityTestBusyError("Another security test is already running.")
            scenario = SCENARIOS[scenario_id]
            port = self.cfg.get("ssh_port", 22)
            connect_timeout = self.cfg.get("connect_timeout_seconds", MAX_SSH_CONNECT_TIMEOUT_SECONDS)
            run_id = uuid.uuid4().hex
            run = {
                "id": run_id,
                "scenario_id": scenario_id,
                "title": scenario["title"],
                "analysis_model": analysis_model,
                "status": "queued",
                "phase": "queued",
                "started_at": None,
                "finished_at": None,
                "exit_code": None,
                "output": "",
                "error": "",
                "attack_end_utc": None,
                "analysis_window_start": None,
                "analysis_window_end": None,
                "wazuh_alert_count": None,
                "wazuh_rule_ids": [],
                "ai_job_id": None,
                "ai_status": "",
                "ai_severity": "",
                "ai_summary": "",
                "ai_error": "",
                "verdict": "",
                "source_ip": LAB_ATTACKER_IP,
                "target_ip": LAB_VICTIM_IP,
                "terminal_command": _terminal_command(scenario, port, connect_timeout),
                "script_preview": _script_preview(scenario),
            }
            self._runs[run_id] = run
            self._active_run_id = run_id
            threading.Thread(target=self._run, args=(run_id,), name="security-test-runner", daemon=True).start()
            return self._public_run(run)

    def get_run(self, run_id: str) -> dict | None:
        with self._lock:
            return self._public_run(self._runs.get(run_id))

    def _run(self, run_id: str) -> None:
        with self._lock:
            run = self._runs[run_id]
            run["status"] = "running"
            run["phase"] = "running_script"
            run["started_at"] = _utc_now()
            scenario = SCENARIOS[run["scenario_id"]]
        try:
            completed = self._execute(scenario)
            output = _safe_output(_completed_output(completed.stdout, completed.stderr))
            with self._lock:
                run["exit_code"] = completed.returncode
                run["output"] = output
            if completed.returncode != 0:
                self._script_failed(run, "The approved script returned a non-zero exit code.")
                return
            if self.store is None:
                # Direct runner users have no local Wazuh/AI coordinator. Keep
                # this compatibility mode script-only; the Flask app never uses it.
                with self._lock:
                    run["status"] = "succeeded"
                    run["phase"] = "completed"
                return
            try:
                attack_end = _parse_attack_end_utc(
                    output,
                    expected_scenario=run["scenario_id"],
                    expected_target=LAB_VICTIM_IP,
                )
            except ValueError as exc:
                self._script_failed(run, str(exc))
                return
            self._correlate_and_queue(run, attack_end)
        except subprocess.TimeoutExpired as exc:
            output = _completed_output(exc.stdout, exc.stderr)
            with self._lock:
                run["status"] = "failed"
                run["phase"] = "timed_out"
                run["verdict"] = "script_failed"
                run["error"] = "The bounded script exceeded its time limit."
                run["output"] = _safe_output(output)
        except (OSError, SecurityTestConfigurationError) as exc:
            self._script_failed(run, _safe_error(exc))
        except Exception as exc:
            # Persistence/runtime failures must still terminate the in-memory run
            # without exposing database paths, Indexer URLs, or traceback text.
            with self._lock:
                run["status"] = "failed"
                run["phase"] = "analysis_failed"
                run["verdict"] = "analysis_failed"
                run["error"] = "Security-test correlation or AI coordination failed."
                run["ai_error"] = _safe_error(type(exc).__name__)
        finally:
            with self._lock:
                if not run["finished_at"]:
                    run["finished_at"] = _utc_now()
                if self._active_run_id == run_id:
                    self._active_run_id = None
                if len(self._runs) > MAX_RUN_HISTORY:
                    oldest = next(iter(self._runs))
                    if oldest != self._active_run_id:
                        self._runs.pop(oldest, None)

    def _script_failed(self, run: dict, message: str) -> None:
        with self._lock:
            run["status"] = "failed"
            run["phase"] = "failed"
            run["verdict"] = "script_failed"
            run["error"] = _safe_error(message)

    def _correlate_and_queue(self, run: dict, attack_end: datetime) -> None:
        """Poll the fixed Indexer filter once per bounded interval; never replay traffic."""
        now = datetime.now(timezone.utc)
        # The lab clock may lag this host, but a remote timestamp too far ahead
        # cannot define a trustworthy historical window.
        if attack_end > now + timedelta(seconds=ANALYSIS_WINDOW_BEFORE_SECONDS):
            self._script_failed(run, "Remote END_UTC is too far in the future for safe correlation.")
            return
        end = min(attack_end + timedelta(seconds=ANALYSIS_WINDOW_AFTER_SECONDS), now)
        start = attack_end - timedelta(seconds=ANALYSIS_WINDOW_BEFORE_SECONDS)
        if end <= start:
            self._script_failed(run, "Remote END_UTC is outside the safe correlation window.")
            return
        with self._lock:
            run["attack_end_utc"] = format_utc(attack_end)
            run["analysis_window_start"] = format_utc(start)
            run["analysis_window_end"] = format_utc(end)
            run["status"] = "running"
            run["phase"] = "waiting_ingest"
        deadline = time.monotonic() + min(
            int(self.cfg.get("ingest_wait_seconds", MAX_INGEST_WAIT_SECONDS)),
            MAX_INGEST_WAIT_SECONDS,
        )
        poll_seconds = int(self.cfg.get("ingest_poll_seconds", 2))
        expected_rule_ids = TELEMETRY_CONTRACTS[run["scenario_id"]]
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with self._lock:
                    run["status"] = "succeeded"
                    run["phase"] = "no_alert"
                    run["verdict"] = "no_matching_alert"
                    run["wazuh_alert_count"] = 0
                    run["finished_at"] = _utc_now()
                return
            with self._lock:
                run["phase"] = "querying_wazuh"
            try:
                fetched = self._fetch_evidence(
                    start, end, expected_rule_ids,
                    request_timeout_seconds=min(
                        float(self.cfg.get("indexer_timeout_seconds", MAX_INDEXER_TIMEOUT_SECONDS)),
                        remaining,
                    ),
                )
            except (requests.RequestException, ValueError) as exc:
                with self._lock:
                    run["status"] = "failed"
                    run["phase"] = "failed"
                    run["verdict"] = "analysis_failed"
                    run["error"] = "Could not query the bounded Wazuh correlation window."
                    run["ai_error"] = _safe_error(type(exc).__name__)
                return
            if fetched.get("total", 0):
                self._queue_ai_job(run, fetched)
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with self._lock:
                    run["status"] = "succeeded"
                    run["phase"] = "no_alert"
                    run["verdict"] = "no_matching_alert"
                    run["wazuh_alert_count"] = 0
                    run["finished_at"] = _utc_now()
                return
            with self._lock:
                run["phase"] = "waiting_ingest"
            time.sleep(min(poll_seconds, remaining))

    def _fetch_evidence(
        self, start: datetime, end: datetime, expected_rule_ids=None,
        *, request_timeout_seconds=None,
    ) -> dict:
        if self.store is None:
            return {"total": 0, "rule_buckets": []}
        cfg = dict(self.root_cfg)
        indexer = dict(cfg.get("wazuh_indexer") or {})
        configured_timeout = min(
            int(self.cfg.get("indexer_timeout_seconds", MAX_INDEXER_TIMEOUT_SECONDS)),
            MAX_INDEXER_TIMEOUT_SECONDS,
        )
        timeout = configured_timeout if request_timeout_seconds is None else min(
            configured_timeout, float(request_timeout_seconds),
        )
        if timeout <= 0:
            raise ValueError("Security-test Indexer timeout is exhausted.")
        indexer["timeout"] = timeout
        cfg["wazuh_indexer"] = indexer
        dashboard = cfg.get("dashboard") or {}
        return fetch_alerts_window(
            cfg, start, end,
            max_alerts=dashboard.get("max_alerts_per_job", 2000),
            max_rule_buckets=dashboard.get("max_aggregate_rule_buckets", 1000),
            max_timeline_buckets=dashboard.get("max_timeline_buckets", 96),
            now=datetime.now(timezone.utc),
            source_ip=LAB_ATTACKER_IP,
            agent_ip=LAB_VICTIM_IP,
            expected_rule_ids=list(expected_rule_ids or ()),
            summary_only=True,
        )

    def _queue_ai_job(self, run: dict, fetched: dict) -> None:
        rules = sorted({str(item.get("rule_id")) for item in fetched.get("rule_buckets", []) if item.get("rule_id")})
        if not rules:
            rules = sorted({str(hit.get("_source", {}).get("rule", {}).get("id")) for hit in fetched.get("alerts", []) if hit.get("_source", {}).get("rule", {}).get("id")})
        with self._lock:
            run["wazuh_alert_count"] = int(fetched.get("total", 0))
            run["wazuh_rule_ids"] = rules[:32]
            run["phase"] = "queued_ai"
        if self.store is None or self.runtime is None:
            with self._lock:
                run["status"] = "failed"
                run["phase"] = "analysis_failed"
                run["verdict"] = "analysis_failed"
                run["ai_error"] = "AI job coordinator is unavailable."
            return
        job_id = self.store.create_job(
            "manual_window", run["analysis_window_start"], run["analysis_window_end"],
            run["analysis_model"], self.analysis_version,
            language="vi", delivery_channel="none",
            llm_parameters={
                "temperature": 0.0, "top_p": 1.0,
                "max_tokens": int(self.cfg.get("analysis_max_tokens", 512)),
                "system_prompt": "",
            },
            correlation={
                "security_test_run_id": run["id"],
                "scenario_id": run["scenario_id"],
                "source_ip": LAB_ATTACKER_IP,
                "agent_ip": LAB_VICTIM_IP,
                "expected_rule_ids": list(TELEMETRY_CONTRACTS[run["scenario_id"]]),
                "analysis_timeout_seconds": min(
                    int(self.cfg.get("analysis_timeout_seconds", MAX_ANALYSIS_TIMEOUT_SECONDS)),
                    MAX_ANALYSIS_TIMEOUT_SECONDS,
                ),
            },
        )
        with self._lock:
            run["ai_job_id"] = job_id
            run["ai_status"] = "pending"
        self.runtime.notify()
        self._wait_for_ai_job(run, job_id)

    def _wait_for_ai_job(self, run: dict, job_id: int) -> None:
        configured_timeout = min(
            int(self.cfg.get("analysis_timeout_seconds", MAX_ANALYSIS_TIMEOUT_SECONDS)),
            MAX_ANALYSIS_TIMEOUT_SECONDS,
        )
        deadline = time.monotonic() + configured_timeout + 5
        while time.monotonic() < deadline:
            job = self.store.get_job_detail(job_id)
            if not job:
                break
            status = job.get("status", "")
            with self._lock:
                run["ai_status"] = status
                run["phase"] = "analyzing_ai" if status in {"pending", "running"} else run["phase"]
            if status in {"pending", "running"}:
                time.sleep(0.2)
                continue
            result = (job.get("results") or [{}])[-1].get("result", {}) if job.get("results") else {}
            with self._lock:
                run["ai_severity"] = str(result.get("severity") or "")
                run["ai_summary"] = _safe_output(str(result.get("summary") or ""))[:2000]
                if status in {"succeeded", "partial"}:
                    run["status"] = "succeeded"
                    run["phase"] = "completed" if status == "succeeded" else "analysis_failed"
                    run["verdict"] = "detected" if status == "succeeded" else "analysis_partial"
                    if status == "partial":
                        warnings = (job.get("results") or [{}])[-1].get("warnings", [])
                        run["ai_error"] = _safe_output(
                            "; ".join(str(item) for item in warnings if isinstance(item, str))
                            or "AI report did not meet the security-test evidence quality gate."
                        )[:1000]
                else:
                    run["status"] = "failed"
                    run["phase"] = "analysis_failed"
                    run["verdict"] = "analysis_failed"
                    run["ai_error"] = "AI analysis did not produce a valid report."
                run["finished_at"] = _utc_now()
            return
        with self._lock:
            try:
                current = self.store.get_job(job_id)
                if current and current.get("status") in {"pending", "running"}:
                    self.store.request_cancel(job_id)
            except Exception:
                pass
            run["status"] = "failed"
            run["phase"] = "analysis_failed"
            run["verdict"] = "analysis_failed"
            run["ai_status"] = "timeout"
            run["ai_error"] = "AI analysis exceeded its bounded time limit."
            run["finished_at"] = _utc_now()

    def _execute(self, scenario: dict) -> subprocess.CompletedProcess:
        identity = Path(self.cfg["ssh_identity_path"])
        if identity.name == "id_ed25519" and identity.parent.name == ".ssh":
            identity = Path.home() / ".ssh" / "id_ed25519"
        script_path = ATTACK_SCRIPTS_DIR / scenario["script"]
        if not script_path.is_file():
            raise SecurityTestConfigurationError("The approved scenario script is missing.")
        # Python text mode would preserve CRLF on Windows; normalize before
        # stdin reaches Bash on Kali so the bounded script cannot fail on `\r`.
        source = script_path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        port = self.cfg.get("ssh_port", 22)
        connect_timeout = self.cfg.get("connect_timeout_seconds", MAX_SSH_CONNECT_TIMEOUT_SECONDS)
        if (
            isinstance(connect_timeout, bool)
            or not isinstance(connect_timeout, int)
            or not 1 <= connect_timeout <= MAX_SSH_CONNECT_TIMEOUT_SECONDS
        ):
            raise SecurityTestConfigurationError("Security test SSH connection timeout is invalid.")
        command = [
            "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={connect_timeout}",
            "-i", str(identity), "-p", str(port),
            f"{LAB_ATTACKER_USER}@{LAB_ATTACKER_IP}",
            "bash -s -- " + " ".join(scenario["arguments"]),
        ]
        return subprocess.run(
            command,
            input=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=scenario["timeout_seconds"],
            check=False,
            shell=False,
            text=False,
        )

    @staticmethod
    def _public_run(run: dict | None) -> dict | None:
        if run is None:
            return None
        output = dict(run)
        # All fields are static/bounded; never return runner configuration or command arguments.
        return output


def _completed_output(stdout: bytes | str | None, stderr: bytes | str | None) -> str:
    """Decode bounded subprocess output without letting invalid bytes break a run."""
    def decode(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value or ""

    left, right = decode(stdout), decode(stderr)
    return left + ("\n" if left and right else "") + right
