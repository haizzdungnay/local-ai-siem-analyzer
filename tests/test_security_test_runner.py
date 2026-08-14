import threading
import time
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone

import security_test_runner as runner_module


def _runner_config(tmp_path, *, enabled=True):
    identity = tmp_path / "id_ed25519"
    identity.write_text("test key", encoding="utf-8")
    return {
        "security_tests": {
            "enabled": enabled,
            "attacker_host": "192.168.100.30",
            "attacker_user": "kali",
            "victim_host": "192.168.100.20",
            "ssh_identity_path": str(identity),
            "ssh_port": 22,
            "connect_timeout_seconds": 5,
            "analysis_model": "qwen2.5:7b",
            "allowed_analysis_models": ["qwen2.5:3b", "qwen2.5:7b"],
            "ingest_wait_seconds": 12,
            "ingest_poll_seconds": 1,
            "indexer_timeout_seconds": 5,
            "analysis_timeout_seconds": 45,
            "analysis_max_tokens": 512,
        }
    }


def test_catalog_has_exactly_the_requested_modules_and_hides_runner_details(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path, enabled=False))

    catalog = runner.catalog()

    assert len(catalog["scenarios"]) == 18
    assert {item["id"] for item in catalog["scenarios"]} >= {
        "brute-force", "sql-injection", "xss-reflected", "api",
    }
    assert catalog["enabled"] is False
    assert catalog["default_model"] == "qwen2.5:7b"
    assert catalog["allowed_models"] == ["qwen2.5:3b", "qwen2.5:7b"]
    assert {item["timeout_seconds"] for item in catalog["scenarios"]} == {20}
    assert all("script" not in item and "arguments" not in item for item in catalog["scenarios"])


def test_enabled_catalog_exposes_only_installed_allowed_models(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    thread_calls = []
    monkeypatch.setattr(
        runner_module.threading.Thread, "start", lambda thread: thread_calls.append(thread),
    )
    runner = runner_module.SecurityTestRunner(
        _runner_config(tmp_path), model_provider=lambda: ["qwen2.5:3b", "other:latest"],
    )

    catalog = runner.catalog()

    assert catalog["enabled"] is True
    assert catalog["allowed_models"] == ["qwen2.5:3b"]
    try:
        runner.start("file-inclusion", model="qwen2.5:7b")
    except runner_module.SecurityTestConfigurationError as exc:
        assert "not installed" in str(exc)
    else:
        raise AssertionError("unavailable model must be rejected before thread/SSH")
    assert thread_calls == []


def test_catalog_enables_only_verified_contracts_and_rejects_others_before_spawning(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    subprocess_calls = []
    monkeypatch.setattr(
        runner_module.subprocess, "run", lambda *args, **kwargs: subprocess_calls.append((args, kwargs)),
    )
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path))

    catalog = runner.catalog()
    assert {item["id"] for item in catalog["scenarios"] if item["enabled"]} == {
        "brute-force", "file-inclusion", "xss-reflected", "api",
    }
    brute_force = next(item for item in catalog["scenarios"] if item["id"] == "brute-force")
    assert brute_force["enabled"] is True
    assert brute_force["expected_rule_ids"] == ["100121"]

    try:
        runner.start("sql-injection")
    except runner_module.SecurityTestConfigurationError as exc:
        assert "verified Wazuh telemetry contract" in str(exc)
    else:
        raise AssertionError("unverified scenario must be rejected")
    assert subprocess_calls == []


def test_brute_force_script_keeps_300_bounded_fixed_login_posts_in_capped_batches():
    script = (Path(__file__).resolve().parents[1] / "scripts" / "attacks" / "dvwa-module-test.sh").read_text(
        encoding="utf-8"
    )
    block = script.split("  brute-force)\n", 1)[1].split("    ;;", 1)[0]

    assert "BRUTE_FORCE_ATTEMPTS=300" in script
    assert "BRUTE_FORCE_CONCURRENCY=25" in script
    assert "BRUTE_FORCE_REQUEST_TIMEOUT_SECONDS=1" in script
    assert "BRUTE_FORCE_BATCH_PAUSE_SECONDS=0.2" in script
    assert "for (( batch_start = 1; batch_start <= BRUTE_FORCE_ATTEMPTS; batch_start += BRUTE_FORCE_CONCURRENCY )); do" in block
    assert 'brute_force_batch "${batch_start}" "${batch_end}"' in block
    assert "for (( attempt = first_attempt; attempt <= last_attempt; attempt++ )); do" in script
    assert "pids+=(\"$!\")" in script
    assert 'if wait "${pid}"; then' in script
    assert "username=lab-invalid-user&password=lab-invalid-password&Login=Login" in script
    assert '"${BASE_URL}/login.php"' in script
    assert block.count('sleep "${BRUTE_FORCE_BATCH_PAUSE_SECONDS}"') == 1
    assert "if (( batch_end < BRUTE_FORCE_ATTEMPTS )); then" in block
    assert '--max-time "${BRUTE_FORCE_REQUEST_TIMEOUT_SECONDS}"' in script
    assert 'echo "BRUTE_FORCE_REQUESTS=${BRUTE_FORCE_ATTEMPTS}"' in block
    assert "BRUTE_FORCE_LAUNCHED=0" in script
    assert "BRUTE_FORCE_SUCCEEDED=0" in script
    assert "BRUTE_FORCE_INCOMPLETE launched=%s succeeded=%s failed=%s" in script
    assert "SCRIPT_DEADLINE_SECONDS=18" in script


def test_brute_force_spacing_stays_within_script_and_runner_time_bounds():
    """Twelve capped concurrent batches fit below script and runner deadlines."""
    script = (Path(__file__).resolve().parents[1] / "scripts" / "attacks" / "dvwa-module-test.sh").read_text(
        encoding="utf-8"
    )
    block = script.split("  brute-force)\n", 1)[1].split("    ;;", 1)[0]

    assert "BRUTE_FORCE_ATTEMPTS=300" in script
    assert "BRUTE_FORCE_CONCURRENCY=25" in script
    assert "BRUTE_FORCE_REQUEST_TIMEOUT_SECONDS=1" in script
    assert "BRUTE_FORCE_BATCH_PAUSE_SECONDS=0.2" in script
    assert "SCRIPT_DEADLINE_EXCEEDED=${SCRIPT_DEADLINE_SECONDS}" in script
    assert "SECONDS - SCRIPT_STARTED_SECONDS + BRUTE_FORCE_REQUEST_TIMEOUT_SECONDS >= SCRIPT_DEADLINE_SECONDS" in script
    assert 'sleep "${BRUTE_FORCE_BATCH_PAUSE_SECONDS}"' in block
    assert (300 // 25) * 1 + ((300 // 25) - 1) * 0.2 < 18
    assert runner_module.SCENARIOS["brute-force"]["timeout_seconds"] == 20


def test_brute_force_telemetry_contract_is_fail_closed_to_one_verified_rule():
    assert runner_module.TELEMETRY_CONTRACTS["brute-force"] == ("100121",)


def test_brute_force_matching_rule_is_the_only_correlation_that_queues_one_ai_job(tmp_path, monkeypatch):
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path), store=object(), runtime=object())
    observed_filters = []
    queued = []

    def fetch(_start, _end, expected_rule_ids, *, request_timeout_seconds=None):
        observed_filters.append((expected_rule_ids, request_timeout_seconds))
        return {"total": 1, "rule_buckets": [{"rule_id": "100121"}]}

    monkeypatch.setattr(runner, "_fetch_evidence", fetch)
    monkeypatch.setattr(runner, "_queue_ai_job", lambda run, fetched: queued.append((run, fetched)))
    run = {
        "id": "b" * 32, "scenario_id": "brute-force", "status": "running",
        "phase": "running_script", "analysis_window_start": None, "analysis_window_end": None,
        "finished_at": None,
    }

    runner._correlate_and_queue(run, datetime.now(timezone.utc))

    assert len(observed_filters) == 1
    assert observed_filters[0][0] == ("100121",)
    assert len(queued) == 1
    assert queued[0][1]["rule_buckets"] == [{"rule_id": "100121"}]


def test_brute_force_ai_job_persists_selected_model_and_exactly_one_expected_rule(tmp_path, monkeypatch):
    created = []

    class Store:
        def create_job(self, *args, **kwargs):
            created.append((args, kwargs))
            return 17

    class Runtime:
        def notify(self):
            return None

    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path), store=Store(), runtime=Runtime())
    monkeypatch.setattr(runner, "_wait_for_ai_job", lambda run, job_id: None)
    run = {
        "id": "c" * 32, "scenario_id": "brute-force", "analysis_window_start": "2026-07-30T11:00:00.000Z",
        "analysis_window_end": "2026-07-30T11:00:10.000Z", "status": "running", "phase": "querying_wazuh",
        "analysis_model": "qwen2.5:3b",
    }

    runner._queue_ai_job(run, {"total": 1, "rule_buckets": [{"rule_id": "100121"}]})

    assert len(created) == 1
    args, kwargs = created[0]
    assert args[3] == "qwen2.5:3b"
    assert kwargs["correlation"]["scenario_id"] == "brute-force"
    assert kwargs["correlation"]["expected_rule_ids"] == ["100121"]
    assert run["wazuh_rule_ids"] == ["100121"]


def test_runner_snapshots_allowed_model_and_rejects_unknown_before_spawning(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    thread_calls = []
    monkeypatch.setattr(
        runner_module.threading.Thread, "start", lambda thread: thread_calls.append(thread),
    )
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path))

    selected = runner.start("file-inclusion", model="qwen2.5:3b")

    assert selected["analysis_model"] == "qwen2.5:3b"
    assert len(thread_calls) == 1

    other_runner = runner_module.SecurityTestRunner(_runner_config(tmp_path))
    try:
        other_runner.start("file-inclusion", model="not-allowed:latest")
    except runner_module.SecurityTestConfigurationError as exc:
        assert "not allowed" in str(exc)
    else:
        raise AssertionError("unapproved model must be rejected before the runner thread starts")
    assert len(thread_calls) == 1


def test_selected_model_flows_from_start_snapshot_into_ai_job(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    created = []

    class Store:
        def create_job(self, *args, **kwargs):
            created.append((args, kwargs))
            return 29

    class Runtime:
        def notify(self):
            return None

    runner = runner_module.SecurityTestRunner(
        _runner_config(tmp_path), store=Store(), runtime=Runtime(),
    )
    monkeypatch.setattr(runner_module.threading.Thread, "start", lambda thread: None)
    monkeypatch.setattr(runner, "_wait_for_ai_job", lambda run, job_id: None)

    run = runner.start("file-inclusion", model="qwen2.5:3b")
    stored_run = runner._runs[run["id"]]
    stored_run.update(
        analysis_window_start="2026-07-30T11:00:00.000Z",
        analysis_window_end="2026-07-30T11:00:10.000Z",
    )
    runner._queue_ai_job(
        stored_run, {"total": 1, "rule_buckets": [{"rule_id": "31104"}]},
    )

    assert run["analysis_model"] == "qwen2.5:3b"
    assert len(created) == 1
    assert created[0][0][3] == "qwen2.5:3b"
    assert stored_run["ai_job_id"] == 29

def test_runner_uses_fixed_arguments_and_returns_bounded_output(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["input"] = kwargs["input"]
        seen["timeout"] = kwargs["timeout"]
        return SimpleNamespace(returncode=0, stdout=b"HTTP 302\n", stderr=b"")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path))
    run = runner.start("file-inclusion")
    for _ in range(20):
        time.sleep(0.01)
        run = runner.get_run(run["id"])
        if run["status"] != "running":
            break

    assert run["status"] == "succeeded"
    assert run["output"] == "HTTP 302\n"
    assert "192.168.100.20" in seen["command"][-1]
    assert b"file-inclusion" in seen["input"]
    assert b"\r\n" not in seen["input"]
    assert "ConnectTimeout=5" in seen["command"]
    assert seen["timeout"] == 20
    assert "bash -s -- 192.168.100.20 file-inclusion" in run["terminal_command"]
    assert "id_ed25519" not in run["terminal_command"]
    assert "#!/usr/bin/env bash" in run["script_preview"]


def test_runner_rejects_unknown_scenario_without_spawning(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path))

    try:
        runner.start("target=http://outside.invalid")
    except runner_module.SecurityTestConfigurationError:
        pass
    else:
        raise AssertionError("unknown scenario must be rejected")


def test_runner_uses_remote_end_marker_and_keeps_serial_lock_through_follow_up(tmp_path, monkeypatch):
    """The next script must wait until bounded Wazuh/AI follow-up is terminal."""
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    marker_seen = threading.Event()
    release_follow_up = threading.Event()
    received = {}

    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=b"HTTP 200\nSCENARIO=file-inclusion TARGET=192.168.100.20 END_UTC=2026-07-30T11:59:55Z\n",
            stderr=b"",
        )

    def follow_up(self, run, attack_end):
        received["attack_end"] = attack_end
        marker_seen.set()
        assert release_follow_up.wait(1)
        with self._lock:
            run.update(status="succeeded", phase="completed", verdict="detected")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    monkeypatch.setattr(runner_module.SecurityTestRunner, "_correlate_and_queue", follow_up)
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path), store=object(), runtime=object())

    run = runner.start("file-inclusion")
    assert marker_seen.wait(1)
    assert received["attack_end"].isoformat() == "2026-07-30T11:59:55+00:00"
    try:
        runner.start("xss-reflected")
    except runner_module.SecurityTestBusyError:
        pass
    else:
        raise AssertionError("follow-up must retain the serial runner lock")

    release_follow_up.set()
    for _ in range(100):
        terminal = runner.get_run(run["id"])
        if terminal["status"] != "running":
            break
        time.sleep(0.01)
    assert terminal["verdict"] == "detected"
    assert runner.catalog()["active_run"] is None


def test_remote_marker_must_match_fixed_scenario_and_target(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    follow_up_calls = []
    monkeypatch.setattr(
        runner_module.SecurityTestRunner, "_correlate_and_queue",
        lambda *args, **kwargs: follow_up_calls.append((args, kwargs)),
    )
    outputs = (
        b"SCENARIO=api TARGET=192.168.100.20 END_UTC=2026-07-30T11:59:55Z\n",
        b"SCENARIO=file-inclusion TARGET=192.168.100.99 END_UTC=2026-07-30T11:59:55Z\n",
    )
    for output in outputs:
        monkeypatch.setattr(
            runner_module.subprocess, "run",
            lambda *args, _output=output, **kwargs: SimpleNamespace(
                returncode=0, stdout=_output, stderr=b"",
            ),
        )
        runner = runner_module.SecurityTestRunner(
            _runner_config(tmp_path), store=object(), runtime=object(),
        )
        run = runner.start("file-inclusion")
        for _ in range(100):
            run = runner.get_run(run["id"])
            if run["phase"] in {"failed", "timed_out", "analysis_failed", "completed"}:
                break
            time.sleep(0.01)
        assert run["verdict"] == "script_failed"
        assert "unexpected correlation marker" in run["error"]
    assert follow_up_calls == []


def test_runner_never_follows_up_after_script_failure_or_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda value: "ssh")
    follow_up_calls = []

    def forbidden_follow_up(*args, **kwargs):
        follow_up_calls.append((args, kwargs))

    monkeypatch.setattr(runner_module.SecurityTestRunner, "_correlate_and_queue", forbidden_follow_up)
    monkeypatch.setattr(
        runner_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=9, stdout=b"END_UTC=2026-07-30T11:59:55Z", stderr=b""),
    )
    runner = runner_module.SecurityTestRunner(_runner_config(tmp_path), store=object(), runtime=object())
    failed = runner.start("file-inclusion")
    for _ in range(100):
        failed = runner.get_run(failed["id"])
        if failed["phase"] in {"failed", "timed_out", "analysis_failed", "completed"}:
            break
        time.sleep(0.01)
    assert failed["verdict"] == "script_failed"

    monkeypatch.setattr(
        runner_module.subprocess, "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            runner_module.subprocess.TimeoutExpired("ssh", 20, output=b"partial")
        ),
    )
    timed_out = runner.start("file-inclusion")
    for _ in range(100):
        timed_out = runner.get_run(timed_out["id"])
        if timed_out["phase"] in {"timed_out", "failed"}:
            break
        time.sleep(0.01)
    assert timed_out["phase"] == "timed_out"
    assert timed_out["verdict"] == "script_failed"
    assert follow_up_calls == []


def test_ingest_poll_uses_bounded_15_second_default_and_last_in_budget_read(tmp_path, monkeypatch):
    """Evidence on the last query started inside the budget queues AI exactly once."""
    cfg = _runner_config(tmp_path)
    cfg["security_tests"].pop("ingest_wait_seconds")
    cfg["security_tests"].pop("ingest_poll_seconds")
    runner = runner_module.SecurityTestRunner(cfg, store=object(), runtime=object())
    clock = {"value": 0.0}
    fetches = []
    queued = []
    sleeps = []

    def monotonic():
        return clock["value"]

    def sleep(seconds):
        sleeps.append(seconds)
        clock["value"] += seconds

    def fetch(_start, _end, expected_rule_ids, *, request_timeout_seconds=None):
        fetches.append((clock["value"], expected_rule_ids, request_timeout_seconds))
        return {"total": 1, "rule_buckets": [{"rule_id": "31104"}]} if clock["value"] == 14 else {"total": 0}

    monkeypatch.setattr(runner_module.time, "monotonic", monotonic)
    monkeypatch.setattr(runner_module.time, "sleep", sleep)
    monkeypatch.setattr(runner, "_fetch_evidence", fetch)
    monkeypatch.setattr(runner, "_queue_ai_job", lambda run, fetched: queued.append((run, fetched)))
    run = {
        "id": "a" * 32, "scenario_id": "file-inclusion", "status": "running",
        "phase": "running_script", "analysis_window_start": None, "analysis_window_end": None,
        "finished_at": None,
    }

    runner._correlate_and_queue(run, datetime.now(timezone.utc))

    assert [at for at, _rules, _timeout in fetches] == [0, 2, 4, 6, 8, 10, 12, 14]
    assert all(rules == ("31104",) for _at, rules, _timeout in fetches)
    assert [timeout for _at, _rules, timeout in fetches] == [5, 5, 5, 5, 5, 5, 3, 1]
    assert sleeps == [2, 2, 2, 2, 2, 2, 2]
    assert len(queued) == 1
    assert run["phase"] != "no_alert"
