import csv
import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "eval"


def test_eval_manifest_has_valid_sanitized_cases():
    manifest = json.loads((EVAL_DIR / "manifest.json").read_text(encoding="utf-8"))

    assert 30 <= len(manifest) <= 50
    assert len({item["case_id"] for item in manifest}) == len(manifest)
    assert {item["provenance"] for item in manifest} == {"sanitized-live"}
    assert {item["scenario"] for item in manifest} >= {"ssh", "fim", "web", "benign", "ambiguous"}

    rule_counts = Counter()
    for item in manifest:
        case = json.loads((ROOT / item["case_file"]).read_text(encoding="utf-8"))
        expected = json.loads((ROOT / item["expected_file"]).read_text(encoding="utf-8"))
        serialized = json.dumps(case, ensure_ascii=False)

        assert expected["case_id"] == item["case_id"]
        assert expected["review_status"] == "draft-single-reviewer"
        assert expected["severity"] in {"low", "medium", "high", "critical"}
        assert expected["disposition"] in {"benign", "suspicious", "malicious", "ambiguous"}
        assert expected["required_facts"]
        assert expected["next_steps_reference"]
        assert "192.168.100." not in serialized
        assert "trnguyn-virtual-machine" not in serialized
        assert "99-claude-lab" not in serialized
        assert "SHA256:TzVS" not in serialized
        assert "password" not in {key.lower() for key in case}
        rule_counts[expected["rule_id"]] += 1

    assert len(rule_counts) >= 10
    assert rule_counts["5503"] >= 3
    assert rule_counts["554"] >= 1
    assert rule_counts["23502"] >= 1
    assert rule_counts["31101"] >= 1
    assert rule_counts["31151"] >= 1
    assert rule_counts["31105"] >= 1

    expected_by_id = {
        item["case_id"]: json.loads(
            (ROOT / item["expected_file"]).read_text(encoding="utf-8")
        )
        for item in manifest
    }
    assert expected_by_id["ssh-40112-01"]["disposition"] == "ambiguous"
    assert expected_by_id["ssh-40112-01"]["severity"] == "high"
    assert expected_by_id["benign-5715-01"]["mitre_ids"] == []
    assert expected_by_id["benign-5402-01"]["mitre_ids"] == []
    assert expected_by_id["ssh-5710-02"]["mitre_ids"] == []


def test_eval_runner_resolves_case_path_from_repo(monkeypatch, tmp_path):
    runner_path = ROOT / "eval" / "run_eval.py"
    spec = importlib.util.spec_from_file_location("run_eval", runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    item = json.loads((EVAL_DIR / "manifest.json").read_text(encoding="utf-8"))[0]

    monkeypatch.chdir(tmp_path)

    assert runner.load_case(item)["rule"]["id"] == item["rule_id"]


def test_result_summary_metrics():
    summary_path = EVAL_DIR / "summarize_results.py"
    spec = importlib.util.spec_from_file_location("summarize_results", summary_path)
    summary_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(summary_module)

    summary = summary_module.summarize(EVAL_DIR / "results.csv")

    assert summary["cases"] == 33
    assert summary["schema_valid"] == 32
    assert summary["errors"] == 0
    assert summary["severity_exact"] == 22
    assert summary["scored_cases"] == 0


def test_results_csv_matches_runner_schema():
    with (EVAL_DIR / "results.csv").open(newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle))

    assert header == [
        "case_id", "model", "rag_enabled", "latency_s", "schema_valid", "error",
        "summary_score", "root_cause_score", "severity_score", "mitre_score",
        "next_steps_score", "reviewer", "notes", "output_json",
    ]


def test_eval_runner_writes_versioned_metadata_without_overwriting(tmp_path):
    runner_path = ROOT / "eval" / "run_eval.py"
    spec = importlib.util.spec_from_file_location("run_eval_metadata", runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    result_path = tmp_path / "results-soc-prompt-v1-vi.csv"

    handle, _ = runner.open_results(result_path)
    handle.close()

    with result_path.open(newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle))
    assert header == runner.RESULT_FIELDS
    assert {
        "language", "prompt_version", "system_prompt_sha256",
        "requested_language", "response_language", "language_compliance",
        "output_origin", "provenance_json",
    } <= set(header)
    with pytest.raises(FileExistsError):
        runner.open_results(result_path)


def test_eval_runner_keeps_all_rows_when_retrieval_fails(tmp_path, monkeypatch):
    import sys

    spec = importlib.util.spec_from_file_location("run_eval_rows", EVAL_DIR / "run_eval.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    records = [{"case_id": case, "rule": {"id": rule, "mitre": {"id": "T1110.001"}}}
               for case, rule in (("before", "1"), ("error", "2"), ("after", "3"))]
    queried = []

    class RAG:
        def __init__(self, *, data_dir, persist_dir, in_memory, **kwargs):
            assert in_memory is True
            self.store = Path(persist_dir)
            assert not self.store.is_relative_to(Path(data_dir))

        def close(self):
            assert self.store.is_dir()

        def ensure_indexed(self):
            pass

        def query(self, rule_id, description, *, mitre_ids, **kwargs):
            queried.append(mitre_ids)
            if rule_id == "2":
                raise TimeoutError("private error detail")
            return [], {"status": "no_match"}

        def format_context(self, results):
            return ""

    output = tmp_path / "new.csv"
    monkeypatch.setattr(sys, "argv", ["run_eval.py", "--results", str(output)])
    monkeypatch.setattr(runner, "load_config", lambda path: {
        "ollama": {"model": "local-model", "base_url": "http://localhost:11434"},
        "extractor": {"fields": ["rule.id", "rule.mitre.id"]},
        "rag": {"enabled": True, "data_dir": str(tmp_path), "embedding_model": "embed"},
    })
    monkeypatch.setattr(runner, "RuleRAG", RAG)
    monkeypatch.setattr(runner, "load_manifest", lambda limit: records)
    monkeypatch.setattr(runner, "load_case", lambda item: item)
    monkeypatch.setattr(runner, "analyze_alert", lambda **kwargs: ({"mitre": "T1110.001"}, {}))
    runner.main()

    with output.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert queried == [["T1110.001"]] * 3
    assert [row["case_id"] for row in rows] == ["before", "error", "after"]
    assert rows[1]["error"] == "RAG: TimeoutError"
    assert json.loads(rows[1]["provenance_json"])["rag"] == {"status": "error", "error_type": "TimeoutError"}
    assert "private error detail" not in output.read_text(encoding="utf-8")


def test_eval_schema_remains_legacy_five_fields():
    runner_path = ROOT / "eval" / "run_eval.py"
    spec = importlib.util.spec_from_file_location("run_eval_schema", runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    valid = {
        "summary": "Observed login failure",
        "root_cause": "Invalid credentials",
        "severity": "low",
        "mitre": "",
        "next_steps": ["Verify the source"],
    }

    assert runner.valid_output(valid)
    assert not runner.valid_output({**valid, "response_language": "en"})
    assert not runner.valid_output({**valid, "summary": "  "})
    assert not runner.valid_output({**valid, "root_cause": ""})
    assert not runner.valid_output({**valid, "next_steps": []})
    assert not runner.valid_output({**valid, "next_steps": [" "]})


def test_eval_runner_configures_utf8_console(monkeypatch):
    runner_path = ROOT / "eval" / "run_eval.py"
    spec = importlib.util.spec_from_file_location("run_eval_console", runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    class FakeStream:
        def reconfigure(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(runner.sys, "stdout", FakeStream())
    monkeypatch.setattr(runner.sys, "stderr", FakeStream())

    runner._configure_console_encoding()

    assert calls == [
        {"encoding": "utf-8", "errors": "replace"},
        {"encoding": "utf-8", "errors": "replace"},
    ]


@pytest.mark.parametrize("mutation", ("duplicate", "unknown", "missing"))
def test_result_summary_rejects_incomplete_or_invalid_case_coverage(tmp_path, mutation):
    summary_path = EVAL_DIR / "summarize_results.py"
    spec = importlib.util.spec_from_file_location("summarize_results_coverage", summary_path)
    summary_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(summary_module)

    with (EVAL_DIR / "results.csv").open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    if mutation == "duplicate":
        rows[-1]["case_id"] = rows[0]["case_id"]
    elif mutation == "unknown":
        rows[-1]["case_id"] = "not-in-manifest"
    else:
        rows = rows[:-1]
    output = tmp_path / f"{mutation}.csv"
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="coverage mismatch"):
        summary_module.summarize(output)


def test_summary_configures_utf8_console(monkeypatch):
    summary_path = EVAL_DIR / "summarize_results.py"
    spec = importlib.util.spec_from_file_location("summarize_results_console", summary_path)
    summary_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(summary_module)
    calls = []

    class FakeStream:
        def reconfigure(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(summary_module.sys, "stdout", FakeStream())
    monkeypatch.setattr(summary_module.sys, "stderr", FakeStream())
    summary_module._configure_console_encoding()

    assert calls == [
        {"encoding": "utf-8", "errors": "replace"},
        {"encoding": "utf-8", "errors": "replace"},
    ]
