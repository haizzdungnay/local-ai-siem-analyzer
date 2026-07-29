import csv
import importlib.util
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "eval"


def test_eval_manifest_has_valid_sanitized_cases():
    manifest = json.loads((EVAL_DIR / "manifest.json").read_text(encoding="utf-8"))

    assert 30 <= len(manifest) <= 50
    assert len({item["case_id"] for item in manifest}) == len(manifest)
    assert {item["provenance"] for item in manifest} == {"sanitized-live"}
    assert {item["scenario"] for item in manifest} >= {"ssh", "fim", "benign", "ambiguous"}

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


def test_results_csv_matches_runner_schema():
    with (EVAL_DIR / "results.csv").open(newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle))

    assert header == [
        "case_id", "model", "rag_enabled", "latency_s", "schema_valid", "error",
        "summary_score", "root_cause_score", "severity_score", "mitre_score",
        "next_steps_score", "reviewer", "notes", "output_json",
    ]
