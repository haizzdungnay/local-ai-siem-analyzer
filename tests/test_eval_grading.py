import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "eval"


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, EVAL_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_judgment(score=4):
    names = ("summary", "root_cause", "severity", "mitre", "next_steps")
    return {
        "scores": {name: score for name in names},
        "rationale": {name: f"evidence {name}" for name in names},
        "confidence": "medium",
        "violations": [],
    }


def test_builds_66_ai_judge_items_without_mutating_inputs():
    judge = load_module("judge_results")
    paths = [EVAL_DIR / "results.csv", EVAL_DIR / "results-no-rag.csv"]
    before = {path: path.read_bytes() for path in paths}

    work = judge.build_work_items(paths)

    assert len(work) == 66
    assert len({(item["source_results"], item["result"]["case_id"]) for item in work}) == 66
    assert {item["manifest"]["provenance"] for item in work} == {"sanitized-live"}
    assert all(len(item["source_output_sha256"]) == 64 for item in work)
    assert all(len(item["expected_sha256"]) == 64 for item in work)
    assert {path: path.read_bytes() for path in paths} == before


def test_parse_judgment_is_strict():
    judge = load_module("judge_results")

    parsed = judge.parse_judgment(json.dumps(valid_judgment()))

    assert parsed["scores"]["summary"] == 4
    invalid = [
        {**valid_judgment(), "extra": "bad"},
        {**valid_judgment(), "scores": {**valid_judgment()["scores"], "summary": 6}},
        {**valid_judgment(), "scores": {**valid_judgment()["scores"], "summary": "4"}},
        {**valid_judgment(), "rationale": {**valid_judgment()["rationale"], "mitre": ""}},
        {**valid_judgment(), "confidence": "certain"},
    ]
    for payload in invalid:
        with pytest.raises(ValueError):
            judge.parse_judgment(json.dumps(payload))


def test_score_item_uses_ai_only_schema_and_output_fields():
    judge = load_module("judge_results")
    work = judge.build_work_items([EVAL_DIR / "results.csv"])[0]
    captured = {}

    class FakeClient:
        def chat(self, **kwargs):
            captured.update(kwargs)
            return {"message": {"content": json.dumps(valid_judgment(5))}}

    judgment, latency = judge.score_item(
        FakeClient(), work, "rubric", "independent-judge", 0, 20260729
    )
    row = judge.output_row(work, "independent-judge", 0, 20260729, judgment, latency)

    assert captured["model"] == "independent-judge"
    assert captured["format"] == judge.JUDGE_SCHEMA
    assert captured["options"] == {"temperature": 0, "seed": 20260729}
    assert row["judge_type"] == "ai-rubric-judge"
    assert row["judge_provider"] == "ollama"
    assert row["overall_ai_score"] == "5.00"
    assert row["judge_schema_valid"] == "true"
    assert not any("human" in key for key in row)


def test_ai_judgment_summary_keeps_ai_label(tmp_path):
    judge = load_module("judge_results")
    summary_module = load_module("summarize_results")
    work = judge.build_work_items([
        EVAL_DIR / "results.csv", EVAL_DIR / "results-no-rag.csv"
    ])
    output = tmp_path / "judgments.csv"

    import csv
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=judge.OUTPUT_FIELDS)
        writer.writeheader()
        for item in work:
            writer.writerow(judge.output_row(
                item, "judge", 0, 1, valid_judgment(4), 1.0
            ))

    result = summary_module.summarize_ai_judgments(
        output, [EVAL_DIR / "results.csv", EVAL_DIR / "results-no-rag.csv"]
    )

    assert result["coverage"] == 66
    assert result["judge_type"] == ["ai-rubric-judge"]
    assert result["groups"]["results.csv"]["mean_scores"]["overall_ai_score"] == 4
    assert result["paired"] == {"rag_wins": 0, "ties": 33, "no_rag_wins": 0}
    assert "human review" in result["limitation"]


def test_existing_judgment_hash_mismatch_is_detectable(tmp_path):
    judge = load_module("judge_results")
    output = tmp_path / "judgments.csv"
    work = judge.build_work_items([EVAL_DIR / "results.csv"])[0]
    row = judge.output_row(
        work, "judge", 0, 1, valid_judgment(), 1.0
    )
    row["source_output_sha256"] = "bad"

    import csv
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=judge.OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerow(row)

    existing = judge.load_existing(output)

    assert existing[(work["source_results"], work["result"]["case_id"])]["source_output_sha256"] == "bad"
    assert existing[(work["source_results"], work["result"]["case_id"])]["source_output_sha256"] != work["source_output_sha256"]
