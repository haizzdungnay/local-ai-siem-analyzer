import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
SCORE_FIELDS = [
    "summary_score", "root_cause_score", "severity_score", "mitre_score",
    "next_steps_score",
]
REQUIRED_RESULT_FIELDS = {
    "case_id", "latency_s", "schema_valid", "error", "output_json", *SCORE_FIELDS,
}


def _configure_console_encoding():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def percentile(values, quantile):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


def load_expected():
    manifest = json.loads((EVAL_DIR / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("eval/manifest.json must be a non-empty list")
    case_ids = [item.get("case_id") for item in manifest]
    if any(not isinstance(case_id, str) or not case_id for case_id in case_ids):
        raise ValueError("eval/manifest.json contains an invalid case_id")
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("eval/manifest.json contains duplicate case_id")
    return {
        item["case_id"]: json.loads(
            (EVAL_DIR.parent / item["expected_file"]).read_text(encoding="utf-8")
        )
        for item in manifest
    }


def _load_result_rows(path):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])
        missing_fields = REQUIRED_RESULT_FIELDS - fieldnames
        if missing_fields:
            raise ValueError(f"{path}: missing CSV columns: {sorted(missing_fields)}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"{path}: không có result row")
    return rows


def _validate_result_coverage(path, rows, expected):
    case_ids = [row.get("case_id", "") for row in rows]
    if any(not case_id for case_id in case_ids):
        raise ValueError(f"{path}: empty case_id")
    actual = set(case_ids)
    duplicates = len(case_ids) - len(actual)
    missing = set(expected) - actual
    unknown = actual - set(expected)
    if duplicates or missing or unknown:
        raise ValueError(
            f"{path}: coverage mismatch; duplicates={duplicates}, "
            f"missing={len(missing)}, unknown={len(unknown)}"
        )


def summarize(path):
    expected = load_expected()
    rows = _load_result_rows(path)
    _validate_result_coverage(path, rows, expected)
    latencies = [float(row["latency_s"]) for row in rows]
    severity_exact = 0
    score_values = {field: [] for field in SCORE_FIELDS}
    for row in rows:
        output = json.loads(row["output_json"]) if row["output_json"] else {}
        severity_exact += output.get("severity") == expected[row["case_id"]]["severity"]
        for field in SCORE_FIELDS:
            if row[field]:
                value = int(row[field])
                if not 1 <= value <= 5:
                    raise ValueError(f"{path}: {row['case_id']} {field} ngoài 1..5")
                score_values[field].append(value)

    completed_scores = sum(all(row[field] for field in SCORE_FIELDS) for row in rows)
    return {
        "path": str(path),
        "cases": len(rows),
        "schema_valid": sum(row["schema_valid"].lower() == "true" for row in rows),
        "errors": sum(bool(row["error"]) for row in rows),
        "mean_latency_s": round(statistics.mean(latencies), 3),
        "median_latency_s": round(statistics.median(latencies), 3),
        "p95_latency_s": round(percentile(latencies, 0.95), 3),
        "max_latency_s": round(max(latencies), 3),
        "severity_exact": severity_exact,
        "scored_cases": completed_scores,
        "mean_scores": {
            field: round(statistics.mean(values), 2) if values else None
            for field, values in score_values.items()
        },
    }


def summarize_ai_judgments(path, result_paths):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    expected_keys = {
        (result_path.name, row["case_id"])
        for result_path in result_paths
        for row in csv.DictReader(result_path.open(newline="", encoding="utf-8"))
    }
    actual_keys = [(row["source_results"], row["case_id"]) for row in rows]
    if len(actual_keys) != len(set(actual_keys)):
        raise ValueError(f"{path}: duplicate AI judgment")
    missing = expected_keys - set(actual_keys)
    unknown = set(actual_keys) - expected_keys
    if missing or unknown:
        raise ValueError(f"{path}: coverage mismatch; missing={len(missing)}, unknown={len(unknown)}")

    groups = {}
    for source in sorted({row["source_results"] for row in rows}):
        source_rows = [row for row in rows if row["source_results"] == source]
        valid = [row for row in source_rows if row["judge_schema_valid"].lower() == "true"]
        scores = {
            field: [float(row[field]) for row in valid]
            for field in (
                "summary_ai_score", "root_cause_ai_score", "severity_ai_score",
                "mitre_ai_score", "next_steps_ai_score", "overall_ai_score",
            )
        }
        groups[source] = {
            "coverage": len(source_rows),
            "judge_schema_valid": len(valid),
            "judge_errors": len(source_rows) - len(valid),
            "mean_scores": {
                field: round(statistics.mean(values), 2) if values else None
                for field, values in scores.items()
            },
            "median_overall_ai_score": round(
                statistics.median(scores["overall_ai_score"]), 2
            ) if scores["overall_ai_score"] else None,
        }

    by_case = {}
    for row in rows:
        if row["judge_schema_valid"].lower() == "true":
            by_case.setdefault(row["case_id"], {})[row["source_results"]] = float(row["overall_ai_score"])
    source_names = sorted(groups)
    paired = {"rag_wins": 0, "ties": 0, "no_rag_wins": 0}
    if len(source_names) == 2:
        rag_source = next((name for name in source_names if name == "results.csv"), source_names[0])
        no_rag_source = next((name for name in source_names if name == "results-no-rag.csv"), source_names[1])
        for values in by_case.values():
            if rag_source not in values or no_rag_source not in values:
                continue
            delta = values[rag_source] - values[no_rag_source]
            paired["rag_wins" if delta > 0 else "no_rag_wins" if delta < 0 else "ties"] += 1

    return {
        "path": str(path),
        "judge_type": sorted({row["judge_type"] for row in rows}),
        "judge_models": sorted({row["judge_model"] for row in rows}),
        "prompt_versions": sorted({row["judge_prompt_version"] for row in rows}),
        "coverage": len(rows),
        "groups": groups,
        "paired": paired,
        "limitation": "AI-only rubric scoring; không phải human review hoặc ground truth final.",
    }


def main():
    _configure_console_encoding()
    parser = argparse.ArgumentParser(description="Tổng hợp kết quả eval tự động, human score và AI judge")
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--ai-judgments", type=Path)
    args = parser.parse_args()
    result = {"baseline": [summarize(path) for path in args.results]}
    if args.ai_judgments:
        result["ai_judgments"] = summarize_ai_judgments(args.ai_judgments, args.results)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
