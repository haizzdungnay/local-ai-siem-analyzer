import argparse
import csv
import json
import math
import statistics
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
SCORE_FIELDS = [
    "summary_score", "root_cause_score", "severity_score", "mitre_score",
    "next_steps_score",
]


def percentile(values, quantile):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


def load_expected():
    manifest = json.loads((EVAL_DIR / "manifest.json").read_text(encoding="utf-8"))
    return {
        item["case_id"]: json.loads(
            (EVAL_DIR.parent / item["expected_file"]).read_text(encoding="utf-8")
        )
        for item in manifest
    }


def summarize(path):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"{path}: không có result row")

    expected = load_expected()
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


def main():
    parser = argparse.ArgumentParser(description="Tổng hợp kết quả eval tự động và human scores")
    parser.add_argument("results", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps([summarize(path) for path in args.results], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
