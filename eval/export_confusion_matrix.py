"""Export severity confusion matrices for the qwen2.5:7b eval snapshots.

The exporter intentionally reads the frozen manifest, draft reference labels
from ``eval/expected/`` and the existing result CSVs.  It does not call Ollama,
so a report is reproducible and cannot silently mix a new model run with the
historical baseline.

Run from the repository root::

    python eval/export_confusion_matrix.py

The default command writes a Markdown report, a long-form CSV and a PNG under
``docs/``/``eval/``.  Rows are ground truth; columns are model predictions.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable


MODEL = "qwen2.5:7b"
LABELS = ("low", "medium", "high")
INVALID_LABEL = "invalid"
PREDICTION_LABELS = LABELS + (INVALID_LABEL,)
CONFIGS = (
    ("RAG", "results.csv", "true"),
    ("No RAG", "results-no-rag.csv", "false"),
)
DISPLAY_LABELS = {
    "low": "thấp",
    "medium": "trung bình",
    "high": "cao",
    "invalid": "không hợp lệ",
}
CONFIG_TITLES = {
    "RAG": "Cấu hình A — có RAG",
    "No RAG": "Cấu hình B — không RAG",
}
REFERENCE_NOTE = (
    "Rows are reference ground truth (draft, single reviewer); "
    "cells show count and row percentage."
)


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_case_ids(eval_dir: Path) -> list[str]:
    manifest = _read_json(eval_dir / "manifest.json")
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("eval/manifest.json must be a non-empty list")
    case_ids = [item.get("case_id") for item in manifest]
    if any(not isinstance(case_id, str) or not case_id for case_id in case_ids):
        raise ValueError("manifest contains an invalid case_id")
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("manifest contains duplicate case_id")
    return case_ids


def load_truth(eval_dir: Path, case_ids: Iterable[str]) -> dict[str, str]:
    """Load the draft, single-reviewer reference labels from expected/*.json."""

    expected = {}
    review_statuses = {}
    for path in (eval_dir / "expected").glob("*.json"):
        item = _read_json(path)
        expected[item["case_id"]] = item["severity"]
        review_statuses[item["case_id"]] = item.get("review_status")

    ids = list(case_ids)
    if set(expected) != set(ids):
        raise ValueError("expected labels do not cover manifest exactly")
    unexpected_statuses = {
        case_id: review_statuses[case_id]
        for case_id in ids
        if review_statuses[case_id] != "draft-single-reviewer"
    }
    if unexpected_statuses:
        raise ValueError(
            "expected labels are not uniformly draft-single-reviewer: "
            + repr(unexpected_statuses)
        )

    truth = {case_id: expected[case_id] for case_id in ids}
    if any(label not in LABELS for label in truth.values()):
        raise ValueError("expected labels contain an unsupported severity")
    return truth


def normalize_prediction(output_json: str) -> str:
    """Map malformed, missing or out-of-contract severity to ``invalid``."""

    try:
        output = json.loads(output_json) if output_json else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        return INVALID_LABEL
    prediction = output.get("severity") if isinstance(output, dict) else None
    return prediction if prediction in LABELS else INVALID_LABEL


def load_predictions(
    path: Path,
    case_ids: Iterable[str],
    *,
    expected_model: str = MODEL,
    expected_rag_enabled: str | None = None,
) -> dict[str, str]:
    ids = list(case_ids)
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"{path}: no result rows")
    actual_ids = [row.get("case_id", "") for row in rows]
    if len(actual_ids) != len(set(actual_ids)):
        raise ValueError(f"{path}: duplicate case_id")
    if set(actual_ids) != set(ids):
        missing = sorted(set(ids) - set(actual_ids))
        unknown = sorted(set(actual_ids) - set(ids))
        raise ValueError(f"{path}: coverage mismatch; missing={missing}, unknown={unknown}")
    models = {row.get("model", "") for row in rows}
    if models != {expected_model}:
        raise ValueError(f"{path}: expected model {expected_model!r}, found {sorted(models)!r}")
    if expected_rag_enabled is not None:
        rag_values = {row.get("rag_enabled", "") for row in rows}
        if rag_values != {expected_rag_enabled}:
            raise ValueError(
                f"{path}: expected rag_enabled={expected_rag_enabled!r}, found {sorted(rag_values)!r}"
            )
    return {row["case_id"]: normalize_prediction(row.get("output_json", "")) for row in rows}


def make_matrix(truth: dict[str, str], predictions: dict[str, str]) -> dict[str, dict[str, int]]:
    matrix = {actual: {predicted: 0 for predicted in PREDICTION_LABELS} for actual in LABELS}
    for case_id, actual in truth.items():
        try:
            predicted = predictions[case_id]
        except KeyError as exc:
            raise ValueError(f"missing prediction for {case_id}") from exc
        matrix[actual][predicted] += 1
    return matrix


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def metrics(matrix: dict[str, dict[str, int]]) -> dict[str, object]:
    total = sum(sum(row.values()) for row in matrix.values())
    per_class = {}
    for label in LABELS:
        tp = matrix[label][label]
        actual_total = sum(matrix[label].values())
        predicted_total = sum(matrix[actual][label] for actual in LABELS)
        precision = _safe_div(tp, predicted_total)
        recall = _safe_div(tp, actual_total)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": actual_total,
        }
    accuracy = _safe_div(sum(matrix[label][label] for label in LABELS), total)
    macro_f1 = _safe_div(sum(item["f1"] for item in per_class.values()), len(LABELS))
    return {
        "total": total,
        "correct": sum(matrix[label][label] for label in LABELS),
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "per_class": per_class,
    }


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_markdown(
    *,
    truth: dict[str, str],
    matrices: dict[str, dict[str, dict[str, int]]],
    all_predictions: dict[str, dict[str, str]],
) -> str:
    lines = [
        "# Confusion matrix — qwen2.5:7b",
        "",
        "- Dataset: `eval/manifest.json` (33 frozen `sanitized-live` cases).",
        "- Reference labels: `eval/expected/*.json` (`review_status=draft-single-reviewer`).",
        f"- {REFERENCE_NOTE} Columns: predicted severity.",
        "- `invalid` includes missing/malformed JSON or a severity outside `low|medium|high`.",
        "- The project contains `qwen2.5:7b`; no `qwen2.7:7b` result exists, so this is the project baseline requested.",
        "",
        "**Hình 4.1. Ma trận nhầm lẫn mức nghiêm trọng — cấu hình A (có RAG) và B (không RAG)**",
        "",
        "Hình 4.1 trực quan hóa Bảng 4.13 dưới dạng bản đồ nhiệt, đặt cạnh ma trận tương ứng của cấu hình B để so sánh trực tiếp hướng sai lệch của hai cấu hình.",
        "",
    ]
    for config, _, _ in CONFIGS:
        matrix = matrices[config]
        result_metrics = metrics(matrix)
        lines.extend([
            f"## {CONFIG_TITLES[config]}",
            "",
            f"Accuracy: **{result_metrics['correct']}/{result_metrics['total']} ({_pct(result_metrics['accuracy'])})**; "
            f"macro-F1: **{result_metrics['macro_f1']:.3f}**.",
            "",
            "| Nhãn chuẩn \\ Dự đoán | thấp | trung bình | cao | không hợp lệ | Tổng |",
            "|---|---:|---:|---:|---:|---:|",
        ])
        for actual in LABELS:
            row = matrix[actual]
            lines.append(
                f"| **{DISPLAY_LABELS[actual]}** | {row['low']} | {row['medium']} | {row['high']} | "
                f"{row['invalid']} | {sum(row.values())} |"
            )
        lines.append(
            "| **Tổng dự đoán** | "
            + " | ".join(str(sum(matrix[actual][predicted] for actual in LABELS)) for predicted in PREDICTION_LABELS)
            + f" | {sum(sum(row.values()) for row in matrix.values())} |"
        )
        lines.extend([
            "",
            "| Class | Precision | Recall | F1 | Support |",
            "|---|---:|---:|---:|---:|",
        ])
        for label, values in result_metrics["per_class"].items():
            lines.append(
                f"| {label} | {_pct(values['precision'])} | {_pct(values['recall'])} | "
                f"{values['f1']:.3f} | {values['support']} |"
            )
        lines.extend(["", "### Misclassification details", ""])
        errors = [
            (case_id, truth[case_id], all_predictions[config][case_id])
            for case_id in truth
            if truth[case_id] != all_predictions[config][case_id]
        ]
        if errors:
            lines.append("| Case | Nhãn chuẩn | Dự đoán |")
            lines.append("|---|---|---|")
            lines.extend(
                f"| `{case_id}` | {DISPLAY_LABELS[actual]} | {DISPLAY_LABELS.get(predicted, predicted)} |"
                for case_id, actual, predicted in errors
            )
        else:
            lines.append("No misclassified cases.")
        lines.append("")
    lines.extend([
        "## Interpretation",
        "",
        "- RAG correctly classifies 22/33 cases; the one `invalid` output is `benign-23502-01`.",
        "- Without RAG, 19/33 cases are correct and all outputs are schema-valid.",
        "- In the `high` row, RAG predicts 3/7 correctly and under-calls 4/7; no-RAG predicts 1/7 correctly and under-calls 6/7.",
        "",
    ])
    return "\n".join(lines)


def write_long_csv(
    path: Path,
    matrices: dict[str, dict[str, dict[str, int]]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("configuration", "ground_truth", "predicted", "count", "row_total", "row_percent"),
        )
        writer.writeheader()
        for config, _, _ in CONFIGS:
            matrix = matrices[config]
            for actual in LABELS:
                row_total = sum(matrix[actual].values())
                for predicted in PREDICTION_LABELS:
                    count = matrix[actual][predicted]
                    writer.writerow({
                        "configuration": config,
                        "ground_truth": actual,
                        "predicted": predicted,
                        "count": count,
                        "row_total": row_total,
                        "row_percent": f"{_safe_div(count, row_total) * 100:.1f}",
                    })


def write_png(path: Path, matrices: dict[str, dict[str, dict[str, int]]]) -> None:
    """Render a compact, row-normalized heatmap while keeping count labels."""

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    path.parent.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(13.2, 5.9), squeeze=False)
    display_labels = ("thấp", "trung bình", "cao", "không hợp lệ")
    panel_titles = ("Cấu hình A — có RAG", "Cấu hình B — không RAG")
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list(
        "teal_matrix", ["#edf5f3", "#1f6f5c"]
    )
    for ax, (config, _, _), panel_title in zip(axes[0], CONFIGS, panel_titles):
        matrix = matrices[config]
        values = np.array([[matrix[actual][predicted] for predicted in PREDICTION_LABELS] for actual in LABELS])
        totals = values.sum(axis=1, keepdims=True)
        normalized = np.divide(values, totals, out=np.zeros_like(values, dtype=float), where=totals != 0)
        image = ax.imshow(normalized, cmap=cmap, vmin=0, vmax=1, aspect="auto")
        ax.set_xticks(range(len(PREDICTION_LABELS)), display_labels)
        ax.set_yticks(range(len(LABELS)), display_labels[:3])
        ax.set_xlabel("Mức do mô hình dự đoán")
        ax.set_ylabel("Mức chuẩn tham chiếu")
        ax.set_title(panel_title)
        ax.set_xticks(np.arange(-0.5, len(PREDICTION_LABELS), 1), minor=True)
        ax.set_yticks(np.arange(-0.5, len(LABELS), 1), minor=True)
        ax.grid(which="minor", color="white", linewidth=2)
        ax.tick_params(which="minor", bottom=False, left=False)
        ax.tick_params(which="major", length=0)
        for row_index, actual in enumerate(LABELS):
            row_total = sum(matrix[actual].values())
            for column_index, predicted in enumerate(PREDICTION_LABELS):
                count = matrix[actual][predicted]
                text_color = "white" if normalized[row_index, column_index] >= 0.55 else "#17302a"
                ax.text(
                    column_index,
                    row_index,
                    f"{count}\n({_safe_div(count, row_total) * 100:.0f}%)",
                    ha="center",
                    va="center",
                    color=text_color,
                    fontsize=11,
                    fontweight="bold" if actual == predicted and predicted in LABELS else "normal",
                )
        ax.spines[:].set_visible(False)
    fig.suptitle(
        "Hình 4.1. Ma trận nhầm lẫn mức nghiêm trọng\n"
        "cấu hình A (có RAG) và B (không RAG)",
        fontsize=15,
        fontweight="bold",
    )
    fig.text(0.5, 0.01, REFERENCE_NOTE, ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.04, 1, 0.94))
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--eval-dir", type=Path, default=root / "eval")
    parser.add_argument("--report", type=Path, default=root / "docs" / "confusion_matrix_qwen2.5_7b.md")
    parser.add_argument("--csv", type=Path, default=root / "eval" / "confusion_matrix_qwen2.5_7b.csv")
    parser.add_argument("--png", type=Path, default=root / "docs" / "confusion_matrix_qwen2.5_7b.png")
    parser.add_argument("--model", default=MODEL)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    case_ids = load_case_ids(args.eval_dir)
    truth = load_truth(args.eval_dir, case_ids)
    matrices = {}
    all_predictions = {}
    for config, filename, expected_rag_enabled in CONFIGS:
        predictions = load_predictions(
            args.eval_dir / filename,
            case_ids,
            expected_model=args.model,
            expected_rag_enabled=expected_rag_enabled,
        )
        all_predictions[config] = predictions
        matrices[config] = make_matrix(truth, predictions)

    report = render_markdown(truth=truth, matrices=matrices, all_predictions=all_predictions)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report + "\n", encoding="utf-8")
    write_long_csv(args.csv, matrices)
    write_png(args.png, matrices)

    print(f"model={args.model}")
    print(f"cases={len(case_ids)}")
    for config, _, _ in CONFIGS:
        result_metrics = metrics(matrices[config])
        print(
            f"{config}: correct={result_metrics['correct']}/{result_metrics['total']} "
            f"accuracy={_pct(result_metrics['accuracy'])} macro_f1={result_metrics['macro_f1']:.3f}"
        )
    print(f"report={args.report}")
    print(f"csv={args.csv}")
    print(f"png={args.png}")


if __name__ == "__main__":
    main()
