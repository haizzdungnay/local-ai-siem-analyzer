import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "eval"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval import export_confusion_matrix as confusion


def test_qwen_baseline_confusion_matrices_are_derived_from_complete_project_data():
    case_ids = confusion.load_case_ids(EVAL_DIR)
    truth = confusion.load_truth(EVAL_DIR, case_ids)

    rag_predictions = confusion.load_predictions(
        EVAL_DIR / "results.csv",
        case_ids,
        expected_rag_enabled="true",
    )
    no_rag_predictions = confusion.load_predictions(
        EVAL_DIR / "results-no-rag.csv",
        case_ids,
        expected_rag_enabled="false",
    )

    assert len(case_ids) == len(truth) == len(rag_predictions) == len(no_rag_predictions) == 33
    assert confusion.make_matrix(truth, rag_predictions) == {
        "low": {"low": 10, "medium": 2, "high": 0, "invalid": 1},
        "medium": {"low": 4, "medium": 9, "high": 0, "invalid": 0},
        "high": {"low": 1, "medium": 3, "high": 3, "invalid": 0},
    }
    assert confusion.make_matrix(truth, no_rag_predictions) == {
        "low": {"low": 9, "medium": 4, "high": 0, "invalid": 0},
        "medium": {"low": 4, "medium": 9, "high": 0, "invalid": 0},
        "high": {"low": 0, "medium": 6, "high": 1, "invalid": 0},
    }


def test_report_declares_draft_reference_labels_and_two_panel_figure():
    case_ids = confusion.load_case_ids(EVAL_DIR)
    truth = confusion.load_truth(EVAL_DIR, case_ids)
    predictions = {
        config: confusion.load_predictions(
            EVAL_DIR / filename,
            case_ids,
            expected_rag_enabled=rag_enabled,
        )
        for config, filename, rag_enabled in confusion.CONFIGS
    }
    matrices = {
        config: confusion.make_matrix(truth, predictions[config])
        for config, _, _ in confusion.CONFIGS
    }
    report = confusion.render_markdown(
        truth=truth,
        matrices=matrices,
        all_predictions=predictions,
    )

    assert confusion.REFERENCE_NOTE == (
        "Rows are reference ground truth (draft, single reviewer); "
        "cells show count and row percentage."
    )
    assert "review_status=draft-single-reviewer" in report
    assert "Rows are reference ground truth (draft, single reviewer)" in report
    assert "Hình 4.1. Ma trận nhầm lẫn mức nghiêm trọng — cấu hình A (có RAG) và B (không RAG)" in report
    assert "Hình 4.1 trực quan hóa Bảng 4.13" in report
    assert "adjudicated" not in report.lower()


@pytest.mark.parametrize(
    "raw_output",
    ("", "not-json", json.dumps({"severity": "unknown"}), json.dumps([])),
)
def test_out_of_contract_prediction_is_counted_as_invalid(raw_output):
    assert confusion.normalize_prediction(raw_output) == "invalid"


def test_export_rejects_result_file_from_a_different_model(tmp_path):
    result_path = tmp_path / "result.csv"
    with result_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("case_id", "model", "rag_enabled", "output_json"),
        )
        writer.writeheader()
        writer.writerow({
            "case_id": "case-1",
            "model": "other-model",
            "rag_enabled": "true",
            "output_json": json.dumps({"severity": "low"}),
        })

    with pytest.raises(ValueError, match="expected model"):
        confusion.load_predictions(result_path, ["case-1"])
