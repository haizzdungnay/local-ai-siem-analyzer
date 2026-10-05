"""Unit tests for confidence calibration metrics (Brier score & ECE)."""

import pytest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "eval"
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from calibration_metrics import (
    brier_score,
    expected_calibration_error,
    maximum_calibration_error,
    evaluate_confidence_calibration,
)


def test_brier_score_perfect_prediction():
    probs = [1.0, 1.0, 0.0, 0.0]
    outcomes = [1, 1, 0, 0]
    assert brier_score(probs, outcomes) == 0.0


def test_brier_score_worst_prediction():
    probs = [1.0, 1.0]
    outcomes = [0, 0]
    assert brier_score(probs, outcomes) == 1.0


def test_brier_score_coin_flip():
    probs = [0.5, 0.5]
    outcomes = [1, 0]
    assert brier_score(probs, outcomes) == 0.25


def test_ece_perfect_calibration():
    # 10 samples with conf 0.8 where exactly 8 are correct
    probs = [0.8] * 10
    outcomes = [1] * 8 + [0] * 2
    assert expected_calibration_error(probs, outcomes, num_bins=5) == pytest.approx(0.0, abs=1e-5)


def test_ece_extreme_overconfidence():
    probs = [1.0] * 10
    outcomes = [0] * 10
    assert expected_calibration_error(probs, outcomes, num_bins=10) == pytest.approx(1.0, abs=1e-5)
    assert maximum_calibration_error(probs, outcomes, num_bins=10) == pytest.approx(1.0, abs=1e-5)


def test_validation_errors():
    with pytest.raises(ValueError, match="do dai"):
        brier_score([0.5], [1, 0])

    with pytest.raises(ValueError, match="khong duoc rong"):
        brier_score([], [])

    with pytest.raises(ValueError, match="xac suat"):
        brier_score([1.5], [1])

    with pytest.raises(ValueError, match="ket qua"):
        brier_score([0.5], [2])


def test_evaluate_confidence_calibration_handles_percent():
    # 4 cases: 90% (correct), 90% (correct), 80% (incorrect), 50% (correct)
    pairs = [
        (90.0, True),
        (90.0, True),
        (80.0, False),
        (50.0, True),
    ]
    report = evaluate_confidence_calibration(pairs, num_bins=5)
    assert report["sample_count"] == 4
    assert 0.0 <= report["brier_score"] <= 1.0
    assert 0.0 <= report["ece"] <= 1.0
    assert report["accuracy"] == 0.75
    assert report["mean_confidence"] == pytest.approx(77.5, abs=0.1)
