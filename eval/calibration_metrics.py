"""eval/calibration_metrics.py — Do luong calibration cho confidence cua mo hinh AI.

Cac chi so:
1. Brier score: Sai so toan phuong trung binh giua xac suat du doan va ket qua thuc te.
2. Expected Calibration Error (ECE): Sai lech ky vong giua do tin cay va do chinh xac qua cac bin.
3. Maximum Calibration Error (MCE): Sai lech lon nhat giua do tin cay va do chinh xac tren cac bin.
"""

from __future__ import annotations

from typing import Sequence


def brier_score(probabilities: Sequence[float], outcomes: Sequence[int | bool]) -> float:
    """Tinh diem Brier score = (1/N) * sum((p_i - y_i)^2)."""
    _validate_inputs(probabilities, outcomes)
    n = len(probabilities)
    total_sq_err = sum((float(p) - float(y)) ** 2 for p, y in zip(probabilities, outcomes))
    return total_sq_err / n


def expected_calibration_error(
    probabilities: Sequence[float],
    outcomes: Sequence[int | bool],
    *,
    num_bins: int = 10,
) -> float:
    """Tinh Expected Calibration Error (ECE) tren cac bin deu nhau."""
    _validate_inputs(probabilities, outcomes, num_bins=num_bins)
    bins = _compute_bins(probabilities, outcomes, num_bins=num_bins)
    n = len(probabilities)
    ece = sum(
        (len(items) / n) * abs(bin_acc - bin_conf)
        for bin_acc, bin_conf, items in bins
        if items
    )
    return ece


def maximum_calibration_error(
    probabilities: Sequence[float],
    outcomes: Sequence[int | bool],
    *,
    num_bins: int = 10,
) -> float:
    """Tinh Maximum Calibration Error (MCE) — sai lech lon nhat trong cac bin co mau."""
    _validate_inputs(probabilities, outcomes, num_bins=num_bins)
    bins = _compute_bins(probabilities, outcomes, num_bins=num_bins)
    diffs = [abs(bin_acc - bin_conf) for bin_acc, bin_conf, items in bins if items]
    return max(diffs) if diffs else 0.0


def evaluate_confidence_calibration(
    pairs: Sequence[tuple[float, bool | int]],
    *,
    num_bins: int = 10,
) -> dict[str, float]:
    """Danh gia do hieu chuan confidence tu tap cap (confidence_0_to_100, is_correct)."""
    if not pairs:
        raise ValueError("pairs khong duoc rong")
    raw_confs, outcomes = zip(*pairs)
    probs = [float(c) / 100.0 if float(c) > 1.0 else float(c) for c in raw_confs]
    clean_outcomes = [1 if bool(y) else 0 for y in outcomes]

    brier = brier_score(probs, clean_outcomes)
    ece = expected_calibration_error(probs, clean_outcomes, num_bins=num_bins)
    mce = maximum_calibration_error(probs, clean_outcomes, num_bins=num_bins)
    accuracy = sum(clean_outcomes) / len(clean_outcomes)
    mean_conf_pct = (sum(probs) / len(probs)) * 100.0

    return {
        "sample_count": len(pairs),
        "brier_score": round(brier, 4),
        "ece": round(ece, 4),
        "mce": round(mce, 4),
        "accuracy": round(accuracy, 4),
        "mean_confidence": round(mean_conf_pct, 2),
    }


def _validate_inputs(
    probabilities: Sequence[float],
    outcomes: Sequence[int | bool],
    *,
    num_bins: int | None = None,
) -> None:
    if not probabilities or not outcomes:
        raise ValueError("Danh sach khong duoc rong")
    if len(probabilities) != len(outcomes):
        raise ValueError("probabilities va outcomes phai cung do dai")
    if num_bins is not None and (not isinstance(num_bins, int) or num_bins < 1):
        raise ValueError("num_bins phai la so nguyen duong")

    for p in probabilities:
        if not (0.0 <= float(p) <= 1.0):
            raise ValueError(f"Gia tri xac suat phai trong khoang [0.0, 1.0]: {p}")

    for y in outcomes:
        if y not in {0, 1, False, True}:
            raise ValueError(f"Gia tri ket qua phai la 0, 1 hoac bool: {y}")


def _compute_bins(
    probabilities: Sequence[float],
    outcomes: Sequence[int | bool],
    *,
    num_bins: int,
) -> list[tuple[float, float, list[tuple[float, int]]]]:
    bin_items: list[list[tuple[float, int]]] = [[] for _ in range(num_bins)]
    for p, y in zip(probabilities, outcomes):
        prob = float(p)
        outcome = 1 if bool(y) else 0
        bin_idx = min(int(prob * num_bins), num_bins - 1)
        bin_items[bin_idx].append((prob, outcome))

    results = []
    for items in bin_items:
        if items:
            bin_acc = sum(y for _, y in items) / len(items)
            bin_conf = sum(p for p, _ in items) / len(items)
            results.append((bin_acc, bin_conf, items))
        else:
            results.append((0.0, 0.0, []))
    return results
