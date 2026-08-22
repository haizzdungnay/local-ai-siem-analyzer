"""Compatibility entry point for the current two-panel confusion matrix.

Use ``python eval/export_confusion_matrix.py`` for the normal export. This
legacy filename remains usable for anyone who already has it in a runbook.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.export_confusion_matrix import (  # noqa: E402
    CONFIGS,
    load_case_ids,
    load_predictions,
    load_truth,
    make_matrix,
    write_png,
)


def main() -> None:
    eval_dir = ROOT / "eval"
    case_ids = load_case_ids(eval_dir)
    truth = load_truth(eval_dir, case_ids)
    matrices = {}
    for config, filename, expected_rag_enabled in CONFIGS:
        predictions = load_predictions(
            eval_dir / filename,
            case_ids,
            expected_rag_enabled=expected_rag_enabled,
        )
        matrices[config] = make_matrix(truth, predictions)
    output = ROOT / "docs" / "confusion_matrix_severity.png"
    write_png(output, matrices)
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
