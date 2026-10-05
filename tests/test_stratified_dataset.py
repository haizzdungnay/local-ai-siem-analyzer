"""tests/test_stratified_dataset.py — Unit tests for stratified dataset generator (F-07)."""

import json
from pathlib import Path
import sys

sys.path.insert(0, "eval")
from generate_stratified_dataset import generate_dataset, generate_case, SEVERITY_TEMPLATES


def test_generate_dataset_meets_strata_quotas_and_structure(tmp_path: Path):
    manifest = generate_dataset(
        output_dir=tmp_path,
        total=100,
        min_critical=20,
        min_high=20,
        seed=123
    )

    assert manifest["total_cases"] == 100
    assert manifest["strata_counts"]["critical"] >= 20
    assert manifest["strata_counts"]["high"] >= 20
    assert (
        manifest["strata_counts"]["critical"]
        + manifest["strata_counts"]["high"]
        + manifest["strata_counts"]["medium"]
        + manifest["strata_counts"]["low"]
    ) == 100

    cases_dir = tmp_path / "cases"
    expected_dir = tmp_path / "expected"

    assert cases_dir.is_dir()
    assert expected_dir.is_dir()

    case_files = list(cases_dir.glob("*.json"))
    expected_files = list(expected_dir.glob("*.json"))

    assert len(case_files) == 100
    assert len(expected_files) == 100

    # Kiểm tra tính toàn vẹn của schema alert case
    sample_case = json.loads(case_files[0].read_text(encoding="utf-8"))
    assert "agent" in sample_case
    assert "rule" in sample_case
    assert "full_log" in sample_case
    assert "id" in sample_case["rule"]
    assert "level" in sample_case["rule"]

    # Kiểm tra schema expected doc
    sample_expected = json.loads(expected_files[0].read_text(encoding="utf-8"))
    assert sample_expected["case_id"] == case_files[0].stem
    assert sample_expected["provenance"] == "synthetic-stratified"
    assert sample_expected["severity"] in ("critical", "high", "medium", "low")
    assert isinstance(sample_expected["mitre_ids"], list)
    assert isinstance(sample_expected["required_facts"], list)
    assert sample_expected["review_status"] == "draft-single-reviewer"


def test_generator_is_reproducible_with_seed(tmp_path: Path):
    dir_a = tmp_path / "run_a"
    dir_b = tmp_path / "run_b"

    manifest_a = generate_dataset(output_dir=dir_a, total=20, min_critical=5, min_high=5, seed=42)
    manifest_b = generate_dataset(output_dir=dir_b, total=20, min_critical=5, min_high=5, seed=42)

    assert manifest_a["cases"] == manifest_b["cases"]

    file_a = (dir_a / "cases" / f"{manifest_a['cases'][0]['case_id']}.json").read_text(encoding="utf-8")
    file_b = (dir_b / "cases" / f"{manifest_b['cases'][0]['case_id']}.json").read_text(encoding="utf-8")
    assert file_a == file_b
