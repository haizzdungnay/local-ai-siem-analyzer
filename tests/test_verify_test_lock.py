import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

import verify_test_lock as vtl  # noqa: E402


def _lock(tmp_path, content=b'{"hits":{"hits":[]}}'):
    target = tmp_path / "eval" / "raw_exports" / "kb1.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    return {"files": [{"path": "eval/raw_exports/kb1.json",
                       "sha256": hashlib.sha256(content).hexdigest()}]}, target


def test_verify_ok_missing_and_tampered(tmp_path):
    lock, target = _lock(tmp_path)
    failures, notes = vtl.verify(lock, root=tmp_path, check_git=False)
    assert failures == [] and notes[0].startswith("OK")

    target.write_bytes(b"tampered")
    failures, _ = vtl.verify(lock, root=tmp_path, check_git=False)
    assert failures and failures[0].startswith("FAIL")

    target.unlink()
    failures, notes = vtl.verify(lock, root=tmp_path, check_git=False)
    assert failures == [] and notes[0].startswith("MISSING")


def test_assert_not_test_data_blocks_locked_file(tmp_path):
    lock, target = _lock(tmp_path)
    copy = tmp_path / "train_candidate.json"
    copy.write_bytes(target.read_bytes())
    with pytest.raises(ValueError):
        vtl.assert_not_test_data(copy, lock)
    other = tmp_path / "other.json"
    other.write_text("{}", encoding="utf-8")
    vtl.assert_not_test_data(other, lock)


def test_repo_lock_file_is_well_formed():
    lock = json.loads((ROOT / "eval" / "test_set_lock.json").read_text(encoding="utf-8"))
    assert lock["files"] and all(len(f["sha256"]) == 64 for f in lock["files"])
    assert set(lock["tracked_eval_sets"]["git_tree"]) == {"eval/cases", "eval/expected", "eval/stratified_370"}
