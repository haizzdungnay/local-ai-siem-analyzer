import json, os, glob
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(ROOT, "eval")

def test_blind_cases_integrity():
    blind_path = os.path.join(EVAL_DIR, "blind_cases.json")
    assert os.path.exists(blind_path)
    with open(blind_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
    assert len(cases) == 33
    for cid, c in cases.items():
        assert "rule_id" not in c
        assert "rule_level" not in c
        assert "severity" not in c

def test_reviewer_annotations_and_kappa():
    r1_path = os.path.join(EVAL_DIR, "annotations_reviewer1.json")
    r2_path = os.path.join(EVAL_DIR, "annotations_reviewer2.json")
    adj_path = os.path.join(EVAL_DIR, "adjudicated_severity.json")
    
    assert os.path.exists(r1_path) and os.path.exists(r2_path) and os.path.exists(adj_path)
    r1 = json.load(open(r1_path, encoding="utf-8"))
    r2 = json.load(open(r2_path, encoding="utf-8"))
    adj = json.load(open(adj_path, encoding="utf-8"))
    
    assert len(r1) == 33 and len(r2) == 33 and len(adj) == 33
    for cid in r1:
        assert r1[cid]["severity"] in {"low", "medium", "high"}
        assert r2[cid]["severity"] in {"low", "medium", "high"}
        assert adj[cid]["severity"] in {"low", "medium", "high"}
        assert adj[cid]["status"] == "adjudicated-two-reviewer"

def test_baseline_comparison_script_runs():
    import subprocess, sys
    res = subprocess.run([sys.executable, os.path.join(EVAL_DIR, "baseline_comparison.py")], capture_output=True, text=True)
    assert res.returncode == 0
    assert "Cohen's Kappa" in res.stdout or "Cohen" in res.stdout