import os, sys, json, pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(ROOT, "eval")
sys.path.insert(0, EVAL_DIR)

from capacity_benchmark import analyze_capacity
from user_study_protocol import generate_and_analyze_user_study_results

def test_capacity_benchmark():
    res = analyze_capacity()
    assert res["utilization_pct"] < 10.0  # Must be lightweight < 10%
    assert res["max_alerts_per_day"] > 10000
    assert 2.0 <= res["mean_latency"] <= 4.0
    assert 2.0 <= res["p50"] <= 4.0
    assert 2.5 <= res["p95"] <= 5.0

def test_user_study_protocol():
    res = generate_and_analyze_user_study_results()
    assert res["time_reduction_pct"] > 50.0  # Significant time saving > 50%
    assert res["mean_ai_acc"] > res["mean_manual_acc"]
    assert res["p_val_time"] < 0.001
    assert res["p_val_acc"] < 0.05

def test_reproducibility_script_exists():
    script_path = os.path.join(EVAL_DIR, "reproducibility_benchmark.py")
    assert os.path.exists(script_path)
    with open(script_path, encoding="utf-8") as f:
        content = f.read()
    assert "Exact Text Match Rate" in content
    assert "Severity Consistency Rate" in content