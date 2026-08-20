"""
eval/reproducibility_benchmark.py

Do luong tinh tai lap (Reproducibility & Determinism) cua mo hinh tren GPU:
1. Chay lap 5 lan (5 runs) voi cung tham so: model=qwen2.5:7b, temperature=0.0, seed=42 tren tap 33 case.
2. Chi so do luong:
   - Output Exact Match Consistency (% token-for-token trung khop tuyet doi giua cac run).
   - Severity Exact Consistency (% dong nhat ve nhan severity qua 5 run).
   - Schema Validity Consistency (% luon giu dung JSON schema qua 5 run).
   - Do bien thien Latency (Latency Variance & Std across 5 runs).
"""

import csv
import glob
import json
import os
import sys
import time
import urllib.request
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(EVAL_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, "ai_module"))

from extractor import extract_fields, format_for_llm
from llm import _untrusted_message, OUTPUT_SCHEMA, build_soc_system_prompt

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL_NAME = "qwen2.5:7b"


def call_model(prompt: str, user_msg: str) -> tuple[str, float]:
    url = f"{OLLAMA_URL}/api/chat"
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_msg}
        ],
        "format": OUTPUT_SCHEMA,
        "options": {"temperature": 0.0, "seed": 42},
        "stream": False
    }
    t0 = time.perf_counter()
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        content = res.get("message", {}).get("content", "")
    t1 = time.perf_counter()
    return content, (t1 - t0)


def run_reproducibility_test(num_runs=5, case_subset=None):
    cases_dir = os.path.join(EVAL_DIR, "cases")
    case_files = sorted(glob.glob(os.path.join(cases_dir, "*.json")))
    if case_subset:
        case_files = case_files[:case_subset]
        
    print("=" * 85)
    print(f"B?O C?O ?O L??NG T?NH T?I L?P (REPRODUCIBILITY BENCHMARK ? {num_runs} L??T CH?Y L?P)")
    print("=" * 85)
    print(f"M? h?nh: {MODEL_NAME} | C?u h?nh: temperature=0, seed=42, format=JSON Schema")
    print(f"S? l??ng case ki?m th?: {len(case_files)} cases | T?ng s? l??t g?i model: {len(case_files) * num_runs}")
    print()

    # Load prompts
    sys_prompt = build_soc_system_prompt("alert", "vi")
    cases_data = []
    for cf in case_files:
        cid = os.path.basename(cf).replace(".json", "")
        with open(cf, encoding="utf-8") as f:
            c_json = json.load(f)
        extracted = extract_fields(c_json)
        text = format_for_llm(extracted)
        user_msg = _untrusted_message("ALERT", text)
        cases_data.append((cid, user_msg))

    results_by_case = {cid: [] for cid, _ in cases_data}
    latencies_by_run = [[] for _ in range(num_runs)]

    for run_idx in range(num_runs):
        print(f"--- ?ang th?c thi Run {run_idx + 1}/{num_runs} ---")
        for cid, user_msg in cases_data:
            content, lat = call_model(sys_prompt, user_msg)
            results_by_case[cid].append(content)
            latencies_by_run[run_idx].append(lat)

    # Calculate Consistency Metrics
    exact_text_matches = 0
    severity_matches = 0
    schema_valid_counts = 0
    total_calls = len(cases_data) * num_runs

    for cid, contents in results_by_case.items():
        # Check text exact match across all 5 runs
        if len(set(contents)) == 1:
            exact_text_matches += 1
            
        # Parse severities
        sevs = []
        for c in contents:
            try:
                d = json.loads(c)
                sevs.append(d.get("severity"))
                schema_valid_counts += 1
            except Exception:
                sevs.append("error")
        if len(set(sevs)) == 1 and sevs[0] != "error":
            severity_matches += 1

    exact_text_rate = (exact_text_matches / len(cases_data)) * 100
    severity_rate = (severity_matches / len(cases_data)) * 100
    schema_rate = (schema_valid_counts / total_calls) * 100

    print()
    print("=" * 85)
    print("K?T QU? ?O L??NG T?NH X?C ??NH & ?? BI?N THI?N (REPRODUCIBILITY RESULTS)")
    print("=" * 85)
    print(f"1. T? l? tr?ng kh?p v?n b?n tuy?t ??i (Exact Text Match Rate 5/5 runs): {exact_text_matches}/{len(cases_data)} ({exact_text_rate:.1f}%)")
    print(f"2. T? l? ??ng nh?t nh?n Severity (Severity Consistency Rate 5/5 runs) : {severity_matches}/{len(cases_data)} ({severity_rate:.1f}%)")
    print(f"3. T? l? tu?n th? Schema JSON (Schema Validity across all calls)       : {schema_valid_counts}/{total_calls} ({schema_rate:.1f}%)")
    print()

    # Latency across runs
    all_latencies = [lat for r_lats in latencies_by_run for lat in r_lats]
    print(f"4. Th?ng k? ?? tr? qua {num_runs} l??t ch?y:")
    print(f"   - ?? tr? trung b?nh : {np.mean(all_latencies):.3f} s  (std: {np.std(all_latencies):.3f} s)")
    print(f"   - Ph?n v? p50 (Median) : {np.percentile(all_latencies, 50):.3f} s")
    print(f"   - Ph?n v? p95          : {np.percentile(all_latencies, 95):.3f} s")
    print(f"   - Ph?n v? p99          : {np.percentile(all_latencies, 99):.3f} s")
    print(f"   - Min / Max            : {np.min(all_latencies):.3f} s / {np.max(all_latencies):.3f} s")
    print()
    
    return {
        "exact_text_rate": exact_text_rate,
        "severity_rate": severity_rate,
        "schema_rate": schema_rate,
        "mean_latency": float(np.mean(all_latencies)),
        "std_latency": float(np.std(all_latencies)),
        "p50_latency": float(np.percentile(all_latencies, 50)),
        "p95_latency": float(np.percentile(all_latencies, 95)),
    }


if __name__ == "__main__":
    # Test on full 33 cases or subset
    subset = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run_reproducibility_test(num_runs=5, case_subset=subset)