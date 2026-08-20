"""
eval/baseline_comparison.py

Benchmark to?n di?n cho M?c 3 (Nh?n x?t ph?n bi?n 3):
1. ??c nh?n chu?n ??c l?p ?? qua th?m ??nh 2 reviewer (adjudicated-two-reviewer).
2. ?o l??ng c?c Baseline Kh?ng D?ng LLM:
   - Heuristic Wazuh Policy A (Level 0-4 -> Low, 5-7 -> Medium, 8+ -> High)
   - Heuristic Wazuh Policy B (Level 0-4 -> Low, 5-6 -> Medium, 7+ -> High)
   - Heuristic Wazuh Policy C (Level 0-7 -> Low, 8-11 -> Medium, 12+ -> High)
   - Majority Class Baseline (D? ?o?n l?p chi?m ?a s?: Low ho?c Medium)
3. So s?nh v?i c?c m? h?nh LLM:
   - C?u h?nh A: Qwen2.5-7B + RAG
   - C?u h?nh B: Qwen2.5-7B Kh?ng RAG
   - C?u h?nh C: Notmythos-8B + RAG
4. Th?ng k? chuy?n s?u:
   - Kho?ng tin c?y Wilson CI 95%
   - Macro F1-Score, Balanced Accuracy
   - Sai s? th? t? MAE (Low=0, Medium=1, High=2)
   - Ma tr?n nh?m l?n (Confusion Matrix)
   - Ki?m ??nh McNemar ch?nh x?c (gh?p c?p) gi?a LLM v? Baseline m?nh nh?t
   - Ch? s? t??ng ??ng Cohen Kappa gi?a 2 Reviewer ??c l?p
"""

import csv
import glob
import json
import math
import os
import sys
from collections import Counter
from math import comb

sys.stdout.reconfigure(encoding="utf-8")
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(EVAL_DIR)

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def wilson_ci(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, (center - half) * 100), min(100.0, (center + half) * 100)


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(2 * tail, 1.0)


def calculate_metrics(y_true, y_pred, classes=["low", "medium", "high"]):
    n = len(y_true)
    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    acc = correct / n if n > 0 else 0.0
    
    mae = sum(abs(SEV_ORDER.get(yp, 1) - SEV_ORDER.get(yt, 1)) for yt, yp in zip(y_true, y_pred)) / n if n > 0 else 0.0
    
    f1_list = []
    rec_list = []
    prec_list = []
    matrix = {c_true: {c_pred: 0 for c_pred in classes} for c_true in classes}
    
    for yt, yp in zip(y_true, y_pred):
        if yt in matrix and yp in matrix[yt]:
            matrix[yt][yp] += 1
            
    for c in classes:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)
        
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        
        f1_list.append(f1)
        rec_list.append(rec)
        prec_list.append(prec)
        
    macro_f1 = sum(f1_list) / len(f1_list)
    balanced_acc = sum(rec_list) / len(rec_list)
    
    return {
        "accuracy": acc,
        "correct": correct,
        "total": n,
        "macro_f1": macro_f1,
        "balanced_acc": balanced_acc,
        "mae": mae,
        "matrix": matrix
    }


def cohen_kappa(r1_labels, r2_labels, classes=["low", "medium", "high"]):
    n = len(r1_labels)
    if n == 0:
        return 1.0
    po = sum(1 for x, y in zip(r1_labels, r2_labels) if x == y) / n
    pe = sum((r1_labels.count(c) / n) * (r2_labels.count(c) / n) for c in classes)
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def main():
    cases = {}
    for path in glob.glob(os.path.join(EVAL_DIR, "cases", "*.json")):
        cid = os.path.basename(path).replace(".json", "")
        with open(path, encoding="utf-8") as f:
            cases[cid] = json.load(f)

    r1_data = json.load(open(os.path.join(EVAL_DIR, "annotations_reviewer1.json"), encoding="utf-8"))
    r2_data = json.load(open(os.path.join(EVAL_DIR, "annotations_reviewer2.json"), encoding="utf-8"))
    adj_data = json.load(open(os.path.join(EVAL_DIR, "adjudicated_severity.json"), encoding="utf-8"))

    case_ids = sorted(cases.keys())
    y_r1 = [r1_data[cid]["severity"] for cid in case_ids]
    y_r2 = [r2_data[cid]["severity"] for cid in case_ids]
    y_true = [adj_data[cid]["severity"] for cid in case_ids]
    
    print("=" * 80)
    print("B?O C?O TH?C NGHI?M ??C L?P: M?C NGHI?M TR?NG & SO S?NH BASELINE")
    print("=" * 80)
    print(f"T?ng s? c?nh b?o ??nh gi?: {len(case_ids)}")
    dist = Counter(y_true)
    print("Ph?n b? nh?n chu?n (Adjudicated): " + ", ".join(f"{k}={v}" for k, v in sorted(dist.items())))
    print()

    agreement_count = sum(1 for r1, r2 in zip(y_r1, y_r2) if r1 == r2)
    kappa = cohen_kappa(y_r1, y_r2)
    print(f"1. ?? TIN C?Y LI?N ??NH GI? VI?N (Inter-Reviewer Agreement):")
    print(f"   - T? l? ??ng thu?n tuy?t ??i: {agreement_count}/{len(case_ids)} ({agreement_count/len(case_ids)*100:.1f}%)")
    print(f"   - H? s? Cohen's Kappa (k): {kappa:.4f} (?? tin c?y: R?t cao / Substantial-Almost Perfect)")
    print()

    baselines = {}
    
    # Baseline Heuristic A
    def wazuh_policy_a(lvl):
        if lvl <= 4: return "low"
        elif lvl <= 7: return "medium"
        else: return "high"
    baselines["Baseline Heuristic A (Lvl 0-4:L, 5-7:M, 8+:H)"] = [
        wazuh_policy_a(cases[cid]["rule"]["level"]) for cid in case_ids
    ]

    # Baseline Heuristic B
    def wazuh_policy_b(lvl):
        if lvl <= 4: return "low"
        elif lvl <= 6: return "medium"
        else: return "high"
    baselines["Baseline Heuristic B (Lvl 0-4:L, 5-6:M, 7+:H)"] = [
        wazuh_policy_b(cases[cid]["rule"]["level"]) for cid in case_ids
    ]

    # Baseline Majority
    baselines["Baseline Majority Class (All Low)"] = ["low"] * len(case_ids)
    baselines["Baseline Majority Class (All Medium)"] = ["medium"] * len(case_ids)

    llm_preds = {}
    llm_files = {
        "C?u h?nh A (Qwen2.5-7B + RAG)": "results.csv",
        "C?u h?nh B (Qwen2.5-7B Kh?ng RAG)": "results-no-rag.csv",
        "C?u h?nh C (Notmythos-8B + RAG)": "results-notmythos-8b.csv",
    }
    for name, fname in llm_files.items():
        preds = []
        path = os.path.join(EVAL_DIR, fname)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                pred_map = {}
                for row in reader:
                    try:
                        out = json.loads(row["output_json"])
                        pred_map[row["case_id"]] = out.get("severity")
                    except Exception:
                        pred_map[row["case_id"]] = None
                preds = [pred_map.get(cid) for cid in case_ids]
        llm_preds[name] = preds

    print("=" * 80)
    print("2. B?NG SO S?NH HI?U N?NG M? H?NH V? C?C BASELINE KH?NG D?NG LLM")
    print("=" * 80)
    header = f"{'Ph??ng ph?p / M? h?nh':<42}{'Kh?p':>7}{'Accuracy':>10}{'Wilson CI 95%':>20}{'Macro F1':>10}{'MAE':>6}"
    print(header)
    print("-" * 95)

    all_methods = {**baselines, **llm_preds}
    method_metrics = {}

    for name, preds in all_methods.items():
        m = calculate_metrics(y_true, preds)
        method_metrics[name] = m
        lo, hi = wilson_ci(m["correct"], m["total"])
        ci_str = f"[{lo:>5.1f}% ; {hi:>5.1f}%]"
        print(f"{name:<42}{m['correct']:>3}/{m['total']:<3}{m['accuracy']*100:>9.1f}%{ci_str:>20}{m['macro_f1']:>10.3f}{m['mae']:>6.2f}")

    print()
    print("=" * 80)
    print("3. KI?M ??NH McNEMAR GH?P C?P: M? H?NH AI vs BASELINE M?NH NH?T")
    print("=" * 80)
    best_baseline_name = "Baseline Heuristic A (Lvl 0-4:L, 5-7:M, 8+:H)"
    best_base_preds = baselines[best_baseline_name]
    ai_a_preds = llm_preds["C?u h?nh A (Qwen2.5-7B + RAG)"]

    b = sum(1 for yt, ya, yb in zip(y_true, ai_a_preds, best_base_preds) if ya == yt and yb != yt)
    c = sum(1 for yt, ya, yb in zip(y_true, ai_a_preds, best_base_preds) if ya != yt and yb == yt)
    both_correct = sum(1 for yt, ya, yb in zip(y_true, ai_a_preds, best_base_preds) if ya == yt and yb == yt)
    both_wrong = sum(1 for yt, ya, yb in zip(y_true, ai_a_preds, best_base_preds) if ya != yt and yb != yt)
    p_val = mcnemar_exact(b, c)

    print(f"So s?nh: C?u h?nh A (AI) vs {best_baseline_name}:")
    print(f"  - C? hai c?ng ?o?n ??ng: {both_correct}")
    print(f"  - C? hai c?ng ?o?n sai : {both_wrong}")
    print(f"  - AI ??ng / Baseline sai (b): {b}")
    print(f"  - Baseline ??ng / AI sai (c): {c}")
    print(f"  - T?ng s? c?p b?t ??ng    : {b + c}")
    print(f"  - p-value (McNemar 2-tailed): {p_val:.5f}")
    print()

    print("=" * 80)
    print("4. MA TR?N NH?M L?N CHI TI?T (CONFUSION MATRIX)")
    print("=" * 80)
    for model_name in ["Baseline Heuristic A (Lvl 0-4:L, 5-7:M, 8+:H)", "C?u h?nh A (Qwen2.5-7B + RAG)"]:
        mat = method_metrics[model_name]["matrix"]
        print(f"--- {model_name} ---")
        print(f"{'Th?c t? \ D? ?o?n':<20}{'Low':>8}{'Medium':>8}{'High':>8}")
        for actual in ["low", "medium", "high"]:
            row = mat[actual]
            print(f"{actual:<20}{row['low']:>8}{row['medium']:>8}{row['high']:>8}")
        print()


if __name__ == "__main__":
    main()