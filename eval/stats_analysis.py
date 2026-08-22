"""
Tính các chỉ số thống kê cho mục 4.4.3 của báo cáo:
  - Tỷ lệ khớp mức nghiêm trọng của 3 cấu hình
  - Khoảng tin cậy Wilson 95%
  - Kiểm định McNemar chính xác (ghép cặp) giữa cấu hình A và B

Cách chạy (từ thư mục gốc của repo):
    python eval/stats_analysis.py
"""

import csv
import glob
import json
import math
import os
from math import comb

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIGS = {
    "A - qwen2.5:7b + RAG":   "results.csv",
    "B - qwen2.5:7b khong RAG": "results-no-rag.csv",
    "C - notmythos-8b + RAG":  "results-notmythos-8b.csv",
}


def load_ground_truth():
    """Doc nhan chuan tu eval/expected/*.json"""
    gt = {}
    for path in glob.glob(os.path.join(EVAL_DIR, "expected", "*.json")):
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        gt[d["case_id"]] = d["severity"]
    return gt


def load_predictions(filename):
    """Doc severity ma model du doan tu cot output_json"""
    preds = {}
    with open(os.path.join(EVAL_DIR, filename), encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                preds[row["case_id"]] = json.loads(row["output_json"]).get("severity")
            except Exception:
                preds[row["case_id"]] = None
    return preds


def wilson_ci(k, n, z=1.96):
    """Khoang tin cay Wilson cho ty le. Tra ve (can duoi, can tren) theo %."""
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (center - half) * 100, (center + half) * 100


def mcnemar_exact(b, c):
    """Kiem dinh McNemar chinh xac hai phia.
    b = so case cau hinh 1 dung / cau hinh 2 sai
    c = nguoc lai
    Dung phan phoi nhi thuc B(n, 0.5) voi n = b + c.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(2 * tail, 1.0)


def main():
    gt = load_ground_truth()
    n_total = len(gt)
    print(f"Bo du lieu danh gia: {n_total} canh bao")
    print(f"Phan bo nhan chuan: ", end="")
    dist = {}
    for v in gt.values():
        dist[v] = dist.get(v, 0) + 1
    print(", ".join(f"{k}={v}" for k, v in sorted(dist.items())))
    print()

    print("=" * 78)
    print("1. TY LE KHOP MUC NGHIEM TRONG + KHOANG TIN CAY WILSON 95%")
    print("=" * 78)
    print(f"{'Cau hinh':<28}{'Khop':>10}{'Ty le':>10}{'Wilson CI 95%':>26}")
    print("-" * 78)

    preds_all = {}
    for label, fname in CONFIGS.items():
        preds = load_predictions(fname)
        preds_all[label] = preds
        k = sum(1 for cid, truth in gt.items() if preds.get(cid) == truth)
        lo, hi = wilson_ci(k, n_total)
        print(f"{label:<28}{k:>4}/{n_total:<5}{k/n_total*100:>9.1f}%   [{lo:>5.1f}% ; {hi:>5.1f}%]")

    print()
    print("=" * 78)
    print("2. KIEM DINH McNEMAR GHEP CAP - CAU HINH A vs B (do anh huong cua RAG)")
    print("=" * 78)

    labels = list(CONFIGS.keys())
    A, B = preds_all[labels[0]], preds_all[labels[1]]

    both_ok = both_bad = b = c = 0
    for cid, truth in gt.items():
        a_ok = (A.get(cid) == truth)
        b_ok = (B.get(cid) == truth)
        if a_ok and b_ok:
            both_ok += 1
        elif a_ok and not b_ok:
            b += 1
        elif b_ok and not a_ok:
            c += 1
        else:
            both_bad += 1

    print(f"  Ca hai cung dung          : {both_ok:>3}  (khong phan biet duoc)")
    print(f"  Ca hai cung sai           : {both_bad:>3}  (khong phan biet duoc)")
    print(f"  A dung / B sai        (b) : {b:>3}  <- cap bat dong")
    print(f"  B dung / A sai        (c) : {c:>3}  <- cap bat dong")
    print(f"  Tong so cap bat dong      : {b+c:>3}")
    print()
    p = mcnemar_exact(b, c)
    print(f"  p (McNemar chinh xac, hai phia) = {p:.4f}")
    print(f"  Ket luan o muc y nghia 0,05     : "
          f"{'CO y nghia thong ke' if p < 0.05 else 'CHUA du bang chung'}")
    print()
    print(f"  Ghi chu: voi {b+c} cap bat dong, gia tri p nho nhat co the dat duoc")
    print(f"           (khi tat ca nghieng ve mot phia) la {mcnemar_exact(b+c, 0):.4f}")

    # --- So sanh A vs C: do khac biet giua hai mo hinh ---
    print()
    print("=" * 78)
    print("2b. KIEM DINH McNEMAR GHEP CAP - CAU HINH A vs C (do khac biet mo hinh)")
    print("=" * 78)
    C = preds_all[labels[2]]
    ok2 = bad2 = b2 = c2 = 0
    for cid, truth in gt.items():
        a_ok = (A.get(cid) == truth)
        c_ok = (C.get(cid) == truth)
        if a_ok and c_ok:
            ok2 += 1
        elif a_ok and not c_ok:
            b2 += 1
        elif c_ok and not a_ok:
            c2 += 1
        else:
            bad2 += 1
    print(f"  Ca hai cung dung          : {ok2:>3}")
    print(f"  Ca hai cung sai           : {bad2:>3}")
    print(f"  A dung / C sai        (b) : {b2:>3}  <- cap bat dong")
    print(f"  C dung / A sai        (c) : {c2:>3}  <- cap bat dong")
    print(f"  Tong so cap bat dong      : {b2+c2:>3}")
    print()
    p2 = mcnemar_exact(b2, c2)
    print(f"  p (McNemar chinh xac, hai phia) = {p2:.5f}")
    print(f"  Ket luan o muc y nghia 0,05     : "
          f"{'CO y nghia thong ke' if p2 < 0.05 else 'CHUA du bang chung'}")




# ============================================================================
# PHAN BO SUNG: BASELINE KHONG DUNG LLM
# ----------------------------------------------------------------------------
# Muc dich: kiem chung rang mo-dun AI thuc su them gia tri, chu khong chi
# doc lai con so rule.level da co san trong canh bao.
#
# !!! QUAN TRONG !!!
# Bang RULE_LEVELS duoi day dang dung muc MAC DINH cua ruleset Wazuh v4.9.0.
# BAN PHAI DOI CHIEU LAI voi rule.level thuc te tren Dashboard cua minh
# truoc khi trich dan ket qua. Neu nhom co sua luat thi so se khac.
# ============================================================================

RULE_LEVELS = {
    "506": 3, "510": 7, "503": 3, "5402": 3, "5501": 3, "5502": 3,
    "5715": 3, "23502": 3, "553": 7, "554": 5, "2502": 10, "40112": 12,
    "5503": 5, "5710": 5, "5712": 10, "5760": 5,
    "31101": 5, "31105": 6, "31151": 10,
}


def level_to_band(level, mid_band="low"):
    """Anh xa rule.level sang nhom severity theo Bang 1.2 cua bao cao.
    mid_band: muc 6-7 thuoc nhom 'Thap - Trung binh', co the xep 'low' hoac 'medium'.
    """
    if level <= 5:
        return "low"
    if level <= 7:
        return mid_band
    if level <= 11:
        return "medium"
    return "high"


def baseline_analysis():
    gt = {}
    rules = {}
    for path in glob.glob(os.path.join(EVAL_DIR, "expected", "*.json")):
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        gt[d["case_id"]] = d["severity"]
        rules[d["case_id"]] = str(d["rule_id"])

    n = len(gt)
    print()
    print("=" * 78)
    print("3. BASELINE KHONG DUNG LLM: 'tra ve dung nhom muc cua luat'")
    print("=" * 78)

    missing = sorted({r for r in rules.values() if r not in RULE_LEVELS})
    if missing:
        print(f"  CANH BAO: thieu muc cho cac rule: {missing}")
        print("  -> Bo sung vao RULE_LEVELS roi chay lai.")
        return

    for mid in ("low", "medium"):
        k = sum(1 for cid, truth in gt.items()
                if level_to_band(RULE_LEVELS[rules[cid]], mid) == truth)
        lo, hi = wilson_ci(k, n)
        print(f"  Baseline (muc 6-7 xep nhom '{mid}'):"
              f" {k}/{n} = {k/n*100:.1f}%   Wilson CI [{lo:.1f}% ; {hi:.1f}%]")

    print()
    print("  So sanh: mo-dun AI (cau hinh A) dat 66,7%.")
    print("  Neu baseline thap hon dang ke -> mo-dun co gia tri gia tang thuc su,")
    print("  khong phai chi doc lai rule.level co san trong canh bao.")
    print()
    print("  Chi tiet tung case (doi chieu voi Dashboard de xac minh rule.level):")
    print(f"  {'case_id':<20}{'rule':>7}{'level':>7}{'baseline':>10}{'nhan chuan':>13}{'khop':>7}")
    print("  " + "-" * 66)
    for cid in sorted(gt):
        lv = RULE_LEVELS[rules[cid]]
        band = level_to_band(lv, "low")
        ok = "OK" if band == gt[cid] else "sai"
        print(f"  {cid:<20}{rules[cid]:>7}{lv:>7}{band:>10}{gt[cid]:>13}{ok:>7}")


if __name__ == "__main__":
    main()
    baseline_analysis()