"""Baseline khong dung LLM: 'tra ve dung nhom muc cua luat'.
Chay:  python eval/baseline_check.py
"""
import glob, json, math, os
 
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
 
# Muc luat. Cac rule co dau (*) da doi chieu tu du lieu that trong CHAM_DIEM.txt.
# Cac rule con lai dang dung muc mac dinh Wazuh v4.9.0 - CAN KIEM TRA TREN DASHBOARD.
RULE_LEVELS = {
    "503": 3,    # *
    "506": 3,    # *
    "510": 7,    # *
    "554": 5,    # *
    "2502": 10,  # *
    "5502": 3,   # *
    "5503": 5,   # *
    "5710": 5,   # *
    "5760": 5,   # *
    "23502": 3,  # *
    "553": 7,    # can kiem tra
    "5402": 3,   # can kiem tra
    "5501": 3,   # can kiem tra
    "5712": 10,  # can kiem tra
    "5715": 3,   # can kiem tra
    "31101": 5,  # can kiem tra
    "31105": 6,  # can kiem tra
    "31151": 10, # can kiem tra
    "40112": 12, # can kiem tra
}
 
 
def band(level, mid):
    """Anh xa rule.level -> nhom severity theo Bang 1.2.
    mid: muc 6-7 la nhom 'Thap - Trung binh', xep 'low' hoac 'medium'."""
    if level <= 5:
        return "low"
    if level <= 7:
        return mid
    if level <= 11:
        return "medium"
    return "high"
 
 
def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h) * 100, (c + h) * 100
 
 
gt, rid = {}, {}
for f in glob.glob(os.path.join(EVAL_DIR, "expected", "*.json")):
    d = json.load(open(f, encoding="utf-8"))
    gt[d["case_id"]] = d["severity"]
    rid[d["case_id"]] = str(d["rule_id"])
 
n = len(gt)
print(f"Bo du lieu: {n} case\n")
 
for mid in ("low", "medium"):
    k = sum(1 for c in gt if band(RULE_LEVELS[rid[c]], mid) == gt[c])
    lo, hi = wilson(k, n)
    print(f"Baseline (muc 6-7 xep '{mid}'): {k}/{n} = {k/n*100:.1f}%"
          f"   Wilson CI [{lo:.1f}% ; {hi:.1f}%]")
 
print("\nDe so sanh: mo-dun AI (cau hinh A) = 22/33 = 66.7%")
print("            notmythos-8b (cau hinh C) = 11/33 = 33.3%\n")
 
print(f"{'case_id':<20}{'rule':>7}{'level':>7}{'baseline':>10}{'chuan':>9}{'':>6}")
print("-" * 60)
for c in sorted(gt):
    lv = RULE_LEVELS[rid[c]]
    b = band(lv, "low")
    print(f"{c:<20}{rid[c]:>7}{lv:>7}{b:>10}{gt[c]:>9}{'OK' if b == gt[c] else 'sai':>6}")
 