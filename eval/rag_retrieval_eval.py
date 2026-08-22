"""
Do chat luong khau TRUY XUAT cua RAG tren bo 33 case danh gia.

Muc dich: bo sung chi so cho muc 5 phan bien - hien bao cao moi do khau SINH
(diem chat luong dien giai), chua do khau TRUY XUAT.

Script KHONG goi LLM, chi goi embedding + truy van ChromaDB nen chay rat nhanh.

Chay tu thu muc goc repo:
    python eval/rag_retrieval_eval.py

Yeu cau: Ollama dang chay (de tao embedding), kho tri thuc da duoc danh chi muc.
"""

import glob
import json
import os
import statistics
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(REPO_ROOT, "eval")
sys.path.insert(0, os.path.join(REPO_ROOT, "ai_module"))

from rag import RuleRAG                      # noqa: E402
from reader import load_config, resolve_config_paths  # noqa: E402

TOP_K_VALUES = [1, 3, 5, 10]
THRESHOLDS = [0.5, 0.8, 1.0, 1.2, 1.5]
BIG_DISTANCE = 999.0   # coi nhu khong loc, de dem so ket qua tho


def load_cases():
    """Doc rule.id va rule.description tu eval/cases/*.json."""
    cases = []
    for path in sorted(glob.glob(os.path.join(EVAL_DIR, "cases", "*.json"))):
        with open(path, encoding="utf-8") as f:
            alert = json.load(f)
        rule = alert.get("rule", {}) if isinstance(alert, dict) else {}
        cases.append({
            "case_id": os.path.splitext(os.path.basename(path))[0],
            "rule_id": str(rule.get("id", "")),
            "description": str(rule.get("description", "")),
        })
    return cases


def main():
    cfg = resolve_config_paths(load_config())
    rag_cfg = cfg.get("rag", {}) or {}
    rag = RuleRAG(
        data_dir=rag_cfg.get("data_dir", os.path.join(REPO_ROOT, "ai_module", "rag_data")),
        embedding_model=rag_cfg.get("embedding_model", "nomic-embed-text"),
        base_url=cfg["ollama"]["base_url"],
    )
    indexed = rag.ensure_indexed()
    print(f"Kho tri thuc: da danh chi muc, {indexed} tai lieu moi trong lan chay nay")
    try:
        total_docs = rag.collection.count()
        print(f"Tong so tai lieu trong kho: {total_docs}")
    except Exception:
        pass

    cases = load_cases()
    if not cases:
        print("\nKHONG doc duoc eval/cases/*.json - kiem tra lai duong dan.")
        return
    n = len(cases)
    print(f"So case: {n}\n")

    # ---------- 1. Cau hinh dang dung: top_k = 3, nguong = 1.0 ----------
    print("=" * 78)
    print("1. CAU HINH DANG DUNG TRONG DE TAI  (top_k = 3, nguong khoang cach = 1.0)")
    print("=" * 78)

    rows = []
    for c in cases:
        raw = rag.query(c["rule_id"], c["description"], top_k=3, max_distance=BIG_DISTANCE)
        kept = [r for r in raw if r["distance"] <= 1.0]
        rows.append({
            "case_id": c["case_id"],
            "rule_id": c["rule_id"],
            "n_raw": len(raw),
            "n_kept": len(kept),
            "best": min((r["distance"] for r in raw), default=None),
            "sources": [r["source"] for r in kept],
        })

    hit = sum(1 for r in rows if r["n_kept"] > 0)
    miss = n - hit
    total_raw = sum(r["n_raw"] for r in rows)
    total_kept = sum(r["n_kept"] for r in rows)

    print(f"  Case truy xuat duoc it nhat 1 tai lieu : {hit}/{n} = {hit/n*100:.1f}%   <-- HIT RATE")
    print(f"  Case KHONG truy xuat duoc gi           : {miss}/{n} = {miss/n*100:.1f}%")
    print(f"     -> o {miss} case nay, cau hinh A chay Y HET cau hinh B")
    print()
    print(f"  Tong ket qua tho (truoc nguong)  : {total_raw}")
    print(f"  Tong ket qua giu lai (sau nguong): {total_kept}")
    if total_raw:
        print(f"  Ty le bi nguong loc bo           : {(total_raw-total_kept)/total_raw*100:.1f}%")
    print(f"  So tai lieu trung binh moi truy van: {total_kept/n:.2f}")

    dists = [r["best"] for r in rows if r["best"] is not None]
    if dists:
        print()
        print(f"  Khoang cach gan nhat - nho nhat : {min(dists):.4f}")
        print(f"  Khoang cach gan nhat - trung vi : {statistics.median(dists):.4f}")
        print(f"  Khoang cach gan nhat - lon nhat : {max(dists):.4f}")

    # ---------- 2. Ablation ----------
    print()
    print("=" * 78)
    print("2. ABLATION: hit rate (%) theo top_k va nguong khoang cach")
    print("=" * 78)
    cache = {}
    for k in TOP_K_VALUES:
        cache[k] = [rag.query(c["rule_id"], c["description"], top_k=k,
                              max_distance=BIG_DISTANCE) for c in cases]

    header = "  nguong \\ top_k " + "".join(f"{k:>8}" for k in TOP_K_VALUES)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for th in THRESHOLDS:
        line = f"  {th:>13.1f} "
        for k in TOP_K_VALUES:
            h = sum(1 for raw in cache[k] if any(r["distance"] <= th for r in raw))
            line += f"{h/n*100:>7.1f}%"
        print(line)
    print()
    print("  (Cau hinh de tai dang dung: top_k = 3, nguong = 1.0)")

    # ---------- 3. Chi tiet tung case ----------
    print()
    print("=" * 78)
    print("3. CHI TIET TUNG CASE  (top_k = 3, nguong = 1.0)")
    print("=" * 78)
    print(f"  {'case_id':<20}{'rule':>7}{'tho':>5}{'giu':>5}{'gan nhat':>10}  nguon")
    print("  " + "-" * 72)
    for r in rows:
        best = f"{r['best']:.4f}" if r["best"] is not None else "-"
        src = ",".join(r["sources"]) if r["sources"] else "(khong co)"
        print(f"  {r['case_id']:<20}{r['rule_id']:>7}{r['n_raw']:>5}{r['n_kept']:>5}{best:>10}  {src}")

    # ---------- 4. Xuat CSV ----------
    out = os.path.join(EVAL_DIR, "rag-retrieval-metrics.csv")
    with open(out, "w", encoding="utf-8", newline="") as f:
        f.write("case_id,rule_id,n_raw,n_kept,best_distance,sources\n")
        for r in rows:
            best = f"{r['best']:.6f}" if r["best"] is not None else ""
            f.write(f"{r['case_id']},{r['rule_id']},{r['n_raw']},{r['n_kept']},"
                    f"{best},\"{';'.join(r['sources'])}\"\n")
    print(f"\nDa ghi chi tiet ra: {out}")


if __name__ == "__main__":
    main()