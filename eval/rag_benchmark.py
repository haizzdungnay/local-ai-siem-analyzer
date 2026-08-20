"""
eval/rag_benchmark.py

Do luong chat luong truy xuat RAG (Information Retrieval Metrics):
1. Dataset: 33 evaluated cases.
2. Ground truth mappings:
   - Target Wazuh Rule document (e.g. rule-5503, rule-5710, ...)
   - Target MITRE Technique documents (e.g. mitre-T1110, mitre-T1110.001, mitre-T1562.001, ...)
3. Chi so IR:
   - Hit Rate@k (k = 1, 2, 3, 5, 10)
   - Recall@k (k = 1, 2, 3, 5, 10)
   - Mean Reciprocal Rank (MRR)
   - Ty le doan vuot nguong khoang cach (Pass Rate vs Threshold)
4. Ablation Study:
   - So sanh Corpus 19 doan (cu) vs Kho tri thuc mo rong 56 doan (moi)
   - Ablation theo k: k in [1, 2, 3, 5, 10]
   - Ablation theo nguong khoang cach (Distance Threshold)
"""

import glob
import json
import math
import os
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8")
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(EVAL_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, "ai_module"))

from rag import RuleRAG


def load_eval_cases_and_ground_truth():
    cases_dir = os.path.join(EVAL_DIR, "cases")
    expected_dir = os.path.join(EVAL_DIR, "expected")
    
    cases = []
    for c_path in sorted(glob.glob(os.path.join(cases_dir, "*.json"))):
        cid = os.path.basename(c_path).replace(".json", "")
        e_path = os.path.join(expected_dir, os.path.basename(c_path))
        
        with open(c_path, encoding="utf-8") as f:
            c_data = json.load(f)
        with open(e_path, encoding="utf-8") as f:
            e_data = json.load(f)
            
        rid = str(c_data.get("rule", {}).get("id", ""))
        rdesc = str(c_data.get("rule", {}).get("description", ""))
        mitre_ids = e_data.get("mitre_ids", [])
        
        target_docs = set()
        if rid:
            target_docs.add(f"rule-{rid}")
        for mid in mitre_ids:
            target_docs.add(f"mitre-{mid}")
            
        cases.append({
            "case_id": cid,
            "rule_id": rid,
            "rule_desc": rdesc,
            "query_text": f"Rule {rid}: {rdesc}",
            "mitre_ids": mitre_ids,
            "target_docs": target_docs
        })
    return cases


def evaluate_retrieval(rag_instance, cases, k_list=[1, 2, 3, 5, 10], dist_thresholds=[200, 250, 300, 350, 400, 500]):
    all_query_results = []
    
    for case in cases:
        query_text = case["query_text"]
        q_emb = rag_instance._embed(query_text)
        max_k = max(k_list)
        results = rag_instance.collection.query(
            query_embeddings=[q_emb],
            n_results=min(max_k, rag_instance.collection.count())
        )
        
        retrieved_ids = results["ids"][0]
        distances = results["distances"][0]
        documents = results["documents"][0]
        
        all_query_results.append({
            "case": case,
            "retrieved_ids": retrieved_ids,
            "distances": distances,
            "documents": documents
        })
        
    k_metrics = {}
    for k in k_list:
        hit_count = 0
        total_recall = 0.0
        reciprocal_ranks = []
        valid_cases_count = 0
        
        for item in all_query_results:
            case = item["case"]
            targets = case["target_docs"]
            if not targets:
                continue
            valid_cases_count += 1
            
            top_k_ids = item["retrieved_ids"][:k]
            hits = [doc_id for doc_id in top_k_ids if doc_id in targets]
            
            if hits:
                hit_count += 1
                
            recall = len(hits) / len(targets) if targets else 1.0
            total_recall += recall
            
            rr = 0.0
            for rank, doc_id in enumerate(top_k_ids, start=1):
                if doc_id in targets:
                    rr = 1.0 / rank
                    break
            reciprocal_ranks.append(rr)
            
        hit_rate = (hit_count / valid_cases_count) if valid_cases_count > 0 else 0.0
        mean_recall = (total_recall / valid_cases_count) if valid_cases_count > 0 else 0.0
        mrr = (sum(reciprocal_ranks) / len(reciprocal_ranks)) if reciprocal_ranks else 0.0
        
        k_metrics[k] = {
            "hit_rate": hit_rate,
            "recall": mean_recall,
            "mrr": mrr
        }
        
    thresh_metrics = {}
    for thresh in dist_thresholds:
        total_chunks = 0
        passed_chunks = 0
        query_has_passed = 0
        
        for item in all_query_results:
            dists = item["distances"][:3]
            total_chunks += len(dists)
            passed = [d for d in dists if d <= thresh]
            passed_chunks += len(passed)
            if passed:
                query_has_passed += 1
                
        thresh_metrics[thresh] = {
            "chunk_pass_rate": passed_chunks / total_chunks if total_chunks > 0 else 0.0,
            "query_pass_rate": query_has_passed / len(all_query_results) if all_query_results else 0.0
        }
        
    return k_metrics, thresh_metrics, all_query_results


def main():
    cases = load_eval_cases_and_ground_truth()
    print("=" * 85)
    print("BAO CAO THUC NGHIEM DO LUONG CHAT LUONG TRUY XUAT RAG (IR METRICS & ABLATION)")
    print("=" * 85)
    print(f"So luong canh bao danh gia: {len(cases)}")
    
    print("\nKhoi tao va danh chi muc 2 kho tri thuc RAG...")
    rag_19 = RuleRAG(data_dir="ai_module/rag_data", base_url="http://127.0.0.1:11434")
    rag_19.ensure_indexed()
    
    rag_full = RuleRAG(data_dir="ai_module/rag_data_full", base_url="http://127.0.0.1:11434", persist_subdir="chroma_full")
    rag_full.ensure_indexed()
    
    k_list = [1, 2, 3, 5, 10]
    thresh_list = [200, 250, 300, 350, 400, 500]
    
    metrics_19, thresh_19, _ = evaluate_retrieval(rag_19, cases, k_list, thresh_list)
    metrics_full, thresh_full, results_full = evaluate_retrieval(rag_full, cases, k_list, thresh_list)
    
    print("\n" + "=" * 85)
    print("1. BANG SO SANH CHAT LUONG TRUY XUAT THEO QUY MO KHO VA ABLATION TOP-K")
    print("=" * 85)
    print(f"{'Cau hinh RAG':<32}{'Top-k':>7}{'Hit Rate@k':>14}{'Recall@k':>14}{'MRR':>12}")
    print("-" * 85)
    
    for k in k_list:
        m19 = metrics_19[k]
        print(f"{'Corpus goc (19 doan)':<32}{k:>7}{m19['hit_rate']*100:>13.1f}%{m19['recall']*100:>13.1f}%{m19['mrr']:>12.4f}")
        
    print("-" * 85)
    for k in k_list:
        mfull = metrics_full[k]
        print(f"{'Kho tri thuc mo rong (56 doan)':<32}{k:>7}{mfull['hit_rate']*100:>13.1f}%{mfull['recall']*100:>13.1f}%{mfull['mrr']:>12.4f}")
        
    print("\n" + "=" * 85)
    print("2. ABLATION STUDY: TY LE DOAN VUOT NGUONG KHOANG CACH (THRESHOLD PASS RATE @ TOP-3)")
    print("=" * 85)
    print(f"{'Nguong khoang cach (L2^2)':<30}{'Ty le doan lot qua (19)':>25}{'Ty le doan lot qua (56)':>25}")
    print("-" * 85)
    for thresh in thresh_list:
        p19 = thresh_19[thresh]["chunk_pass_rate"] * 100
        pfull = thresh_full[thresh]["chunk_pass_rate"] * 100
        print(f"Threshold <= {thresh:<20}{p19:>24.1f}%{pfull:>24.1f}%")
        
    print("\n" + "=" * 85)
    print("3. PHAN TICH DINH LUONG: NGUYEN NHAN RAG ANH HUONG TOI DIEM ANH XA MITRE")
    print("=" * 85)
    print("Doi chieu chi tiet 33 case thuc nghiem:")
    print("  a) Do phu quy tac Wazuh trong Corpus 19 doan:")
    print(f"     - Hit Rate@1 cua Corpus 19 doan chi dat {metrics_19[1]['hit_rate']*100:.1f}%, Recall@3 chi dat {metrics_19[3]['recall']*100:.1f}%.")
    print("     - Do thieu luat trong kho, RAG tra ve cac doan khong lien quan (Dist > 300) gay nhieu context (Context Distraction).")
    print(f"  b) Cai thien khi mo rong kho tri thuc (56 doan):")
    print(f"     - Hit Rate@3 tang tu {metrics_19[3]['hit_rate']*100:.1f}% -> {metrics_full[3]['hit_rate']*100:.1f}%.")
    print(f"     - Recall@3 tang tu {metrics_19[3]['recall']*100:.1f}% -> {metrics_full[3]['recall']*100:.1f}%.")
    print(f"     - MRR tang tu {metrics_19[3]['mrr']:.4f} -> {metrics_full[3]['mrr']:.4f}.")
    print()


if __name__ == "__main__":
    main()