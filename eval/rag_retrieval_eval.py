"""R0.3 development retrieval benchmark; see docs/rag-evaluation-protocol.md.

Offline: python eval/rag_retrieval_eval.py --freeze-only --output <new.json>
Live:    python eval/rag_retrieval_eval.py --output <new.json>
No held-out labels, service startup or generation calls. Outputs never overwrite.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_module"))
from llm import SOC_PROMPT_VERSION, build_soc_system_prompt, _model_digest
from playbooks import PLAYBOOK_POLICY_VERSION
from rag import DEFAULT_RELEVANCE_THRESHOLD, CORPUS_FORMAT_VERSION, INDEX_SCHEMA_VERSION, RETRIEVAL_POLICY_VERSION, RuleRAG
from reader import load_config, resolve_config_paths

DEVELOPMENT_CASES = ROOT / "eval/rag_development_cases.json"
TOP_K_VALUES = (1, 3, 5, 10)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_cases(path=DEVELOPMENT_CASES):
    cases = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("Development cases must be a non-empty list")
    seen = set()
    for case in cases:
        if (not isinstance(case, dict) or not isinstance(case.get("case_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", case["case_id"])
                or case["case_id"] in seen
                or not isinstance(case.get("rule_id"), str)
                or not isinstance(case.get("description"), str)
                or not isinstance(case.get("mitre_ids"), list) or len(case["mitre_ids"]) > 10
                or any(not isinstance(mid, str) or not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", mid)
                       for mid in case["mitre_ids"])
                or not isinstance(case.get("targets"), list) or not case["targets"]
                or any(not isinstance(target, str) or not re.fullmatch(r"(?:rule-[0-9]+|mitre-T[0-9]{4}(?:\.[0-9]{3})?)", target)
                       for target in case["targets"])
                or not isinstance(case.get("source"), str)
                or case.get("review_status") != "development-only-not-independent"):
            raise ValueError("Invalid synthetic development case")
        seen.add(case["case_id"])
    return cases


def snapshot(cfg, config_path, *, model="qwen2.5:7b"):
    def git(*args):
        return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    files = ["ai_module/rag.py", "ai_module/analysis_service.py", "ai_module/main.py",
             "ai_module/llm.py", "ai_module/extractor.py", "ai_module/playbooks.py",
             "ai_module/rag_data/playbooks.yaml", "eval/rag_retrieval_eval.py", "eval/rag_benchmark.py", "eval/run_eval.py"]
    corpus_dir = Path(cfg["rag"]["data_dir"])
    return {
        "schema_version": 1, "kind": "development_snapshot", "formal_baseline_ready": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git("rev-parse", "HEAD"), "working_tree_dirty": bool(git("status", "--porcelain")),
        "file_sha256": {name: sha256(ROOT / name) for name in files},
        "config_sha256": sha256(config_path),
        "corpus_sources": {name: sha256(corpus_dir / name) for name in (
            "wazuh_rules.json", "mitre_techniques.json",
        ) if (corpus_dir / name).exists()},
        "corpus_version": CORPUS_FORMAT_VERSION, "index_schema_version": INDEX_SCHEMA_VERSION,
        "retrieval_policy_version": RETRIEVAL_POLICY_VERSION,
        "playbook_policy_version": PLAYBOOK_POLICY_VERSION,
        "prompt_version": SOC_PROMPT_VERSION,
        "prompt_sha256": hashlib.sha256(build_soc_system_prompt("alert", "vi").encode()).hexdigest(),
        "protocol": {"version": "rag-r0.3-v2", "sha256": sha256(ROOT / "docs/rag-evaluation-protocol.md")},
        "development_cases_sha256": sha256(DEVELOPMENT_CASES),
        "held_out": {"version": "pending-independent-review",
                     "existing_lock_sha256": sha256(ROOT / "eval/test_set_lock.json")},
        "generator_model": model, "generator_model_digest": "",
        "embedding_model": cfg["rag"]["embedding_model"], "embedding_model_digest": "",
        "analysis_options_sha256": hashlib.sha256(json.dumps(
            cfg.get("ollama", {}).get("analysis", {}), sort_keys=True,
        ).encode()).hexdigest(),
        "retrieval_config": {"top_k_values": TOP_K_VALUES,
                             "max_distance": cfg["rag"].get("relevance_threshold", DEFAULT_RELEVANCE_THRESHOLD)},
        "limitations": ["Synthetic development data; not independent held-out evidence.",
                        "Final playbook freeze and reviewer agreement pending (#23/#27/#29).",
                        "No generator, Indexer, browser or SOC acceptance implied (#32)."],
    }


def evaluate_retrieval(rag, cases, *, threshold=DEFAULT_RELEVANCE_THRESHOLD, k_values=TOP_K_VALUES):
    available = {key.split(":", 1)[0] for key in rag.indexed_document_ids}
    report = {}
    for hybrid in (False, True):
        rows = []
        for k in k_values:
            for case in cases:
                try:
                    matches, provenance = rag.query(
                        case["rule_id"], case["description"], top_k=k, max_distance=threshold,
                        mitre_ids=case["mitre_ids"], exact_lookup=hybrid, include_provenance=True,
                    )
                    retrieved = list(dict.fromkeys(match["document_id"].split(":", 1)[0] for match in matches))
                    references = provenance["references"]
                except Exception as exc:
                    provenance = {"status": "error", "error_type": type(exc).__name__}
                    retrieved, references = [], []
                targets = set(case["targets"])
                hits = targets.intersection(retrieved)
                context_sources = {ref["document_id"].split(":", 1)[0] for ref in references}
                rows.append({"case_id": case["case_id"], "k": k, "status": provenance["status"],
                             "error_type": provenance.get("error_type", ""),
                             "targets": sorted(targets), "target_coverage": len(targets & available) / len(targets),
                             "retrieved": retrieved, "references": references,
                             "context_recall": len(targets & context_sources) / len(targets),
                             "context_chars": provenance.get("context_chars", 0),
                             "context_truncated": provenance.get("context_truncated", False),
                             "hit": bool(hits), "recall": len(hits) / len(targets),
                             "reciprocal_rank": next((1 / rank for rank, key in enumerate(retrieved, 1)
                                                       if key in targets), 0.0)})
        metrics = {}
        for k in k_values:
            group = [row for row in rows if row["k"] == k]
            metrics[k] = {"cases": len(group), "hit_rate": sum(row["hit"] for row in group) / len(group),
                          "recall": sum(row["recall"] for row in group) / len(group),
                          "context_recall": sum(row["context_recall"] for row in group) / len(group),
                          "mrr": sum(row["reciprocal_rank"] for row in group) / len(group),
                          "target_coverage": sum(row["target_coverage"] for row in group) / len(group),
                          "error_count": sum(row["status"] in {"error", "partial"} for row in group)}
        report["hybrid" if hybrid else "semantic_only"] = {"metrics": metrics, "per_case": rows}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "ai_module/config.yaml")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--freeze-only", action="store_true")
    parser.add_argument("--model", default="qwen2.5:7b", help="Generator identity only; no generation calls")
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError("Output exists; choose a new output path")
    cfg = resolve_config_paths(load_config(args.config))
    cases = load_cases()
    report = snapshot(cfg, args.config, model=args.model)
    if not args.freeze_only:
        threshold = cfg["rag"].get("relevance_threshold", DEFAULT_RELEVANCE_THRESHOLD)
        with TemporaryDirectory(prefix="siem-rag-development-") as store:
            rag = RuleRAG(data_dir=cfg["rag"]["data_dir"], embedding_model=cfg["rag"]["embedding_model"],
                          base_url=cfg["ollama"]["base_url"], timeout=cfg["ollama"].get("timeout", 120),
                          relevance_threshold=threshold, persist_dir=store, in_memory=True)
            try:
                rag.ensure_indexed()
                report.update(kind="development_retrieval", evidence="LIVE_EMBEDDING_SYNTHETIC_DEVELOPMENT",
                              index=rag.manifest_metadata())
                report["embedding_model_digest"] = report["index"]["embedding_model_digest"]
                report["generator_model_digest"] = _model_digest(rag.ollama_client, args.model, args.model)
                report["results"] = evaluate_retrieval(rag, cases, threshold=threshold)
            finally:
                rag.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=True, sort_keys=True, indent=2)
        handle.write("\n")
    print("Saved development snapshot" if args.freeze_only else "Saved development retrieval results")


if __name__ == "__main__":
    main()
