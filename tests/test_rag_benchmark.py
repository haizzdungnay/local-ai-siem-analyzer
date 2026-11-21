import os, sys, json, pytest, urllib.request, urllib.error
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(ROOT, "eval")
sys.path.insert(0, os.path.join(ROOT, "ai_module"))
sys.path.insert(0, EVAL_DIR)

import rag_retrieval_eval


def test_legacy_semantic_metrics_deduplicate_section_hits():
    import rag_benchmark

    class Collection:
        def count(self):
            return 3

        def semantic_query(self, text, top_k):
            return {"ids": [["mitre-T1110", "mitre-T1110:detection:0", "mitre-T1110:mitigations:0"]],
                    "distances": [[0.1, 0.2, 0.3]], "documents": [["one", "two", "three"]]}

    instance = Collection()
    instance.collection = instance
    metrics, _, _ = rag_benchmark.evaluate_retrieval(
        instance, [{"query_text": "synthetic", "target_docs": {"mitre-T1110"}}],
        k_list=[3], dist_thresholds=[1.0],
    )
    assert metrics[3]["recall"] == 1.0


def test_development_retrieval_metrics_count_missing_targets_and_failures():
    cases = rag_retrieval_eval.load_cases()

    class RAG:
        indexed_document_ids = ["rule-5712", "mitre-T1110", "mitre-T1110:detection:0", "mitre-T1110.001"]

        def query(self, rule_id, description, **kwargs):
            if rule_id == "999999" and not kwargs["mitre_ids"]:
                raise RuntimeError("do not persist exception detail")
            refs = [key for key in self.indexed_document_ids if key.startswith("mitre-T1110")]
            return [{"document_id": key} for key in refs], {"status": "used", "references": []}

    report = rag_retrieval_eval.evaluate_retrieval(RAG(), cases, k_values=(10,))
    hybrid = report["hybrid"]
    assert hybrid["metrics"][10]["cases"] == 5
    assert hybrid["metrics"][10]["error_count"] == 1
    unknown = next(row for row in hybrid["per_case"] if row["case_id"] == "development-unknown-rule")
    assert unknown["target_coverage"] == 0.5
    assert unknown["recall"] == 0.5
    assert unknown["context_recall"] == 0.0
    assert "do not persist" not in json.dumps(report)


def test_development_freeze_is_offline_sanitized_and_exclusive(tmp_path, monkeypatch):
    import yaml

    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "ollama": {"model": "qwen2.5:7b", "base_url": "http://localhost:11434"},
        "wazuh_indexer": {"password": "PRIVATE_CONFIG_SENTINEL"},
        "rag": {"enabled": True, "data_dir": str(Path(ROOT) / "ai_module/rag_data"),
                "embedding_model": "nomic-embed-text"},
        "extractor": {"fields": ["rule.id"]},
    }), encoding="utf-8")
    monkeypatch.setattr(rag_retrieval_eval, "RuleRAG", lambda **kwargs: pytest.fail("offline snapshot called RAG"))
    output = tmp_path / "new-snapshot.json"
    args = ["--config", str(config), "--freeze-only", "--output", str(output)]
    rag_retrieval_eval.main(args)
    saved = output.read_bytes()
    report = json.loads(saved)
    assert report["formal_baseline_ready"] is False
    assert report["held_out"]["version"] == "pending-independent-review"
    assert report["generator_model"] == "qwen2.5:7b"
    assert report["embedding_model_digest"] == ""
    assert "PRIVATE_CONFIG_SENTINEL" not in saved.decode("utf-8")
    assert "localhost" not in saved.decode("utf-8")
    assert len(report["protocol"]["sha256"]) == 64
    with pytest.raises(FileExistsError):
        rag_retrieval_eval.main(args)
    assert output.read_bytes() == saved


def test_benchmarks_use_separate_temporary_stores(tmp_path, monkeypatch):
    import rag_benchmark
    stores = []

    class FakeRAG:
        collection = None

        def __init__(self, data_dir, *, persist_dir, in_memory, **kwargs):
            assert in_memory is True
            self.store = Path(persist_dir)
            assert not self.store.is_relative_to(Path(data_dir).resolve())
            self.store.mkdir(parents=True, exist_ok=True)
            stores.append(self.store)
            self.collection = self
            self.ollama_client = object()

        def count(self):
            return 1

        def ensure_indexed(self):
            return 1

        def manifest_metadata(self):
            return {"embedding_model_digest": "mock"}

        def close(self):
            assert self.store.is_dir()

    monkeypatch.setattr(rag_retrieval_eval, "RuleRAG", FakeRAG)
    monkeypatch.setattr(rag_retrieval_eval, "load_config", lambda path: {
        "ollama": {"base_url": "http://localhost:11434"},
        "rag": {"data_dir": str(tmp_path / "corpus"), "embedding_model": "embed"},
    })
    monkeypatch.setattr(rag_retrieval_eval, "snapshot", lambda *args, **kwargs: {})
    monkeypatch.setattr(rag_retrieval_eval, "evaluate_retrieval", lambda *args, **kwargs: {})
    rag_retrieval_eval.main(["--output", str(tmp_path / "development.json")])
    assert len(stores) == 1 and not stores[0].exists()

    monkeypatch.setattr(rag_benchmark, "RuleRAG", FakeRAG)
    monkeypatch.setattr(rag_benchmark, "load_eval_cases_and_ground_truth", lambda: [])
    monkeypatch.setattr(rag_benchmark, "evaluate_retrieval", lambda *args, **kwargs: (
        {k: {"hit_rate": 0, "recall": 0, "mrr": 0} for k in args[2]},
        {t: {"chunk_pass_rate": 0, "query_pass_rate": 0} for t in args[3]}, [],
    ))
    monkeypatch.setattr(sys, "argv", ["rag_benchmark.py", "--output", str(tmp_path / "legacy.json")])
    rag_benchmark.main()
    assert len(set(stores)) == 3 and not any(store.exists() for store in stores)


def _ollama_reachable() -> bool:
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/tags",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2):
            return True
    except (urllib.error.URLError, OSError):
        return False

def test_full_knowledge_base_integrity():
    kb_path = os.path.join(ROOT, "ai_module", "rag_data_full")
    wazuh_rules_file = os.path.join(kb_path, "wazuh_rules.json")
    mitre_tech_file = os.path.join(kb_path, "mitre_techniques.json")
    
    assert os.path.exists(wazuh_rules_file)
    assert os.path.exists(mitre_tech_file)
    
    with open(wazuh_rules_file, encoding="utf-8") as f:
        rules = json.load(f)
    with open(mitre_tech_file, encoding="utf-8") as f:
        techs = json.load(f)
        
    assert len(rules) >= 20
    assert len(techs) >= 25
    assert all("id" in r and "description" in r for r in rules)
    assert all("id" in t and "name" in t and "tactic" in t for t in techs)

def test_rag_benchmark_script_runs(tmp_path):
    if os.environ.get("SIEM_RUN_LIVE_RAG_BENCHMARK") != "1":
        pytest.skip("Live legacy benchmark requires explicit opt-in")
    if not _ollama_reachable():
        pytest.skip("Ollama not running on localhost:11434")

    chroma_mod = sys.modules.get("chromadb")
    if chroma_mod is None or getattr(chroma_mod, "__file__", None) is None:
        pytest.skip("chromadb not installed")

    import subprocess
    env = os.environ.copy()
    env["NO_PROXY"] = "localhost,127.0.0.1"
    env["HTTP_PROXY"] = ""
    env["HTTPS_PROXY"] = ""
    env["PYTHONPATH"] = os.path.join(ROOT, "ai_module") + os.pathsep + env.get("PYTHONPATH", "")
    res = subprocess.run([sys.executable, os.path.join(EVAL_DIR, "rag_benchmark.py"),
                          "--output", str(tmp_path / "rag-benchmark.json")],
                         capture_output=True, text=True, env=env)
    assert res.returncode == 0
    assert "Hit Rate@k" in res.stdout
    assert "Recall@k" in res.stdout
    assert "MRR" in res.stdout
