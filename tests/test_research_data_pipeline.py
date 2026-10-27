"""Offline unit tests for research dataset candidate and RAG exporters."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_starter_rag_export(tmp_path):
    builder = load("research_rag", "research/rag/build_rag_corpus.py")
    result = builder.build("starter", tmp_path)
    assert result["wazuh_rules_count"] > 0
    assert result["mitre_techniques_count"] > 0
    data = json.loads((tmp_path / "mitre_techniques.json").read_text(encoding="utf-8"))
    assert all(x.get("id") and x.get("description") for x in data)


def test_stix_parser_filters_deprecated_and_non_technique():
    builder = load("research_rag", "research/rag/build_rag_corpus.py")
    fake = {"objects": [
        {"type": "attack-pattern", "name": "Sample", "description": "Description",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}]},
        {"type": "attack-pattern", "name": "Old", "revoked": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1120"}]},
        {"type": "malware", "name": "Tool", "external_references": []},
    ]}
    out = builder.extract_mitre(fake)
    assert [x["id"] for x in out] == ["T1110"]


def test_log_candidates_are_unlabeled_and_scrubbed(tmp_path):
    module = load("candidate_converter", "research/datasets/prepare_log_candidates.py")
    inp, out = tmp_path / "source.jsonl", tmp_path / "candidates.jsonl"
    inp.write_text(
        json.dumps({"EventID": 1, "Message": "Connection 192.168.1.5 password=secret123"}, ensure_ascii=False)
        + "\nnot-json\n", encoding="utf-8"
    )
    result = module.convert(inp, out, "test-splunk", "scenario-1", 10)
    assert result["candidates"] == 1
    assert result["malformed_or_non_object"] == 1
    obj = json.loads(out.read_text(encoding="utf-8"))
    assert obj["train_ready"] is False
    assert obj["severity"] is None
    assert "secret123" not in str(obj)
    assert "192.168.1.5" not in str(obj)
