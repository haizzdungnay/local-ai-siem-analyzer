import json
import sys

import extractor
import llm
import main
import rag
import reader


def test_load_config_reads_utf8_on_windows(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        '# Cấu hình tiếng Việt — dấu ngoặc “cong”\nextractor:\n  fields: []\n',
        encoding="utf-8",
    )

    assert extractor.load_config(config_path)["extractor"]["fields"] == []


def test_format_for_llm_keeps_mitre_technique():
    text = extractor.format_for_llm(
        {
            "rule.mitre.id": ["T1110"],
            "rule.mitre.tactic": ["Credential Access"],
            "rule.mitre.technique": ["Brute Force"],
        }
    )

    assert "T1110" in text
    assert "Credential Access" in text
    assert "Brute Force" in text


def test_parse_response_falls_back_for_non_object_json():
    result = llm._parse_response("[]")

    assert result["severity"] == "unknown"
    assert "JSON object" in result["root_cause"]


def test_analyze_alert_forwards_timeout_to_ollama(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def chat(self, **kwargs):
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "summary",
                            "root_cause": "cause",
                            "severity": "low",
                            "mitre": "",
                            "next_steps": [],
                        }
                    )
                }
            }

    monkeypatch.setattr(llm.ollama_sdk, "Client", FakeClient)

    llm.analyze_alert("alert", timeout=9)

    assert captured == {"host": "http://localhost:11434", "timeout": 9}


def test_fetch_alerts_api_uses_configured_timeout(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"hits": {"hits": [{"_source": {"rule": {"id": "5503"}}}]}}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr(reader.requests, "post", fake_post)
    cfg = {
        "wazuh": {"protocol": "https"},
        "wazuh_indexer": {
            "host": "192.168.100.10",
            "port": 9200,
            "user": "admin",
            "password": "secret",
            "verify_ssl": False,
            "timeout": 17,
        },
    }

    alerts = reader.fetch_alerts_api(cfg, limit=1)

    assert alerts[0]["rule"]["id"] == "5503"
    assert captured["timeout"] == 17


def test_get_wazuh_token_uses_configured_timeout(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"data": {"token": "jwt-token"}}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr(reader.requests, "post", fake_post)
    cfg = {
        "wazuh": {
            "protocol": "https",
            "host": "192.168.100.10",
            "port": 55000,
            "user": "wazuh-wui",
            "password": "secret",
            "verify_ssl": False,
            "timeout": 11,
        }
    }

    assert reader.get_wazuh_token(cfg) == "jwt-token"
    assert captured["timeout"] == 11


def test_rule_rag_indexes_only_when_collection_is_empty(monkeypatch, tmp_path):
    class FakeCollection:
        def __init__(self):
            self.document_count = 0

        def count(self):
            return self.document_count

    collection = FakeCollection()

    class FakeChromaClient:
        def get_or_create_collection(self, name):
            return collection

    ollama_kwargs = {}

    def fake_ollama_client(**kwargs):
        ollama_kwargs.update(kwargs)
        return object()

    monkeypatch.setattr(rag.chromadb, "PersistentClient", lambda path: FakeChromaClient())
    monkeypatch.setattr(rag.ollama_sdk, "Client", fake_ollama_client)

    rule_rag = rag.RuleRAG(data_dir=str(tmp_path), timeout=13)
    indexed = []

    def fake_index():
        indexed.append(True)
        return 19

    monkeypatch.setattr(rule_rag, "index", fake_index)

    assert rule_rag.ensure_indexed() == 19
    collection.document_count = 19
    assert rule_rag.ensure_indexed() == 0
    assert indexed == [True]
    assert ollama_kwargs["timeout"] == 13


def test_main_initializes_rag_index_and_passes_timeout(monkeypatch):
    cfg = {
        "ollama": {
            "base_url": "http://localhost:11434",
            "model": "qwen2.5:3b",
            "timeout": 23,
        },
        "wazuh_indexer": {"host": "192.168.100.10", "port": 9200},
        "extractor": {"fields": []},
        "rag": {
            "enabled": True,
            "data_dir": "rag_data",
            "embedding_model": "nomic-embed-text",
        },
    }
    instances = []
    analyze_kwargs = {}

    class FakeRAG:
        def __init__(self, **kwargs):
            self.init_kwargs = kwargs
            self.ensure_calls = 0
            instances.append(self)

        def ensure_indexed(self):
            self.ensure_calls += 1
            return 19

        def query(self, rule_id, description):
            return []

        def format_context(self, results):
            return ""

    def fake_analyze_alert(**kwargs):
        analyze_kwargs.update(kwargs)
        return {
            "summary": "summary",
            "root_cause": "cause",
            "severity": "low",
            "mitre": "",
            "next_steps": [],
        }

    monkeypatch.setattr(main, "load_config", lambda path: cfg)
    monkeypatch.setattr(main, "load_sample_alerts", lambda path: [{}])
    monkeypatch.setattr(main, "RuleRAG", FakeRAG)
    monkeypatch.setattr(main, "analyze_alert", fake_analyze_alert)
    monkeypatch.setattr(sys, "argv", ["main.py", "--demo"])

    main.main()

    assert instances[0].ensure_calls == 1
    assert instances[0].init_kwargs["timeout"] == 23
    assert analyze_kwargs["timeout"] == 23
