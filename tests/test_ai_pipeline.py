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
        '# Cấu hình tiếng Việt — dấu ngoặc “cong”\n'
        'ollama: {}\nwazuh_indexer: {}\nextractor:\n  fields: []\n',
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


def test_parse_response_rejects_invalid_schema():
    invalid = {
        "summary": "summary",
        "root_cause": "cause",
        "severity": "urgent",
        "mitre": "",
        "next_steps": "not-a-list",
    }

    result = llm._parse_response(json.dumps(invalid))

    assert result["severity"] == "unknown"


def test_fetch_alerts_api_rejects_bad_limit():
    cfg = {"wazuh_indexer": {}}

    for limit in (0, -1, 51):
        try:
            reader.fetch_alerts_api(cfg, limit=limit)
        except ValueError as exc:
            assert "1..50" in str(exc)
        else:
            raise AssertionError(f"limit {limit} phải bị từ chối")


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


def test_fetch_alerts_api_rejects_malformed_hits(monkeypatch):
    class FakeResponse:
        def __init__(self, hits):
            self.hits = hits

        def raise_for_status(self):
            return None

        def json(self):
            return {"hits": {"hits": self.hits}}

    cfg = {
        "wazuh_indexer": {
            "host": "192.168.100.10", "port": 9200,
            "user": "admin", "password": "secret", "verify_ssl": False,
        }
    }
    invalid = [
        ([None], "hits.hits[0] phải là object"),
        ([{}], "hits.hits[0]._source phải là object"),
        ([{"_source": "bad"}], "hits.hits[0]._source phải là object"),
    ]

    for hits, message in invalid:
        monkeypatch.setattr(reader.requests, "post", lambda *args, hits=hits, **kwargs: FakeResponse(hits))
        try:
            reader.fetch_alerts_api(cfg, limit=1)
        except ValueError as exc:
            assert message in str(exc)
        else:
            raise AssertionError(f"Malformed hits phải bị từ chối: {hits}")


def test_fetch_alerts_api_preserves_valid_hit_order(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"hits": {"hits": [
                {"_source": {"rule": {"id": "5503"}}},
                {"_source": {"rule": {"id": "5760"}}},
            ]}}

    monkeypatch.setattr(reader.requests, "post", lambda *args, **kwargs: FakeResponse())
    cfg = {
        "wazuh_indexer": {
            "host": "192.168.100.10", "port": 9200,
            "user": "admin", "password": "secret", "verify_ssl": False,
        }
    }

    alerts = reader.fetch_alerts_api(cfg, limit=2)

    assert [alert["rule"]["id"] for alert in alerts] == ["5503", "5760"]


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


def test_rule_rag_rejects_invalid_source_before_embedding(monkeypatch, tmp_path):
    class FakeCollection:
        def upsert(self, **kwargs):
            raise AssertionError("upsert không được gọi")

    class FakeChromaClient:
        def get_or_create_collection(self, name):
            return FakeCollection()

    monkeypatch.setattr(rag.chromadb, "PersistentClient", lambda path: FakeChromaClient())
    monkeypatch.setattr(rag.ollama_sdk, "Client", lambda **kwargs: object())
    (tmp_path / "wazuh_rules.json").write_text(
        json.dumps({"id": "5503"}), encoding="utf-8"
    )
    rule_rag = rag.RuleRAG(data_dir=tmp_path)
    monkeypatch.setattr(
        rule_rag, "_embed", lambda text: (_ for _ in ()).throw(AssertionError("embed không được gọi"))
    )

    try:
        rule_rag.index()
    except ValueError as exc:
        assert "top-level phải là list" in str(exc)
    else:
        raise AssertionError("JSON object phải bị từ chối")


def test_rule_rag_rejects_bad_items_and_ids(tmp_path):
    source = tmp_path / "source.json"
    invalid_cases = [
        (["bad"], "item[0] phải là object"),
        ([{}], "item[0].id phải là string không rỗng"),
        ([{"id": "  "}], "item[0].id phải là string không rỗng"),
        ([{"id": "5503"}, {"id": "5503"}], "duplicate id '5503'"),
    ]

    for payload, message in invalid_cases:
        source.write_text(json.dumps(payload), encoding="utf-8")
        try:
            rag._load_source(source, "rule")
        except ValueError as exc:
            assert message in str(exc)
        else:
            raise AssertionError(f"Payload phải bị từ chối: {payload}")


def test_rule_rag_rejects_duplicate_mitre_id(tmp_path):
    source = tmp_path / "mitre_techniques.json"
    source.write_text(json.dumps([{"id": "T1110"}, {"id": "T1110"}]), encoding="utf-8")

    try:
        rag._load_source(source, "mitre")
    except ValueError as exc:
        assert "duplicate id 'T1110'" in str(exc)
    else:
        raise AssertionError("Duplicate MITRE ID phải bị từ chối")


def test_rule_rag_indexes_valid_sources(monkeypatch, tmp_path):
    captured = {}

    class FakeCollection:
        def upsert(self, **kwargs):
            captured.update(kwargs)

    class FakeChromaClient:
        def get_or_create_collection(self, name):
            return FakeCollection()

    monkeypatch.setattr(rag.chromadb, "PersistentClient", lambda path: FakeChromaClient())
    monkeypatch.setattr(rag.ollama_sdk, "Client", lambda **kwargs: object())
    (tmp_path / "wazuh_rules.json").write_text(
        json.dumps([{"id": "5503", "description": "PAM failed"}]), encoding="utf-8"
    )
    (tmp_path / "mitre_techniques.json").write_text(
        json.dumps([{"id": "T1110", "name": "Brute Force", "description": "Guessing"}]),
        encoding="utf-8",
    )
    rule_rag = rag.RuleRAG(data_dir=tmp_path)
    monkeypatch.setattr(rule_rag, "_embed", lambda text: [1.0])

    assert rule_rag.index() == 2
    assert captured["ids"] == ["rule-5503", "mitre-T1110"]
    assert captured["metadatas"] == [
        {"source": "wazuh_rule", "rule_id": "5503"},
        {"source": "mitre", "technique_id": "T1110"},
    ]


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


def test_configure_console_encoding_uses_utf8(monkeypatch):
    calls = []

    class FakeStream:
        def reconfigure(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(main.sys, "stdout", FakeStream())
    monkeypatch.setattr(main.sys, "stderr", FakeStream())

    main._configure_console_encoding()

    assert calls == [
        {"encoding": "utf-8", "errors": "replace"},
        {"encoding": "utf-8", "errors": "replace"},
    ]


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
