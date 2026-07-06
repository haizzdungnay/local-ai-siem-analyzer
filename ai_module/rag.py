"""rag.py — RAG: tra cứu mô tả rule Wazuh + MITRE ATT&CK.

Index rule descriptions + MITRE bằng embedding local → ChromaDB.
Alert đến → tra rule liên quan → nhét vào LLM context.
Stub: cấu trúc sẵn, chưa chạy thật. Implement ở GĐ3.
"""
from pathlib import Path


class RuleRAG:
    """RAG đơn giản cho rule Wazuh + MITRE."""

    def __init__(self, data_dir: str = "rag_data", embedding_model: str = "nomic-embed-text"):
        self.data_dir = Path(data_dir)
        self.embedding_model = embedding_model
        self.collection = None  # ChromaDB collection, init khi index()

    def index(self):
        """Index rule descriptions + MITRE vào ChromaDB.

        Nguồn:
          - rag_data/wazuh_rules.json   (trích từ ruleset/rules/*.xml)
          - rag_data/mitre_techniques.json

        ponytail: dùng ChromaDB persistent. Nâng lên FAISS khi > 10k docs.
        """
        # TODO: implement
        # 1. Load JSON files từ data_dir
        # 2. Embed bằng Ollama (nomic-embed-text)
        # 3. Upsert vào ChromaDB
        raise NotImplementedError("RAG index chưa implement")

    def query(self, rule_id: str, description: str, top_k: int = 3) -> list[dict]:
        """Tra cứu context liên quan cho 1 alert.

        Args:
            rule_id: Wazuh rule ID (vd "5712")
            description: rule description text
            top_k: số doc trả về

        Returns:
            list of {source, text, score}
        """
        # TODO: implement
        # 1. Embed query text
        # 2. Search ChromaDB
        # 3. Return top_k results
        raise NotImplementedError("RAG query chưa implement")

    def format_context(self, results: list[dict]) -> str:
        """Format RAG results thành text nhét vào prompt LLM."""
        lines = []
        for r in results:
            lines.append(f"[{r.get('source', '?')}] {r.get('text', '')}")
        return "\n".join(lines)
