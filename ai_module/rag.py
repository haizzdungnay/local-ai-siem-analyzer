"""rag.py — RAG: tra cứu mô tả rule Wazuh + MITRE ATT&CK.

Index rule descriptions + MITRE bằng embedding local (qua Ollama) → ChromaDB.
Alert đến → tra rule liên quan → nhét vào LLM context.

Dữ liệu nguồn cần chuẩn bị trong data_dir (vd rag_data/):
  - wazuh_rules.json        : [{"id": "5503", "description": "..."}, ...]
  - mitre_techniques.json   : [{"id": "T1110", "name": "...", "description": "...", "tactic": "..."}, ...]
"""
import json
from pathlib import Path

import chromadb
import ollama as ollama_sdk


class RuleRAG:
    """RAG đơn giản cho rule Wazuh + MITRE, dùng ChromaDB persistent local."""

    def __init__(self, data_dir: str = "rag_data", embedding_model: str = "nomic-embed-text",
                 base_url: str = "http://localhost:11434", persist_subdir: str = "chroma",
                 timeout: float = 120):
        self.data_dir = Path(data_dir)
        self.embedding_model = embedding_model
        self.ollama_client = ollama_sdk.Client(host=base_url, timeout=timeout)

        persist_path = self.data_dir / persist_subdir
        persist_path.mkdir(parents=True, exist_ok=True)
        self.chroma_client = chromadb.PersistentClient(path=str(persist_path))
        self.collection = self.chroma_client.get_or_create_collection("wazuh_rules_mitre")

    def ensure_indexed(self) -> int:
        """Index dữ liệu nguồn khi collection chưa có document nào."""
        if self.collection.count() > 0:
            return 0
        return self.index()

    def _embed(self, text: str) -> list:
        resp = self.ollama_client.embeddings(model=self.embedding_model, prompt=text)
        return resp["embedding"]

    def index(self) -> int:
        """Index rule descriptions + MITRE vào ChromaDB. Chạy lại khi data đổi.

        Returns:
            số document đã index
        """
        docs, metadatas, ids = [], [], []

        rules_path = self.data_dir / "wazuh_rules.json"
        if rules_path.exists():
            rules = json.loads(rules_path.read_text(encoding="utf-8"))
            for r in rules:
                text = f"Rule {r.get('id')}: {r.get('description', '')}"
                docs.append(text)
                metadatas.append({"source": "wazuh_rule", "rule_id": str(r.get("id", ""))})
                ids.append(f"rule-{r.get('id')}")

        mitre_path = self.data_dir / "mitre_techniques.json"
        if mitre_path.exists():
            techniques = json.loads(mitre_path.read_text(encoding="utf-8"))
            for t in techniques:
                text = f"MITRE {t.get('id')} ({t.get('name')}): {t.get('description', '')}"
                docs.append(text)
                metadatas.append({"source": "mitre", "technique_id": str(t.get("id", ""))})
                ids.append(f"mitre-{t.get('id')}")

        if not docs:
            raise FileNotFoundError(
                f"Không tìm thấy dữ liệu index trong {self.data_dir}. "
                "Cần wazuh_rules.json và/hoặc mitre_techniques.json."
            )

        embeddings = [self._embed(d) for d in docs]
        self.collection.upsert(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)
        return len(docs)

    def query(self, rule_id: str, description: str, top_k: int = 3) -> list:
        """Tra cứu context liên quan cho 1 rule/behavior.

        Args:
            rule_id: Wazuh rule ID (vd "5503")
            description: rule description hoặc mô tả hành vi
            top_k: số doc trả về

        Returns:
            list of {source, text, score}
        """
        query_text = f"Rule {rule_id}: {description}"
        query_embedding = self._embed(query_text)
        results = self.collection.query(query_embeddings=[query_embedding], n_results=top_k)

        output = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]
        for doc, meta, dist in zip(docs, metas, dists):
            output.append({"source": meta.get("source", "?"), "text": doc, "score": dist})
        return output

    def format_context(self, results: list) -> str:
        """Format RAG results thành text nhét vào prompt LLM."""
        if not results:
            return ""
        lines = []
        for r in results:
            lines.append(f"[{r.get('source', '?')}] {r.get('text', '')}")
        return "\n".join(lines)
