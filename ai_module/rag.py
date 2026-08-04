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


MODULE_DIR = Path(__file__).resolve().parent
MAX_TOP_K = 10


def _load_source(path: Path, prefix: str) -> list[tuple[str, dict]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path}: JSON top-level phải là list")

    records = []
    seen_ids = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: item[{index}] phải là object")
        source_id = item.get("id")
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError(f"{path}: item[{index}].id phải là string không rỗng")
        document_id = f"{prefix}-{source_id.strip()}"
        if document_id in seen_ids:
            raise ValueError(f"{path}: duplicate id {source_id.strip()!r}")
        seen_ids.add(document_id)
        records.append((document_id, item))
    return records


class RuleRAG:
    """RAG đơn giản cho rule Wazuh + MITRE, dùng ChromaDB persistent local."""

    def __init__(self, data_dir: str | Path = MODULE_DIR / "rag_data",
                 embedding_model: str = "nomic-embed-text",
                 base_url: str = "http://localhost:11434", persist_subdir: str = "chroma",
                 timeout: float = 120):
        self.data_dir = Path(data_dir).resolve()
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
        if isinstance(resp, dict):
            embedding = resp.get("embedding")
        else:
            try:
                embedding = resp["embedding"]
            except (KeyError, TypeError, AttributeError):
                embedding = getattr(resp, "embedding", None)
        if not isinstance(embedding, list) or not embedding or not all(
            not isinstance(value, bool) and isinstance(value, (int, float))
            for value in embedding
        ):
            raise ValueError("Ollama embedding response không hợp lệ")
        return embedding

    def index(self) -> int:
        """Index rule descriptions + MITRE vào ChromaDB. Chạy lại khi data đổi.

        Returns:
            số document đã index
        """
        docs, metadatas, ids = [], [], []

        rules_path = self.data_dir / "wazuh_rules.json"
        rules = _load_source(rules_path, "rule") if rules_path.exists() else []
        mitre_path = self.data_dir / "mitre_techniques.json"
        techniques = _load_source(mitre_path, "mitre") if mitre_path.exists() else []

        for document_id, rule in rules:
            rule_id = document_id.removeprefix("rule-")
            docs.append(f"Rule {rule_id}: {rule.get('description', '')}")
            metadatas.append({"source": "wazuh_rule", "rule_id": rule_id})
            ids.append(document_id)

        for document_id, technique in techniques:
            technique_id = document_id.removeprefix("mitre-")
            docs.append(
                f"MITRE {technique_id} ({technique.get('name')}): "
                f"{technique.get('description', '')}"
            )
            metadatas.append({"source": "mitre", "technique_id": technique_id})
            ids.append(document_id)

        if not docs:
            raise FileNotFoundError(
                f"Không tìm thấy dữ liệu index trong {self.data_dir}. "
                "Cần wazuh_rules.json và/hoặc mitre_techniques.json."
            )

        embeddings = [self._embed(d) for d in docs]
        self.collection.upsert(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)
        return len(docs)

    def query(self, rule_id: str, description: str, top_k: int = 3) -> list:
        """Tra cứu context liên quan cho 1 rule/behavior."""
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= MAX_TOP_K:
            raise ValueError(f"top_k phải là số nguyên trong khoảng 1..{MAX_TOP_K}")

        query_text = f"Rule {rule_id}: {description}"
        query_embedding = self._embed(query_text)
        results = self.collection.query(query_embeddings=[query_embedding], n_results=top_k)
        if not isinstance(results, dict):
            raise ValueError("Chroma query response không hợp lệ")

        columns = []
        for key in ("documents", "metadatas", "distances"):
            value = results.get(key)
            if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], list):
                raise ValueError(f"Chroma query response thiếu {key}[0]")
            columns.append(value[0])
        docs, metas, dists = columns
        if not (len(docs) == len(metas) == len(dists)):
            raise ValueError("Chroma query response có số phần tử không khớp")

        output = []
        for doc, meta, dist in zip(docs, metas, dists):
            if not isinstance(doc, str) or not isinstance(meta, dict):
                raise ValueError("Chroma query response chứa dữ liệu sai kiểu")
            if isinstance(dist, bool) or not isinstance(dist, (int, float)):
                raise ValueError("Chroma query response chứa distance sai kiểu")
            output.append({"source": str(meta.get("source", "?")), "text": doc, "score": dist})
        return output

    def format_context(self, results: list) -> str:
        """Format RAG results thành text nhét vào prompt LLM."""
        if not results:
            return ""
        lines = []
        for r in results:
            lines.append(f"[{r.get('source', '?')}] {r.get('text', '')}")
        return "\n".join(lines)
