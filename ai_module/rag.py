"""rag.py — RAG: tra cứu mô tả rule Wazuh + MITRE ATT&CK.

Index rule descriptions + MITRE bằng embedding local (qua Ollama) → ChromaDB.
Alert đến → tra rule liên quan → nhét vào LLM context.

Dữ liệu nguồn cần chuẩn bị trong data_dir (vd rag_data/):
  - wazuh_rules.json        : [{"id": "5503", "description": "..."}, ...]
  - mitre_techniques.json   : [{"id": "T1110", "name": "...", "description": "...", "tactic": "..."}, ...]
"""
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path

import chromadb
import ollama as ollama_sdk


MODULE_DIR = Path(__file__).resolve().parent
MAX_TOP_K = 10
INDEX_SCHEMA_VERSION = 1
MANIFEST_FILENAME = "index_manifest.json"
DEFAULT_RELEVANCE_THRESHOLD = 1.0
MAX_CONTEXT_DOCUMENT_CHARS = 2000
BASE_COLLECTION_NAME = "wazuh_rules_mitre"
MODEL_LIST_LOOKUP_LIMIT = 128
MODEL_DIGEST_RE = re.compile(r"^[A-Za-z0-9:+._-]{1,256}$")


def _canonical_sha256(value: object) -> str:
    """Hash structured index inputs deterministically."""
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validated_distance(value, field: str) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0):
        raise ValueError(f"{field} must be a non-negative number")
    return float(value)


def _safe_reference_id(value) -> str:
    """Keep identifiers useful without letting them alter prompt structure."""
    return re.sub(r"[^A-Za-z0-9._:-]+", "_", str(value))[:128]


def _safe_context_text(value) -> str:
    """Bound local corpus text before it becomes untrusted LLM evidence."""
    text = str(value).replace("\x00", " ")
    text = "".join(char if char.isprintable() or char in "\n\t" else " " for char in text)
    return text[:MAX_CONTEXT_DOCUMENT_CHARS]


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
                 timeout: float = 120,
                 relevance_threshold: float = DEFAULT_RELEVANCE_THRESHOLD):
        self.data_dir = Path(data_dir).resolve()
        self.embedding_model = embedding_model
        self.relevance_threshold = _validated_distance(
            relevance_threshold, "relevance_threshold"
        )
        self.ollama_client = ollama_sdk.Client(host=base_url, timeout=timeout)

        persist_path = self.data_dir / persist_subdir
        persist_path.mkdir(parents=True, exist_ok=True)
        self.persist_path = persist_path
        self.manifest_path = persist_path / MANIFEST_FILENAME
        self.chroma_client = chromadb.PersistentClient(path=str(persist_path))
        manifest = self._read_manifest()
        self.collection_name = self._collection_name_from_manifest(manifest)
        self.collection = self.chroma_client.get_or_create_collection(self.collection_name)

    def ensure_indexed(self) -> int:
        """Build a new index generation, then atomically activate its manifest."""
        try:
            corpus = self._load_corpus()
        except FileNotFoundError:
            # Never serve an old index after all configured source files were removed.
            self._delete_document_ids(self._known_document_ids())
            self._remove_manifest()
            raise
        previous = self._read_manifest()
        # Keep index() as the first-build seam used by the CLI and integrations.
        # It still creates a generation collection before activating its manifest.
        if previous is None:
            return self.index()
        manifest = self._manifest_for(corpus, previous=previous)
        if self._is_fresh(manifest):
            return 0
        return self._index_corpus(corpus, manifest)

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

    def _load_corpus(self) -> dict:
        """Load and validate every source before contacting the embedding service."""
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
                f"No RAG index sources found in {self.data_dir}; expected "
                "wazuh_rules.json and/or mitre_techniques.json."
            )
        return {"ids": ids, "documents": docs, "metadatas": metadatas}

    def _embedding_model_digest_metadata(self) -> tuple[str, str, str]:
        """Observe the embedding model digest without making indexing depend on it."""
        try:
            listing = self.ollama_client.list()
            models = listing.get("models", []) if isinstance(listing, dict) else getattr(listing, "models", [])
            if not isinstance(models, (list, tuple)):
                return "", "", ""
            for item in models[:MODEL_LIST_LOOKUP_LIMIT]:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("model")
                    digest = item.get("digest")
                else:
                    name = getattr(item, "name", None) or getattr(item, "model", None)
                    digest = getattr(item, "digest", None)
                if name == self.embedding_model and isinstance(digest, str) and MODEL_DIGEST_RE.fullmatch(digest):
                    observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    return digest, "ollama.Client.list.pre_index", observed_at
        except Exception:
            pass
        return "", "", ""

    def _manifest_for(self, corpus: dict, previous: dict | None = None) -> dict:
        records = sorted(
            (
                {"id": document_id, "document": document, "metadata": metadata}
                for document_id, document, metadata in zip(
                    corpus["ids"], corpus["documents"], corpus["metadatas"]
                )
            ),
            key=lambda record: record["id"],
        )
        corpus_digest = _canonical_sha256(records)
        previous = previous if isinstance(previous, dict) else {}
        model_digest, digest_source, digest_observed_at = self._embedding_model_digest_metadata()
        # A transient metadata lookup failure must not churn a known-good index.
        if not model_digest and previous.get("embedding_model") == self.embedding_model:
            model_digest = previous.get("embedding_model_digest", "")
            digest_source = previous.get("embedding_model_digest_source", "")
            digest_observed_at = previous.get("embedding_model_digest_observed_at", "")
        elif model_digest and model_digest == previous.get("embedding_model_digest"):
            digest_source = previous.get("embedding_model_digest_source", digest_source)
            digest_observed_at = previous.get("embedding_model_digest_observed_at", digest_observed_at)
        embedding_schema_digest = _canonical_sha256({
            "schema_version": INDEX_SCHEMA_VERSION,
            "embedding_model": self.embedding_model,
            "embedding_model_digest": model_digest,
        })
        collection_name = f"wazuh-rag-{corpus_digest[:12]}-{embedding_schema_digest[:12]}"
        return {
            "schema_version": INDEX_SCHEMA_VERSION,
            "embedding_model": self.embedding_model,
            "embedding_model_digest": model_digest,
            "embedding_model_digest_source": digest_source,
            "embedding_model_digest_observed_at": digest_observed_at,
            "document_count": len(corpus["ids"]),
            "document_ids": list(corpus["ids"]),
            "collection_name": collection_name,
            "corpus_digest": corpus_digest,
            "corpus_sha256": corpus_digest,
            "embedding_schema_digest": embedding_schema_digest,
            "embedding_schema_sha256": embedding_schema_digest,
        }

    def _read_manifest(self) -> dict | None:
        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def manifest_metadata(self) -> dict:
        """Return only non-content index identity needed for analysis provenance."""
        manifest = self._read_manifest() or {}
        return {
            key: manifest.get(key, "")
            for key in (
                "schema_version", "embedding_model", "document_count",
                "embedding_model_digest", "embedding_model_digest_source",
                "embedding_model_digest_observed_at", "collection_name",
                "corpus_digest", "embedding_schema_digest",
            )
        }

    def _write_manifest(self, manifest: dict) -> None:
        temporary_path = self.manifest_path.with_suffix(".tmp")
        temporary_path.write_text(
            json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        # The manifest is the active-generation pointer. Replacing it happens
        # only after the staging collection contains every document/embedding.
        temporary_path.replace(self.manifest_path)

    def _remove_manifest(self) -> None:
        try:
            self.manifest_path.unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def _collection_name_from_manifest(manifest: dict | None) -> str:
        name = manifest.get("collection_name") if isinstance(manifest, dict) else None
        if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]{3,128}", name):
            return name
        return BASE_COLLECTION_NAME

    def _collection_ids(self, collection=None) -> list[str]:
        getter = getattr(collection or self.collection, "get", None)
        if not callable(getter):
            return []
        try:
            result = getter(include=[])
        except TypeError:
            result = getter()
        if not isinstance(result, dict) or not isinstance(result.get("ids"), list):
            return []
        return [item for item in result["ids"] if isinstance(item, str)]

    def _known_document_ids(self) -> list[str]:
        manifest = self._read_manifest()
        if manifest and isinstance(manifest.get("document_ids"), list):
            return [item for item in manifest["document_ids"] if isinstance(item, str)]
        return self._collection_ids()

    def _delete_document_ids(self, document_ids: list[str], collection=None) -> None:
        if not document_ids:
            return
        deleter = getattr(collection or self.collection, "delete", None)
        if callable(deleter):
            deleter(ids=sorted(set(document_ids)))

    def _is_fresh(self, manifest: dict) -> bool:
        existing = self._read_manifest()
        if existing != manifest:
            return False
        counter = getattr(self.collection, "count", None)
        return callable(counter) and counter() == manifest["document_count"]

    def _index_corpus(self, corpus: dict, manifest: dict) -> int:
        new_ids = set(corpus["ids"])
        # Generate embeddings before mutating a usable index. A failed embedding
        # call therefore leaves the active manifest and collection intact.
        embeddings = [self._embed(document) for document in corpus["documents"]]
        staging_name = self._collection_name_from_manifest(manifest)
        staging_collection = self.chroma_client.get_or_create_collection(staging_name)
        old_staging_ids = set(self._collection_ids(staging_collection))
        staging_collection.upsert(
            ids=corpus["ids"],
            documents=corpus["documents"],
            embeddings=embeddings,
            metadatas=corpus["metadatas"],
        )
        # Upsert replaces changed IDs; explicit deletion removes stale retries in
        # the same staging generation. Earlier generations stay inactive.
        self._delete_document_ids(list(old_staging_ids - new_ids), staging_collection)
        self._write_manifest(manifest)
        self.collection_name = staging_name
        self.collection = staging_collection
        return len(corpus["documents"])

    def index(self) -> int:
        """Index the current corpus and update its persistence manifest."""
        corpus = self._load_corpus()
        return self._index_corpus(corpus, self._manifest_for(corpus))

    def query(self, rule_id: str, description: str, top_k: int = 3,
              max_distance: float | None = None) -> list:
        """Tra cứu context liên quan cho 1 rule/behavior."""
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= MAX_TOP_K:
            raise ValueError(f"top_k phải là số nguyên trong khoảng 1..{MAX_TOP_K}")

        threshold = self.relevance_threshold if max_distance is None else _validated_distance(
            max_distance, "max_distance"
        )
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
            distance = _validated_distance(dist, "Chroma query response distance")
            if distance > threshold:
                continue
            reference_id = meta.get("rule_id", meta.get("technique_id", ""))
            output.append({
                "source": str(meta.get("source", "?")),
                "reference_id": _safe_reference_id(reference_id),
                "text": doc,
                "distance": distance,
            })
        return output

    def format_context(self, results: list) -> str:
        """Format RAG results thành text nhét vào prompt LLM."""
        if not results:
            return ""
        lines = []
        for r in results:
            source = _safe_reference_id(r.get("source", "?")) or "unknown"
            reference_id = _safe_reference_id(r.get("reference_id", ""))
            lines.append(
                f"[REFERENCE source={source} id={reference_id}] "
                f"{_safe_context_text(r.get('text', ''))}"
            )
        return "\n".join(lines)
