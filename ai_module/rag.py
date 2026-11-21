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
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import Lock
from uuid import uuid4

import chromadb
import ollama as ollama_sdk

from extractor import MITRE_TECHNIQUE_ID, normalize_mitre_ids


MODULE_DIR = Path(__file__).resolve().parent
MAX_TOP_K = 10
INDEX_SCHEMA_VERSION = 3
CORPUS_FORMAT_VERSION = "rule-mitre-sections-v3"
RETRIEVAL_POLICY_VERSION = "exact-semantic-v2"
MANIFEST_FILENAME = "index_manifest.json"
DEFAULT_RELEVANCE_THRESHOLD = 1.0
MAX_CONTEXT_DOCUMENT_CHARS = 2000
MAX_CONTEXT_CHARS = 12000
MAX_SECTION_CHUNKS = 3
MODEL_LIST_LOOKUP_LIMIT = 128
MODEL_DIGEST_RE = re.compile(r"^[A-Za-z0-9:+._-]{1,256}$")
VERIFIED_EMBEDDING_SOURCE = "ollama.Client.list.pre_post_index"


class EmbeddingIdentityError(RuntimeError):
    """Ollama could not confirm the embedding model for this generation."""


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


def _knowledge_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(filter(None, (_knowledge_text(item) for item in value)))
    if isinstance(value, dict):
        return "; ".join(f"{key}: {_knowledge_text(item)}" for key, item in value.items() if item)
    return str(value).strip()


def reference_metadata(result: dict) -> dict:
    """Content-free provenance shared by alert, window and evaluation outputs."""
    output = {key: _safe_reference_id(result[key]) for key in (
        "source", "reference_id", "source_file", "section", "record_sha256", "corpus_version",
        "corpus_digest", "retrieval_method", "lookup_basis",
    ) if key in result}
    if "document_id" in result:
        output["document_id"] = re.sub(r"[^A-Za-z0-9._:-]+", "_", result["document_id"])[:192]
    if "fields" in result:
        output["fields"] = re.sub(r"[^A-Za-z0-9._,:-]+", "_", str(result["fields"]))[:256]
    if "chunk" in result:
        output["chunk"] = int(result["chunk"])
    if "section_truncated" in result:
        output["section_truncated"] = bool(result["section_truncated"])
    if result.get("mapped_mitre_ids"):
        output["mapped_mitre_ids"] = result["mapped_mitre_ids"]
    distance = result.get("distance")
    output["distance"] = None if distance is None else _validated_distance(distance, "distance")
    return output


def render_reference(result: dict, remaining: int):
    """Render a complete chunk so its field provenance still describes the prompt."""
    text = _safe_context_text(result.get("text", "")).strip()
    if not text:
        return None
    metadata = reference_metadata(result)
    source = metadata.get("source", "unknown")
    ref_id = metadata.get("reference_id", "")
    fields = " ".join(f"{key}={value}" for key, value in metadata.items()
                      if key not in {"source", "reference_id", "mapped_mitre_ids"} and value is not None)
    row = f"[REFERENCE source={source} id={ref_id} {fields}] {text}"
    return (row, {**metadata, "rendered_text_chars": len(text)}) if len(row) <= remaining else None


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
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", source_id.strip()):
            raise ValueError(f"{path}: item[{index}].id không hợp lệ")
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
                 relevance_threshold: float = DEFAULT_RELEVANCE_THRESHOLD, *,
                 persist_dir: str | Path | None = None, in_memory: bool = False):
        if in_memory and persist_dir is None:
            raise ValueError("An in-memory index requires a separate manifest directory")
        self.data_dir = Path(data_dir).resolve()
        self.embedding_model = embedding_model
        self.relevance_threshold = _validated_distance(
            relevance_threshold, "relevance_threshold"
        )
        self.ollama_client = ollama_sdk.Client(host=base_url, timeout=timeout)

        persist_path = self.data_dir / persist_subdir if persist_dir is None else Path(persist_dir).resolve()
        persist_path.mkdir(parents=True, exist_ok=True)
        self.persist_path = persist_path
        self.manifest_path = persist_path / MANIFEST_FILENAME
        self.chroma_client = (chromadb.EphemeralClient() if in_memory else
                              chromadb.PersistentClient(path=str(persist_path)))
        self._build_lock = Lock()
        try:
            self._generation = self._published_generation()
        except Exception:
            with suppress(Exception):
                self.close()
            raise

    def close(self) -> None:
        try:
            self.chroma_client.close()
        finally:
            close_ollama = getattr(self.ollama_client, "close", None)
            if callable(close_ollama):
                close_ollama()

    def semantic_query(self, text: str, top_k: int) -> dict:
        """Return raw Chroma ranks for semantic-only benchmarks."""
        generation = self._generation
        if generation is None:
            raise RuntimeError("No compatible RAG index is available")
        return self._semantic_query(text, top_k, generation)

    @property
    def collection(self):
        generation = self._generation
        return generation[1] if generation else None

    @property
    def collection_name(self) -> str:
        return self.manifest_metadata().get("collection_name", "")

    @property
    def indexed_document_ids(self) -> tuple[str, ...]:
        generation = self._generation
        return tuple(generation[0]["document_ids"]) if generation else ()

    def ensure_indexed(self) -> int:
        """Build a new index generation, then atomically activate its manifest."""
        with self._build_lock:
            corpus = self._load_build_corpus()
            generation = self._published_generation()
            self._generation = generation
            manifest = self._manifest_for(corpus)
            if generation and all(generation[0].get(key) == manifest[key] for key in (
                "schema_version", "corpus_digest", "embedding_schema_digest", "document_ids",
                "embedding_model_digest_source",
            )):
                return 0
            return self._index_corpus(corpus, manifest)

    def _load_build_corpus(self) -> dict:
        try:
            return self._load_corpus()
        except FileNotFoundError:
            # Do not serve a removed corpus or mutate a generation used by other readers.
            self._generation = None
            raise

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
            and math.isfinite(value) for value in embedding
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

        def append_sections(document_id, record, metadata, sections):
            metadata = {**metadata, "corpus_version": CORPUS_FORMAT_VERSION,
                        "record_sha256": _canonical_sha256(record)}
            for section, pieces in sections:
                content, spans = "", []
                for field, piece in pieces:
                    start = len(content)
                    content += piece
                    if field and piece:
                        spans.append((field, start, len(content)))
                if not content:
                    continue
                header = "" if section == "overview" else f"{document_id} {section}: "
                size = MAX_CONTEXT_DOCUMENT_CHARS - len(header)
                # ponytail: at most 3 chunks/section; add ranked subchunks if real retrieval needs longer records.
                for number, start in enumerate(range(0, min(len(content), size * MAX_SECTION_CHUNKS), size)):
                    chunk_id = document_id if section == "overview" and number == 0 else f"{document_id}:{section}:{number}"
                    stop = start + size
                    docs.append(header + _safe_context_text(content[start:stop]))
                    chunk_meta = {**metadata, "document_id": chunk_id, "section": section,
                                  "fields": ",".join(field for field, begin, end in spans
                                                     if begin < stop and end > start),
                                  "chunk": number, "section_truncated": len(content) > size * MAX_SECTION_CHUNKS}
                    for field, begin, end in spans:
                        if field == "mitre" and begin < stop and end > start:
                            offset = begin
                            included = []
                            for value in content[begin:end].split("; "):
                                if offset >= start and offset + len(value) <= stop and MITRE_TECHNIQUE_ID.fullmatch(value):
                                    included.append(value)
                                offset += len(value) + 2
                            chunk_meta["visible_mitre_ids"] = json.dumps(included)
                    metadatas.append(chunk_meta)
                    ids.append(chunk_id)

        for document_id, rule in rules:
            rule_id = document_id.removeprefix("rule-")
            mapping = rule.get("mitre")
            if mapping is not None and (not isinstance(mapping, list) or any(
                not isinstance(item, str) or not item.strip() for item in mapping
            )):
                raise ValueError(f"Rule {rule_id}: mitre must be a list of non-empty strings")
            overview = [(None, f"Rule {rule_id}: "), ("description", _knowledge_text(rule.get("description")))]
            for field in ("mitre", "level", "groups", "frequency", "timeframe", "if_sid", "if_matched_sid", "file", "text"):
                value = _knowledge_text(rule.get(field))
                if value:
                    overview.extend([(None, f"\n{field}: "), (field, value)])
            append_sections(document_id, rule, {
                "source": "wazuh_rule", "rule_id": rule_id, "source_file": rules_path.name,
                "mitre_ids": json.dumps(normalize_mitre_ids(mapping)),
            }, [("overview", overview)])

        for document_id, technique in techniques:
            technique_id = document_id.removeprefix("mitre-")
            overview = [(None, f"MITRE {technique_id} ("), ("name", _knowledge_text(technique.get("name"))), (None, ")")]
            for field in ("tactics", "tactic", "subtechnique_of"):
                value = _knowledge_text(technique.get(field))
                if value:
                    overview.extend([(None, f"\n{field}: "), (field, value)])
            description_field = "description" if technique.get("description") else "text"
            overview.extend([(None, ": "), (description_field, _knowledge_text(technique.get(description_field)))])
            mitigation_field = "mitigation_details" if technique.get("mitigation_details") else "mitigations"
            append_sections(document_id, technique, {
                "source": "mitre", "technique_id": technique_id, "source_file": mitre_path.name,
            }, [("overview", overview), ("detection", [("detection", _knowledge_text(technique.get("detection")))]),
                ("mitigations", [(mitigation_field, _knowledge_text(technique.get(mitigation_field)))])])

        if not docs:
            raise FileNotFoundError(
                f"No RAG index sources found in {self.data_dir}; expected "
                "wazuh_rules.json and/or mitre_techniques.json."
            )
        return {"ids": ids, "documents": docs, "metadatas": metadatas}

    def _embedding_model_digest_metadata(self) -> tuple[str, str]:
        """Look up the configured tag, including Ollama's implicit :latest."""
        try:
            listing = self.ollama_client.list()
            models = listing.get("models", []) if isinstance(listing, dict) else getattr(listing, "models", [])
            if not isinstance(models, (list, tuple)):
                return "", ""
            requested = self.embedding_model
            if ":" not in requested.rsplit("/", 1)[-1]:
                requested += ":latest"
            for item in models[:MODEL_LIST_LOOKUP_LIMIT]:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("model")
                    digest = item.get("digest")
                else:
                    name = getattr(item, "name", None) or getattr(item, "model", None)
                    digest = getattr(item, "digest", None)
                if not isinstance(name, str):
                    continue
                listed = name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"
                if listed == requested and isinstance(digest, str) and MODEL_DIGEST_RE.fullmatch(digest):
                    observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    return digest, observed_at
        except Exception:
            pass
        return "", ""

    def _manifest_for(self, corpus: dict) -> dict:
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
        model_digest, _ = self._embedding_model_digest_metadata()
        if not model_digest:
            raise EmbeddingIdentityError("Embedding model digest unavailable before build")
        embedding_schema_digest = _canonical_sha256({
            "schema_version": INDEX_SCHEMA_VERSION,
            "corpus_version": CORPUS_FORMAT_VERSION,
            "document_chars": MAX_CONTEXT_DOCUMENT_CHARS,
            "section_chunks": MAX_SECTION_CHUNKS,
            "embedding_model": self.embedding_model,
            "embedding_model_digest": model_digest,
        })
        return {
            "schema_version": INDEX_SCHEMA_VERSION,
            "corpus_version": CORPUS_FORMAT_VERSION,
            "embedding_model": self.embedding_model,
            "embedding_model_digest": model_digest,
            "embedding_model_digest_source": VERIFIED_EMBEDDING_SOURCE,
            "document_count": len(corpus["ids"]),
            "document_ids": [record["id"] for record in records],
            "corpus_digest": corpus_digest,
            "corpus_sha256": corpus_digest,
            "embedding_schema_digest": embedding_schema_digest,
            "embedding_schema_sha256": embedding_schema_digest,
        }

    def _read_manifest(self) -> dict | None:
        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def manifest_metadata(self) -> dict:
        """Return only non-content index identity needed for analysis provenance."""
        generation = self._generation
        return self._index_metadata(generation[0]) if generation else {}

    @staticmethod
    def _index_metadata(manifest: dict) -> dict:
        return {
            key: manifest.get(key, "")
            for key in (
                "schema_version", "corpus_version", "embedding_model", "document_count",
                "embedding_model_digest", "embedding_model_digest_source",
                "embedding_model_digest_observed_at", "collection_name",
                "corpus_digest", "embedding_schema_digest",
            )
        }

    def _write_manifest(self, manifest: dict) -> None:
        temporary_path = None
        try:
            with NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=self.persist_path,
                                    prefix=".manifest-", suffix=".tmp", delete=False) as handle:
                temporary_path = Path(handle.name)
                json.dump(manifest, handle, ensure_ascii=True, sort_keys=True, indent=2)
                handle.write("\n")
            temporary_path.replace(self.manifest_path)
        finally:
            if temporary_path is not None:
                with suppress(OSError):
                    temporary_path.unlink(missing_ok=True)

    def _published_generation(self):
        manifest = self._read_manifest()
        if not manifest or (manifest.get("schema_version"), manifest.get("corpus_version"),
                            manifest.get("embedding_model"), manifest.get("embedding_model_digest_source")) != (
            INDEX_SCHEMA_VERSION, CORPUS_FORMAT_VERSION, self.embedding_model, VERIFIED_EMBEDDING_SOURCE,
        ):
            return None
        name, ids = manifest.get("collection_name"), manifest.get("document_ids")
        digest = manifest.get("embedding_model_digest")
        if (not isinstance(name, str) or not re.fullmatch(r"wazuh-rag-[0-9a-f]{32}", name)
                or not isinstance(digest, str) or not MODEL_DIGEST_RE.fullmatch(digest)
                or not isinstance(ids, list) or not ids or not all(isinstance(key, str) for key in ids)
                or len(set(ids)) != manifest.get("document_count") or len(set(ids)) != len(ids)):
            return None
        try:
            collection = self.chroma_client.get_collection(name)
        except chromadb.errors.NotFoundError:
            return None
        if not self._has_ids(collection, ids):
            return None
        return manifest, collection

    @staticmethod
    def _has_ids(collection, expected: list[str]) -> bool:
        stored = collection.get(include=[])["ids"]
        return isinstance(stored, list) and len(stored) == len(expected) and set(stored) == set(expected)

    def _require_embedding_identity(self, expected_digest: str) -> str:
        digest, observed_at = self._embedding_model_digest_metadata()
        if not expected_digest or digest != expected_digest:
            raise EmbeddingIdentityError("Embedding model digest differs or is unavailable")
        return observed_at

    def _semantic_query(self, text: str, top_k: int, generation) -> dict:
        manifest, collection = generation
        digest = manifest["embedding_model_digest"]
        self._require_embedding_identity(digest)
        embedding = self._embed(text)
        self._require_embedding_identity(digest)
        return collection.query(query_embeddings=[embedding], n_results=top_k)

    def _index_corpus(self, corpus: dict, manifest: dict) -> int:
        ids = corpus["ids"]
        batch_size = self.chroma_client.get_max_batch_size()
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
            raise ValueError("Invalid Chroma batch size")
        digest = manifest["embedding_model_digest"]
        self._require_embedding_identity(digest)
        staging_name = f"wazuh-rag-{uuid4().hex}"
        staging_collection = self.chroma_client.create_collection(staging_name)
        try:
            for start in range(0, len(ids), batch_size):
                stop = start + batch_size
                documents = corpus["documents"][start:stop]
                embeddings = []
                for document in documents:
                    embeddings.append(self._embed(document))
                    self._require_embedding_identity(digest)
                staging_collection.upsert(ids=ids[start:stop], documents=documents,
                                          embeddings=embeddings, metadatas=corpus["metadatas"][start:stop])
            if not self._has_ids(staging_collection, ids):
                raise RuntimeError("Staging index is incomplete; active generation unchanged")
            manifest = {**manifest, "collection_name": staging_name,
                        "embedding_model_digest_observed_at": self._require_embedding_identity(digest)}
            self._write_manifest(manifest)
        except Exception:
            with suppress(Exception):
                self.chroma_client.delete_collection(staging_name)
            raise
        self._generation = manifest, staging_collection
        return len(ids)

    def index(self) -> int:
        """Index the current corpus and update its persistence manifest."""
        with self._build_lock:
            corpus = self._load_build_corpus()
            return self._index_corpus(corpus, self._manifest_for(corpus))

    def query(self, rule_id: str, description: str, top_k: int = 3,
              max_distance: float | None = None, *, mitre_ids=None,
              include_provenance: bool = False, exact_lookup: bool = True):
        """Exact IDs first, then thresholded semantic evidence; top_k bounds all chunks."""
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= MAX_TOP_K:
            raise ValueError(f"top_k phải là số nguyên trong khoảng 1..{MAX_TOP_K}")
        if not isinstance(rule_id, str) or not isinstance(description, str):
            raise ValueError("rule_id and description must be strings")
        if not isinstance(exact_lookup, bool):
            raise ValueError("exact_lookup must be a boolean")
        if mitre_ids is None:
            mitre_ids = []
        if (not isinstance(mitre_ids, list) or len(mitre_ids) > MAX_TOP_K
                or any(not isinstance(mid, str) or not MITRE_TECHNIQUE_ID.fullmatch(mid)
                       for mid in mitre_ids)):
            raise ValueError("mitre_ids must contain at most 10 MITRE technique IDs")
        threshold = self.relevance_threshold if max_distance is None else _validated_distance(
            max_distance, "max_distance"
        )
        generation = self._generation
        if generation is None:
            raise RuntimeError("No compatible RAG index is available")
        manifest, collection = generation
        provenance = {"status": "no_match", "exact_count": 0, "semantic_count": 0,
                      "filtered_count": 0, "top_k": top_k, "max_distance": threshold,
                      "policy_version": RETRIEVAL_POLICY_VERSION,
                      "exact_lookup": exact_lookup,
                      "index": self._index_metadata(manifest)}
        output, seen = [], set()

        def add(document, metadata, distance, method, lookup_basis=None):
            if not isinstance(document, str) or not isinstance(metadata, dict):
                raise ValueError("Chroma response contains invalid document/metadata")
            reference_id = metadata.get("rule_id", metadata.get("technique_id", ""))
            document_id = metadata.get("document_id") or (
                ("rule-" if metadata.get("source") == "wazuh_rule" else "mitre-") + str(reference_id)
            )
            if document_id in seen or len(output) >= top_k:
                return
            seen.add(document_id)
            result = {"source": str(metadata.get("source", "?")),
                      "reference_id": _safe_reference_id(reference_id), "text": document,
                      "distance": distance, "document_id": document_id,
                      "retrieval_method": method, "corpus_digest": manifest.get("corpus_digest", "")}
            result.update({key: metadata[key] for key in (
                "source_file", "section", "record_sha256", "corpus_version", "fields", "chunk", "section_truncated",
            ) if key in metadata})
            if lookup_basis:
                result["lookup_basis"] = lookup_basis
            if "visible_mitre_ids" in metadata:
                result["mapped_mitre_ids"] = normalize_mitre_ids(json.loads(metadata["visible_mitre_ids"]))
            output.append(result)

        def exact_rows(response):
            if not isinstance(response, dict):
                raise ValueError("Invalid Chroma get response")
            docs, metas = response.get("documents"), response.get("metadatas")
            if not isinstance(docs, list) or not isinstance(metas, list) or len(docs) != len(metas):
                raise ValueError("Invalid Chroma get columns")
            if any(not isinstance(doc, str) or not isinstance(meta, dict) for doc, meta in zip(docs, metas)):
                raise ValueError("Invalid Chroma get rows")
            return list(zip(docs, metas))

        root = f"rule-{rule_id}"
        rule_ids = [root] + [key for key in manifest.get("document_ids", []) if key.startswith(root + ":")]
        rules = exact_rows(collection.get(ids=rule_ids, include=["documents", "metadatas"])) if rule_id and exact_lookup else []
        rules.sort(key=lambda row: row[1].get("chunk", 0))
        techniques = list(dict.fromkeys(mitre_ids))
        for document, metadata in rules:
            if not metadata.get("chunk", 0):
                add(document, metadata, None, "exact_rule")
            mapped = json.loads(metadata.get("mitre_ids", "[]"))
            if not isinstance(mapped, list):
                raise ValueError("Invalid indexed MITRE mapping")
            techniques.extend(mid for mid in normalize_mitre_ids(mapped) if mid not in techniques)
        techniques = techniques[:MAX_TOP_K]
        if techniques and exact_lookup:
            rows = exact_rows(collection.get(where={"technique_id": {"$in": techniques}},
                                                  include=["documents", "metadatas"]))
            section_order = {"overview": 0, "detection": 1, "mitigations": 2}
            rows.sort(key=lambda row: (row[1].get("chunk", 0) > 0,
                                      section_order.get(row[1].get("section"), 3),
                                      row[1].get("chunk", 0),
                                      techniques.index(row[1]["technique_id"])))
            for document, metadata in rows:
                basis = "alert_annotation" if metadata["technique_id"] in mitre_ids else "kb_mapping"
                add(document, metadata, None, "exact_mitre", basis)
        for document, metadata in rules:
            add(document, metadata, None, "exact_rule")
        provenance["exact_count"] = len(output)
        try:
            query_text = f"Rule {rule_id[:128]}: {description[:1000]}"
            results = self._semantic_query(query_text, top_k, generation)
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
            for doc, meta, dist in zip(docs, metas, dists):
                distance = _validated_distance(dist, "Chroma query response distance")
                if not isinstance(doc, str) or not isinstance(meta, dict):
                    raise ValueError("Chroma query response chứa dữ liệu sai kiểu")
                if distance > threshold:
                    provenance["filtered_count"] += 1
                else:
                    add(doc, meta, distance, "semantic")
            provenance["status"] = "used" if output else (
                "filtered_out" if provenance["filtered_count"] else "no_match"
            )
        except Exception as exc:
            if not output:
                raise
            provenance.update(status="partial", error_type=type(exc).__name__)
        provenance["semantic_count"] = len(output) - provenance["exact_count"]
        context, references = self._render_context(output)
        provenance["references"] = references
        provenance["context_chars"] = len(context)
        provenance["context_truncated"] = len(references) < len(output)
        return (output, provenance) if include_provenance else output

    def format_context(self, results: list) -> str:
        """Bound context, keeping section/index provenance beside untrusted text."""
        return self._render_context(results)[0]

    @staticmethod
    def _render_context(results: list) -> tuple[str, list[dict]]:
        lines, references, remaining = [], [], MAX_CONTEXT_CHARS
        for result in results[:MAX_TOP_K]:
            rendered = render_reference(result, remaining - bool(lines))
            if rendered:
                row, reference = rendered
                remaining -= len(row) + bool(lines)
                lines.append(row)
                references.append(reference)
        return "\n".join(lines), references
