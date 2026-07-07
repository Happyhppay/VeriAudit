# VeriAudit - RAG: Vector Store (ChromaDB)
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .chunker import CodeChunk


class VectorStore:
    """
    ChromaDB wrapper for semantic code search.
    Stores code chunks as embeddings and supports similarity queries.
    """

    def __init__(self, persist_dir: str = "./workspace/chroma",
                 collection_name: str = "veriaudit_code"):
        self._persist_dir = persist_dir
        self._collection_name = collection_name
        self._client = None
        self._collection = None

    def _ensure_client(self):
        """Lazy-init ChromaDB client."""
        if self._client is not None:
            return
        try:
            import chromadb
            self._client = chromadb.PersistentClient(path=self._persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata={"hnsw:space": "cosine"},
            )
        except ImportError:
            pass

    def index_chunks(self, chunks: List[CodeChunk]) -> int:
        """
        Index code chunks into the vector store.

        Returns:
            Number of chunks indexed.
        """
        self._ensure_client()
        if not self._collection or not chunks:
            return 0

        ids = []
        documents = []
        metadatas = []

        for c in chunks:
            ids.append(c.chunk_id)
            documents.append(f"{c.function_name}\n{c.code}")
            metadatas.append({
                "file_path": c.file_path,
                "function_name": c.function_name,
                "start_line": c.start_line,
                "end_line": c.end_line,
                "language": c.language,
            })

        # Add in batches of 100
        batch_size = 100
        for i in range(0, len(ids), batch_size):
            self._collection.add(
                ids=ids[i:i + batch_size],
                documents=documents[i:i + batch_size],
                metadatas=metadatas[i:i + batch_size],
            )

        return len(ids)

    def search_similar(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for code chunks semantically similar to the query.

        Args:
            query: Natural language or code query
            top_k: Number of results to return

        Returns:
            List of {chunk_id, file_path, function_name, code, distance}
        """
        self._ensure_client()
        if not self._collection:
            return []

        results = self._collection.query(
            query_texts=[query],
            n_results=top_k,
        )

        formatted = []
        ids = results.get("ids", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for i in range(len(ids)):
            formatted.append({
                "chunk_id": ids[i],
                "file_path": metadatas[i].get("file_path", "") if i < len(metadatas) else "",
                "function_name": metadatas[i].get("function_name", "") if i < len(metadatas) else "",
                "code": documents[i] if i < len(documents) else "",
                "distance": distances[i] if i < len(distances) else 1.0,
            })

        return formatted

    def find_similar_patterns(self, finding: Dict[str, Any],
                               top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Find code chunks with similar patterns to a finding.
        Uses the finding's code_snippet and message as the query.
        """
        code_snippet = finding.get("code_snippet", "")
        message = finding.get("message", "")
        query = f"{message}\n{code_snippet}"

        return self.search_similar(query, top_k=top_k)

    def delete_collection(self):
        """Delete the current collection (for re-indexing)."""
        self._ensure_client()
        if self._client and self._collection:
            self._client.delete_collection(self._collection_name)
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata={"hnsw:space": "cosine"},
            )
