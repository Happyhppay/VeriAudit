# VeriAudit - RAG: Query interface
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .chunker import ASTChunker, CodeChunk
from .vector_store import VectorStore


class RAGQuery:
    """
    High-level RAG query interface used by Static Scan Agent.
    Provides:
    - semantic search for similar code patterns
    - finding context enrichment
    - project-wide pattern matching
    """

    def __init__(self, vector_store: VectorStore, chunker: ASTChunker):
        self._store = vector_store
        self._chunker = chunker

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Semantic search across the indexed codebase."""
        return self._store.search_similar(query, top_k=top_k)

    def find_similar_to_finding(self, finding: Dict[str, Any],
                                 top_k: int = 5) -> List[Dict[str, Any]]:
        """Find code patterns similar to a finding's vulnerable code."""
        return self._store.find_similar_patterns(finding, top_k=top_k)

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a finding with context from the codebase.
        Finds similar patterns and adds them to the finding.
        """
        similar = self.find_similar_to_finding(finding, top_k=3)
        finding["similar_patterns"] = [
            {"file": s["file_path"], "function": s["function_name"],
             "distance": s["distance"]} for s in similar
        ]
        return finding

    def index_project(self, repo_path: str, language: str,
                       file_extensions: List[str]) -> int:
        """
        Index an entire project for RAG queries.

        Returns:
            Number of chunks indexed.
        """
        chunks = self._chunker.chunk_project(repo_path, language, file_extensions)
        return self._store.index_chunks(chunks)

    def security_search(self, vulnerability_type: str,
                         top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Search for patterns that match a vulnerability type.
        e.g. vulnerability_type="sql-injection" searches for SQL query construction patterns.
        """
        vuln_queries = {
            "sql-injection": "string concatenation in SQL query execute",
            "command-injection": "shell command execution with user input",
            "path-traversal": "file path constructed from user input",
            "hardcoded-secret": "password secret key token hardcoded string",
            "xss": "innerHTML dangerouslySetInnerHTML user input to HTML",
            "ssrf": "user-controlled URL HTTP request fetch",
            "deserialization": "unserialize pickle yaml.load ObjectInputStream",
            "memory-corruption": "memcpy strcpy sprintf malloc without bounds check",
        }
        query = vuln_queries.get(vulnerability_type, vulnerability_type)
        return self.search(query, top_k=top_k)
