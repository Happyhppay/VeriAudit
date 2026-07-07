# VeriAudit - RAG: Tree-sitter AST chunking
from __future__ import annotations

from typing import Any, Dict, List, Optional


class CodeChunk:
    """A semantically meaningful chunk of code."""
    def __init__(self, chunk_id: str, file_path: str, function_name: str = "",
                 start_line: int = 0, end_line: int = 0,
                 code: str = "", language: str = "", metadata: Dict[str, Any] | None = None):
        self.chunk_id = chunk_id
        self.file_path = file_path
        self.function_name = function_name
        self.start_line = start_line
        self.end_line = end_line
        self.code = code
        self.language = language
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "code": self.code,
            "language": self.language,
            "metadata": self.metadata,
        }


class ASTChunker:
    """
    Semantic code chunker using Tree-sitter AST.
    Splits code by function/class/method boundaries.
    """

    def __init__(self):
        self._parsers: Dict[str, Any] = {}

    def chunk_file(self, file_path: str, language: str) -> List[CodeChunk]:
        """
        Parse a file and return semantic chunks (functions, classes, methods).

        Args:
            file_path: Path to source file
            language: Programming language

        Returns:
            List of CodeChunk objects
        """
        try:
            with open(file_path, encoding='utf-8', errors='ignore') as f:
                source = f.read()
        except Exception:
            return []

        return self.chunk_source(source, file_path, language)

    def chunk_source(self, source: str, file_path: str,
                      language: str) -> List[CodeChunk]:
        """
        Parse source code string and return semantic chunks.
        Falls back to regex-based chunking if tree-sitter is unavailable.
        """
        # Try tree-sitter first
        chunks = self._chunk_with_treesitter(source, file_path, language)
        if chunks:
            return chunks

        # Fallback: regex-based function/method detection
        return self._chunk_with_regex(source, file_path, language)

    def _chunk_with_treesitter(self, source: str, file_path: str,
                                language: str) -> List[CodeChunk]:
        """Use tree-sitter for accurate parsing."""
        try:
            import tree_sitter
            import tree_sitter_c
            import tree_sitter_python

            lang_map = {
                "python": tree_sitter_python.language(),
                "c": tree_sitter_c.language(),
                "c++": tree_sitter_c.language(),
                "php": None,
                "go": None,
                "java": None,
                "javascript": None,
                "typescript": None,
                "rust": None,
                "ruby": None,
            }

            ts_lang = lang_map.get(language.lower())
            if ts_lang is None:
                return []

            parser = tree_sitter.Parser()
            parser.set_language(ts_lang)
            tree = parser.parse(bytes(source, 'utf-8'))

            chunks = []
            self._extract_functions(tree.root_node, source, file_path, language, chunks)
            return chunks

        except ImportError:
            return []

    def _extract_functions(self, node, source, file_path, language,
                            chunks: List[CodeChunk]):
        """Recursively extract function/class/method definitions."""
        func_types = {"function_definition", "method_definition",
                       "class_definition", "function_declaration"}

        if node.type in func_types:
            name_node = node.child_by_field_name("name")
            name = name_node.text.decode() if name_node else "anonymous"
            code = source[node.start_byte:node.end_byte]
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            chunk_id = f"{file_path}:{name}:{start_line}"
            chunks.append(CodeChunk(
                chunk_id=chunk_id, file_path=file_path,
                function_name=name, start_line=start_line,
                end_line=end_line, code=code, language=language,
            ))

        for child in node.children:
            self._extract_functions(child, source, file_path, language, chunks)

    def _chunk_with_regex(self, source: str, file_path: str,
                           language: str) -> List[CodeChunk]:
        """Regex-based fallback chunking."""
        import re

        patterns = {
            "python": r'^\s*(def |class )(\w+)',
            "php": r'^\s*(function |class )(\w+)',
            "go": r'^\s*func (\w+)',
            "java": r'^\s*(public |private |protected )?(static )?(class |void |\w+ )(\w+)\(',
            "c": r'^\s*(\w+)\s+(\w+)\s*\([^)]*\)\s*\{',
            "c++": r'^\s*(\w+)\s+(\w+)::(\w+)\s*\([^)]*\)\s*\{',
            "javascript": r'^\s*(function |class |const \w+ = |let \w+ = )(?:async )?(\w+)',
            "rust": r'^\s*(pub )?fn (\w+)',
            "ruby": r'^\s*def (\w+)',
        }

        pattern = patterns.get(language.lower())
        if not pattern:
            return []

        lines = source.split('\n')
        chunks = []
        current_func = None
        current_start = 0
        brace_depth = 0
        in_function = False

        for i, line in enumerate(lines, 1):
            m = re.match(pattern, line)
            if m and not in_function:
                groups = m.groups()
                current_func = groups[-1]  # Last group is function name
                current_start = i
                in_function = True

            if in_function:
                brace_depth += line.count('{') - line.count('}')

            if in_function and brace_depth <= 0 and ('{' in line or '}' in line or not line.strip()):
                if current_func:
                    chunk_id = f"{file_path}:{current_func}:{current_start}"
                    chunk_code = '\n'.join(lines[current_start - 1:i])
                    chunks.append(CodeChunk(
                        chunk_id=chunk_id, file_path=file_path,
                        function_name=current_func, start_line=current_start,
                        end_line=i, code=chunk_code, language=language,
                    ))
                current_func = None
                in_function = False

        return chunks

    def chunk_project(self, repo_path: str, language: str,
                       file_extensions: List[str]) -> List[CodeChunk]:
        """Chunk an entire project."""
        import os
        all_chunks = []

        for root, dirs, files in os.walk(repo_path):
            # Skip hidden dirs and common non-source dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                        ('node_modules', 'vendor', '__pycache__', 'venv', '.git')]
            for f in files:
                ext = os.path.splitext(f)[1]
                if ext in file_extensions:
                    fpath = os.path.join(root, f)
                    chunks = self.chunk_file(fpath, language)
                    all_chunks.extend(chunks)

        return all_chunks
