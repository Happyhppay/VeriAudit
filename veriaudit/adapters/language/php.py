# VeriAudit - PHP Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("composer.json", "composer"),
    ("composer.lock", "composer"),
]

_PHP_EXTENSIONS = [
    ".php", ".phtml", ".inc", ".php4", ".php5",
    ".phar", ".phps",
]


class PhpAdapter(LanguageAdapter):
    """Language adapter for PHP projects."""

    @property
    def language_name(self) -> str:
        return "PHP"

    @property
    def file_extensions(self) -> List[str]:
        return _PHP_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        for filename, system in _BUILD_INDICATORS:
            if os.path.isfile(os.path.join(repo_path, filename)):
                return system
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "psalm"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "system", "category": "command_exec", "severity": "high"},
            {"function": "exec", "category": "command_exec", "severity": "high"},
            {"function": "shell_exec", "category": "command_exec", "severity": "high"},
            {"function": "passthru", "category": "command_exec", "severity": "high"},
            {"function": "popen", "category": "command_exec", "severity": "high"},
            {"function": "proc_open", "category": "command_exec", "severity": "high"},
            {"function": "pcntl_exec", "category": "command_exec", "severity": "high"},
            {"function": "eval", "category": "code_eval", "severity": "critical"},
            {"function": "assert", "category": "code_eval", "severity": "high"},
            {"function": "create_function", "category": "code_eval", "severity": "high"},
            {"function": "preg_replace", "category": "code_eval", "severity": "high",
             "note": "dangerous with /e modifier"},
            {"function": "include", "category": "code_eval", "severity": "high",
             "note": "dangerous with variable argument"},
            {"function": "require", "category": "code_eval", "severity": "high",
             "note": "dangerous with variable argument"},
            {"function": "include_once", "category": "code_eval", "severity": "medium"},
            {"function": "require_once", "category": "code_eval", "severity": "medium"},
            {"function": "unserialize", "category": "deserialization", "severity": "high"},
            {"function": "extract", "category": "variable_taint", "severity": "medium"},
            {"function": "parse_str", "category": "variable_taint", "severity": "medium"},
            {"function": "mysql_query", "category": "sql_exec", "severity": "high"},
            {"function": "mysqli_query", "category": "sql_exec", "severity": "high"},
            {"function": "pg_query", "category": "sql_exec", "severity": "high"},
            {"function": "mssql_query", "category": "sql_exec", "severity": "high"},
            {"function": "sqlsrv_query", "category": "sql_exec", "severity": "high"},
            {"function": "file_get_contents", "category": "file_ops", "severity": "medium",
             "note": "dangerous with remote URL"},
            {"function": "curl_exec", "category": "network_output", "severity": "medium"},
            {"function": "curl_multi_exec", "category": "network_output", "severity": "medium"},
            {"function": "ReflectionMethod", "category": "code_eval", "severity": "medium",
             "note": "dangerous with invoke() on user-controlled method"},
            {"function": "call_user_func", "category": "code_eval", "severity": "high"},
            {"function": "call_user_func_array", "category": "code_eval", "severity": "high"},
            {"function": "fopen", "category": "file_ops", "severity": "medium",
             "note": "dangerous with remote URL"},
            {"function": "move_uploaded_file", "category": "file_ops", "severity": "medium"},
            {"function": "copy", "category": "file_ops", "severity": "medium"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "command-injection",
            "sql-injection",
            "path-traversal",
            "hardcoded-secret",
            "xss",
            "ssrf",
            "deserialization",
            "xxe",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "web_entry",
                "pattern": "index.php",
                "file_filter": "index.php",
            },
            {
                "type": "web_entry",
                "pattern": "index.phtml",
                "file_filter": "index.phtml",
            },
            {
                "type": "route_file",
                "pattern": r"routes/.*\.php",
                "file_filter": "routes/*.php",
            },
            {
                "type": "http_handler",
                "pattern": r"public/index\.php",
                "file_filter": "public/index.php",
            },
            {
                "type": "api_endpoint",
                "pattern": r"api/.*\.php",
                "file_filter": "api/*.php",
            },
            {
                "type": "http_handler",
                "pattern": r"app\.php",
                "file_filter": "app.php",
            },
            {
                "type": "http_handler",
                "pattern": r"\b\$_GET\b",
                "file_filter": "*.php,*.phtml,*.inc",
            },
            {
                "type": "http_handler",
                "pattern": r"\b\$_POST\b",
                "file_filter": "*.php,*.phtml,*.inc",
            },
            {
                "type": "http_handler",
                "pattern": r"\b\$_REQUEST\b",
                "file_filter": "*.php,*.phtml,*.inc",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "psalm"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        return None

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        return None
