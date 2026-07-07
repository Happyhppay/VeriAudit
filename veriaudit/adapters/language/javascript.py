# VeriAudit - JavaScript/TypeScript Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
    ("package.json", "npm"),
    ("bun.lockb", "bun"),
]

_JS_TS_EXTENSIONS = [
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".mts", ".cts",
]


class JsTsAdapter(LanguageAdapter):
    """Language adapter for JavaScript and TypeScript projects."""

    @property
    def language_name(self) -> str:
        return "JavaScript/TypeScript"

    @property
    def file_extensions(self) -> List[str]:
        return _JS_TS_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        # Check lock files first for more specific detection
        if os.path.isfile(os.path.join(repo_path, "pnpm-lock.yaml")):
            return "pnpm"
        if os.path.isfile(os.path.join(repo_path, "yarn.lock")):
            return "yarn"
        if os.path.isfile(os.path.join(repo_path, "bun.lockb")):
            return "bun"
        if os.path.isfile(os.path.join(repo_path, "package.json")):
            return "npm"
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "eslint"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "eval", "category": "code_eval", "severity": "critical"},
            {"function": "Function", "category": "code_eval", "severity": "high",
             "note": "new Function() constructor"},
            {"function": "child_process.exec", "category": "command_exec", "severity": "high"},
            {"function": "child_process.execSync", "category": "command_exec", "severity": "high"},
            {"function": "child_process.execFile", "category": "command_exec", "severity": "high"},
            {"function": "child_process.execFileSync", "category": "command_exec", "severity": "high"},
            {"function": "child_process.spawn", "category": "command_exec", "severity": "high",
             "note": "dangerous with user-controlled arguments"},
            {"function": "child_process.spawnSync", "category": "command_exec", "severity": "high"},
            {"function": "child_process.fork", "category": "command_exec", "severity": "medium"},
            {"function": "document.write", "category": "xss", "severity": "medium"},
            {"function": "document.writeln", "category": "xss", "severity": "medium"},
            {"function": "element.innerHTML", "category": "xss", "severity": "high"},
            {"function": "element.outerHTML", "category": "xss", "severity": "high"},
            {"function": "element.insertAdjacentHTML", "category": "xss", "severity": "high"},
            {"function": "location.href", "category": "open_redirect", "severity": "medium",
             "note": "dangerous when set to user-controlled value"},
            {"function": "location.assign", "category": "open_redirect", "severity": "medium"},
            {"function": "location.replace", "category": "open_redirect", "severity": "medium"},
            {"function": "localStorage.setItem", "category": "insecure_storage", "severity": "low"},
            {"function": "sessionStorage.setItem", "category": "insecure_storage", "severity": "low"},
            {"function": "document.cookie", "category": "insecure_storage", "severity": "low",
             "note": "dangerous without HttpOnly/Secure flags"},
            {"function": "fetch", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL"},
            {"function": "XMLHttpRequest.open", "category": "network_output", "severity": "medium"},
            {"function": "XMLHttpRequest.send", "category": "network_output", "severity": "medium"},
            {"function": "axios.get", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL"},
            {"function": "axios.post", "category": "network_output", "severity": "medium"},
            {"function": "axios.request", "category": "network_output", "severity": "medium"},
            {"function": "require", "category": "code_eval", "severity": "medium",
             "note": "dangerous with user-controlled path in Node.js"},
            {"function": "import", "category": "code_eval", "severity": "medium",
             "note": "dynamic import with user-controlled path"},
            {"function": "vm.runInNewContext", "category": "code_eval", "severity": "high"},
            {"function": "vm.runInThisContext", "category": "code_eval", "severity": "high"},
            {"function": "vm.compileFunction", "category": "code_eval", "severity": "medium"},
            {"function": "vm.Script", "category": "code_eval", "severity": "high"},
            {"function": "new WebSocket", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL"},
            {"function": "setTimeout", "category": "code_eval", "severity": "medium",
             "note": "dangerous with string argument"},
            {"function": "setInterval", "category": "code_eval", "severity": "medium",
             "note": "dangerous with string argument"},
            {"function": "JSON.parse", "category": "deserialization", "severity": "low",
             "note": "generally safe, flag for large untrusted payloads"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "command-injection",
            "path-traversal",
            "hardcoded-secret",
            "xss",
            "ssrf",
            "deserialization",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "express_route",
                "pattern": r"app\.get\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "express_route",
                "pattern": r"app\.post\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "express_route",
                "pattern": r"app\.put\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "express_route",
                "pattern": r"app\.delete\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "express_route",
                "pattern": r"app\.patch\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "express_route",
                "pattern": r"router\.get\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "express_route",
                "pattern": r"router\.post\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "module_export",
                "pattern": r"module\.exports\s*=",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "module_export",
                "pattern": r"export\s+default\s+function\b",
                "file_filter": "*.js,*.ts,*.jsx,*.tsx,.mjs,.cjs,.mts,.cts",
            },
            {
                "type": "module_export",
                "pattern": r"export\s+default\s+class\b",
                "file_filter": "*.js,*.ts,*.jsx,*.tsx,.mjs,.cjs,.mts,.cts",
            },
            {
                "type": "network_listener",
                "pattern": r"\.listen\s*\(",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "lambda_handler",
                "pattern": r"exports\.handler\s*=",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
            {
                "type": "lambda_handler",
                "pattern": r"export\s+const\s+handler\s*=",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs,.mts,.cts",
            },
            {
                "type": "nextjs_route",
                "pattern": r"export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\b",
                "file_filter": "*.ts,*.tsx,.mts,.cts",
            },
            {
                "type": "cli_main",
                "pattern": r"#!/usr/bin/env\s+node",
                "file_filter": "*.js,*.ts,*.mjs,*.cjs",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "codeql"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        return None

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        harness_template = """\
const fuzz = require('jsfuzz');

function fuzzTarget(data) {
    // TODO: Call target function with fuzzer data
}

fuzz.run(fuzzTarget);
"""
        return FuzzConfig(
            engine="jsfuzz",
            harness_template=harness_template,
            extra_flags=[],
        )
