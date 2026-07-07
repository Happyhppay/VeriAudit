# VeriAudit - Go Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("go.mod", "go_modules"),
    ("go.sum", "go_modules"),
]

_GO_EXTENSIONS = [
    ".go",
]


class GoAdapter(LanguageAdapter):
    """Language adapter for Go projects."""

    @property
    def language_name(self) -> str:
        return "Go"

    @property
    def file_extensions(self) -> List[str]:
        return _GO_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        for filename, system in _BUILD_INDICATORS:
            if os.path.isfile(os.path.join(repo_path, filename)):
                return system
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "staticcheck", "govulncheck"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "os/exec.Command", "category": "command_exec", "severity": "high"},
            {"function": "os/exec.CommandContext", "category": "command_exec", "severity": "high"},
            {"function": "os.Open", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "os.OpenFile", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "os.Create", "category": "file_ops", "severity": "medium"},
            {"function": "os.ReadFile", "category": "file_ops", "severity": "medium"},
            {"function": "net/http.HandleFunc", "category": "network_input", "severity": "info"},
            {"function": "database/sql.Query", "category": "sql_exec", "severity": "medium",
             "note": "dangerous with fmt.Sprintf"},
            {"function": "database/sql.QueryRow", "category": "sql_exec", "severity": "medium"},
            {"function": "database/sql.Exec", "category": "sql_exec", "severity": "medium"},
            {"function": "unsafe.Pointer", "category": "mem_unsafe", "severity": "high"},
            {"function": "unsafe.Slice", "category": "mem_unsafe", "severity": "medium"},
            {"function": "unsafe.Add", "category": "mem_unsafe", "severity": "medium"},
            {"function": "unsafe.String", "category": "mem_unsafe", "severity": "medium"},
            {"function": "unsafe.StringData", "category": "mem_unsafe", "severity": "medium"},
            {"function": "syscall.Syscall", "category": "syscall", "severity": "high"},
            {"function": "syscall.RawSyscall", "category": "syscall", "severity": "high"},
            {"function": "syscall.Exec", "category": "command_exec", "severity": "high"},
            {"function": "cgo", "category": "code_eval", "severity": "medium",
             "note": "CGo interop introduces memory safety risks"},
            {"function": "net.Listen", "category": "network_listener", "severity": "info"},
            {"function": "net.ListenUDP", "category": "network_listener", "severity": "info"},
            {"function": "net/http.Get", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL (SSRF)"},
            {"function": "net/http.Post", "category": "network_output", "severity": "medium"},
            {"function": "net/http.NewRequest", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL"},
            {"function": "io/ioutil.ReadFile", "category": "file_ops", "severity": "medium"},
            {"function": "io/ioutil.ReadDir", "category": "file_ops", "severity": "medium"},
            {"function": "text/template.Execute", "category": "code_eval", "severity": "medium",
             "note": "dangerous with user-controlled template content"},
            {"function": "html/template.HTML", "category": "xss", "severity": "high"},
            {"function": "html/template.JS", "category": "xss", "severity": "high"},
            {"function": "encoding/gob.NewDecoder", "category": "deserialization", "severity": "medium"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "command-injection",
            "sql-injection",
            "path-traversal",
            "hardcoded-secret",
            "ssrf",
            "race-condition",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "cli_main",
                "pattern": r"\bfunc\s+main\s*\(\s*\)",
                "file_filter": "*.go",
            },
            {
                "type": "http_handler",
                "pattern": r"http\.HandleFunc\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "http_handler",
                "pattern": r"http\.Handle\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "grpc_server",
                "pattern": r"grpc\.NewServer\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "grpc_server",
                "pattern": r"pb\.Register\w+Server\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "network_listener",
                "pattern": r"net\.Listen\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "http_handler",
                "pattern": r"mux\.HandleFunc\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "http_handler",
                "pattern": r"gin\.GET\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "http_handler",
                "pattern": r"gin\.POST\s*\(",
                "file_filter": "*.go",
            },
            {
                "type": "http_handler",
                "pattern": r"echo\.GET\s*\(",
                "file_filter": "*.go",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "codeql"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        return SanitizerConfig(
            available=["race"],
            compiler="go",
            flags={
                "race": "-race",
                "common": "-buildmode=pie -trimpath",
            },
        )

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        harness_template = """\
package main

import (
    "testing"
)

func FuzzTarget(f *testing.F) {
    f.Add([]byte("initial seed"))
    f.Fuzz(func(t *testing.T, data []byte) {
        // TODO: Call target function with fuzzer data
    })
)
"""
        return FuzzConfig(
            engine="go-fuzz",
            harness_template=harness_template,
            extra_flags=["-fuzztime=30s"],
        )
