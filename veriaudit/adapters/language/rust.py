# VeriAudit - Rust Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("Cargo.toml", "cargo"),
    ("Cargo.lock", "cargo"),
]

_RUST_EXTENSIONS = [
    ".rs",
]


class RustAdapter(LanguageAdapter):
    """Language adapter for Rust projects."""

    @property
    def language_name(self) -> str:
        return "Rust"

    @property
    def file_extensions(self) -> List[str]:
        return _RUST_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        for filename, system in _BUILD_INDICATORS:
            if os.path.isfile(os.path.join(repo_path, filename)):
                return system
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "cargo-audit"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "unsafe", "category": "mem_unsafe", "severity": "high",
             "note": "unsafe block — opt-out of Rust safety guarantees"},
            {"function": "unsafe fn", "category": "mem_unsafe", "severity": "high",
             "note": "unsafe function declaration"},
            {"function": "unsafe trait", "category": "mem_unsafe", "severity": "high",
             "note": "unsafe trait declaration"},
            {"function": "unsafe impl", "category": "mem_unsafe", "severity": "high",
             "note": "unsafe trait implementation"},
            {"function": "std::mem::transmute", "category": "mem_unsafe", "severity": "critical"},
            {"function": "std::mem::transmute_copy", "category": "mem_unsafe", "severity": "critical"},
            {"function": "std::mem::zeroed", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::mem::uninitialized", "category": "mem_unsafe", "severity": "high",
             "note": "deprecated, use MaybeUninit"},
            {"function": "std::ptr::read", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::ptr::read_unaligned", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::ptr::read_volatile", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::ptr::write", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::ptr::write_unaligned", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::ptr::write_volatile", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::ptr::copy", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::ptr::copy_nonoverlapping", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::ptr::swap", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::ptr::replace", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::ptr::null", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::ptr::null_mut", "category": "mem_unsafe", "severity": "medium"},
            {"function": "std::process::Command", "category": "command_exec", "severity": "high"},
            {"function": "std::process::Command::new", "category": "command_exec", "severity": "high"},
            {"function": "std::process::Command::arg", "category": "command_exec", "severity": "medium",
             "note": "dangerous with user-controlled argument"},
            {"function": "std::process::Command::args", "category": "command_exec", "severity": "medium"},
            {"function": "std::process::Command::output", "category": "command_exec", "severity": "medium"},
            {"function": "std::fs::read", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "std::fs::write", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "std::fs::read_to_string", "category": "file_ops", "severity": "medium"},
            {"function": "std::fs::remove_file", "category": "file_ops", "severity": "medium"},
            {"function": "std::fs::remove_dir_all", "category": "file_ops", "severity": "high"},
            {"function": "std::net::TcpStream::connect", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled address (SSRF)"},
            {"function": "std::net::TcpListener::bind", "category": "network_listener", "severity": "info"},
            {"function": "std::net::UdpSocket::bind", "category": "network_listener", "severity": "info"},
            {"function": "include_str!", "category": "code_eval", "severity": "medium",
             "note": "dangerous with user-controlled path at build time"},
            {"function": "include_bytes!", "category": "code_eval", "severity": "medium"},
            {"function": "std::str::from_utf8_unchecked", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::str::from_utf8_unchecked_mut", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::slice::from_raw_parts", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::slice::from_raw_parts_mut", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::ffi::CStr::from_ptr", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::ffi::CString::from_raw", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::boxed::Box::from_raw", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::rc::Rc::from_raw", "category": "mem_unsafe", "severity": "high"},
            {"function": "std::arch::asm!", "category": "mem_unsafe", "severity": "high",
             "note": "inline assembly"},
            {"function": "extern \"C\"", "category": "code_eval", "severity": "medium",
             "note": "FFI boundary — requires careful validation"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "memory-corruption",
            "command-injection",
            "path-traversal",
            "hardcoded-secret",
            "race-condition",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "cli_main",
                "pattern": r"\bfn\s+main\s*\(",
                "file_filter": "*.rs",
            },
            {
                "type": "tokio_main",
                "pattern": r"#\[tokio::main\]",
                "file_filter": "*.rs",
            },
            {
                "type": "actix_main",
                "pattern": r"#\[actix_web::main\]",
                "file_filter": "*.rs",
            },
            {
                "type": "actix_main",
                "pattern": r"#\[actix_rt::main\]",
                "file_filter": "*.rs",
            },
            {
                "type": "rocket_launch",
                "pattern": r"#\[rocket::launch\]",
                "file_filter": "*.rs",
            },
            {
                "type": "rocket_launch",
                "pattern": r"#\[rocket::main\]",
                "file_filter": "*.rs",
            },
            {
                "type": "rocket_launch",
                "pattern": r"#\[launch\]",
                "file_filter": "*.rs",
            },
            {
                "type": "axum_route",
                "pattern": r"axum::Router::new\s*\(",
                "file_filter": "*.rs",
            },
            {
                "type": "axum_route",
                "pattern": r"\.route\s*\(",
                "file_filter": "*.rs",
            },
            {
                "type": "warp_route",
                "pattern": r"warp::path\s*\(",
                "file_filter": "*.rs",
            },
            {
                "type": "warp_route",
                "pattern": r"warp::get\s*\(",
                "file_filter": "*.rs",
            },
            {
                "type": "warp_route",
                "pattern": r"warp::post\s*\(",
                "file_filter": "*.rs",
            },
            {
                "type": "network_listener",
                "pattern": r"TcpListener::bind\s*\(",
                "file_filter": "*.rs",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "codeql"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        # Rust is memory-safe by default. Sanitizers are only useful
        # for code in unsafe blocks — static analysis should flag those.
        return None

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        harness_template = """\
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: Call target function with fuzzer data
});
"""
        return FuzzConfig(
            engine="cargo-fuzz",
            harness_template=harness_template,
            extra_flags=[
                "-Zsanitizer=address",
                "--cfg=fuzzing",
            ],
        )
