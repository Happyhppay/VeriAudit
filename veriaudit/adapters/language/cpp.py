# VeriAudit - C/C++ Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("CMakeLists.txt", "cmake"),
    ("Makefile", "make"),
    ("configure.ac", "autotools"),
    ("configure.in", "autotools"),
    ("meson.build", "meson"),
    ("BUILD.bazel", "bazel"),
    ("WORKSPACE", "bazel"),
    ("SConstruct", "scons"),
]

_CPP_EXTENSIONS = [
    ".c", ".cc", ".cpp", ".cxx", ".c++",
    ".h", ".hh", ".hpp", ".hxx", ".h++",
    ".inc",
]


class CppAdapter(LanguageAdapter):
    """Language adapter for C and C++ projects."""

    @property
    def language_name(self) -> str:
        return "C/C++"

    @property
    def file_extensions(self) -> List[str]:
        return _CPP_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        for filename, system in _BUILD_INDICATORS:
            if os.path.isfile(os.path.join(repo_path, filename)):
                return system
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "cppcheck", "clang_tidy"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "memcpy", "category": "mem_unsafe", "severity": "high"},
            {"function": "strcpy", "category": "mem_unsafe", "severity": "high"},
            {"function": "strcat", "category": "mem_unsafe", "severity": "high"},
            {"function": "sprintf", "category": "mem_unsafe", "severity": "high"},
            {"function": "vsprintf", "category": "mem_unsafe", "severity": "high"},
            {"function": "gets", "category": "mem_unsafe", "severity": "critical"},
            {"function": "scanf", "category": "mem_unsafe", "severity": "medium"},
            {"function": "scanf_s", "category": "mem_unsafe", "severity": "medium"},
            {"function": "system", "category": "command_exec", "severity": "high"},
            {"function": "popen", "category": "command_exec", "severity": "high"},
            {"function": "execl", "category": "command_exec", "severity": "high"},
            {"function": "execle", "category": "command_exec", "severity": "high"},
            {"function": "execlp", "category": "command_exec", "severity": "high"},
            {"function": "execv", "category": "command_exec", "severity": "high"},
            {"function": "execve", "category": "command_exec", "severity": "high"},
            {"function": "execvp", "category": "command_exec", "severity": "high"},
            {"function": "malloc", "category": "mem_alloc", "severity": "low"},
            {"function": "realloc", "category": "mem_alloc", "severity": "low"},
            {"function": "free", "category": "mem_alloc", "severity": "low"},
            {"function": "read", "category": "file_ops", "severity": "medium"},
            {"function": "fread", "category": "file_ops", "severity": "medium"},
            {"function": "recv", "category": "network_input", "severity": "medium"},
            {"function": "send", "category": "network_output", "severity": "medium"},
            {"function": "recvfrom", "category": "network_input", "severity": "medium"},
            {"function": "sendto", "category": "network_output", "severity": "medium"},
            {"function": "strncpy", "category": "mem_unsafe", "severity": "medium"},
            {"function": "snprintf", "category": "format_string", "severity": "medium"},
            {"function": "fprintf", "category": "format_string", "severity": "medium"},
            {"function": "printf", "category": "format_string", "severity": "medium"},
            {"function": "mmap", "category": "mem_alloc", "severity": "low"},
            {"function": "alloca", "category": "mem_alloc", "severity": "medium"},
            {"function": "dlopen", "category": "code_eval", "severity": "high"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "memory-corruption",
            "integer-overflow",
            "format-string",
            "command-injection",
            "path-traversal",
            "hardcoded-secret",
            "race-condition",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "cli_main",
                "pattern": r"\bint\s+main\s*\(",
                "file_filter": "*.c,*.cpp,*.cc,*.cxx",
            },
            {
                "type": "cli_main",
                "pattern": r"\bvoid\s+main\s*\(",
                "file_filter": "*.c,*.cpp,*.cc,*.cxx",
            },
            {
                "type": "signal_handler",
                "pattern": r"\bsignal\s*\(\s*\w+\s*,",
                "file_filter": "*.c,*.cpp,*.cc,*.cxx",
            },
            {
                "type": "public_api",
                "pattern": r"__declspec\(dllexport\)",
                "file_filter": "*.h,*.hpp,*.hxx",
            },
            {
                "type": "public_api",
                "pattern": r"__attribute__\s*\(\s*\(\s*visibility\s*\(\"default\"\)\s*\)\s*\)",
                "file_filter": "*.h,*.hpp,*.hxx",
            },
            {
                "type": "network_listener",
                "pattern": r"\blisten\s*\(",
                "file_filter": "*.c,*.cpp,*.cc,*.cxx",
            },
            {
                "type": "network_listener",
                "pattern": r"\baccept\s*\(",
                "file_filter": "*.c,*.cpp,*.cc,*.cxx",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "joern"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        return SanitizerConfig(
            available=["asan", "ubsan", "msan"],
            compiler="clang",
            flags={
                "asan": "-fsanitize=address -fno-omit-frame-pointer -g -O1",
                "ubsan": "-fsanitize=undefined -fno-omit-frame-pointer -g -O1",
                "msan": "-fsanitize=memory -fno-omit-frame-pointer -g -O1 -fsanitize-memory-track-origins=2",
                "tsan": "-fsanitize=thread -fno-omit-frame-pointer -g -O1",
                "common": "-fno-omit-frame-pointer -g -O1 -Wall -Wextra",
            },
        )

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        harness_template = """\
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // TODO: Call target function with fuzzer data
    return 0;
}
"""
        return FuzzConfig(
            engine="libfuzzer",
            harness_template=harness_template,
            extra_flags=[
                "-fsanitize=fuzzer,address,undefined",
                "-fno-omit-frame-pointer",
                "-g",
                "-O1",
            ],
        )
