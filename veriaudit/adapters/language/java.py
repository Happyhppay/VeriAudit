# VeriAudit - Java Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("pom.xml", "maven"),
    ("build.gradle.kts", "gradle"),
    ("build.gradle", "gradle"),
    ("settings.gradle", "gradle"),
    ("settings.gradle.kts", "gradle"),
]

_JAVA_EXTENSIONS = [
    ".java", ".kt", ".kts", ".scala",
]


class JavaAdapter(LanguageAdapter):
    """Language adapter for Java / Kotlin / Scala projects."""

    @property
    def language_name(self) -> str:
        return "Java"

    @property
    def file_extensions(self) -> List[str]:
        return _JAVA_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        # Prefer pom.xml for maven, but check gradle first since
        # multi-module projects can have both
        if os.path.isfile(os.path.join(repo_path, "build.gradle.kts")):
            return "gradle"
        if os.path.isfile(os.path.join(repo_path, "build.gradle")):
            return "gradle"
        for filename, system in _BUILD_INDICATORS:
            if os.path.isfile(os.path.join(repo_path, filename)):
                return system
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "spotbugs"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "java.lang.Runtime.exec", "category": "command_exec", "severity": "high"},
            {"function": "java.lang.ProcessBuilder", "category": "command_exec", "severity": "high"},
            {"function": "java.lang.ProcessBuilder.start", "category": "command_exec", "severity": "high"},
            {"function": "java.sql.Statement.executeQuery", "category": "sql_exec", "severity": "high",
             "note": "dangerous with string concatenation"},
            {"function": "java.sql.Statement.execute", "category": "sql_exec", "severity": "high"},
            {"function": "java.sql.Statement.executeUpdate", "category": "sql_exec", "severity": "high"},
            {"function": "java.sql.Statement.addBatch", "category": "sql_exec", "severity": "medium"},
            {"function": "java.net.URL.openConnection", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL (SSRF)"},
            {"function": "java.net.URL.openStream", "category": "network_output", "severity": "medium"},
            {"function": "java.io.ObjectInputStream", "category": "deserialization", "severity": "high"},
            {"function": "java.io.ObjectInputStream.readObject", "category": "deserialization", "severity": "high"},
            {"function": "javax.xml.parsers.DocumentBuilder.parse", "category": "xxe", "severity": "high",
             "note": "dangerous with external entities enabled"},
            {"function": "javax.xml.parsers.SAXParser.parse", "category": "xxe", "severity": "high"},
            {"function": "javax.xml.transform.TransformerFactory.newInstance", "category": "xxe", "severity": "medium"},
            {"function": "javax.script.ScriptEngine.eval", "category": "code_eval", "severity": "critical"},
            {"function": "javax.script.ScriptEngineManager.getEngineByName", "category": "code_eval", "severity": "medium"},
            {"function": "java.io.FileOutputStream", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "java.io.FileWriter", "category": "file_ops", "severity": "medium"},
            {"function": "java.nio.file.Files.write", "category": "file_ops", "severity": "medium"},
            {"function": "java.nio.file.Files.newOutputStream", "category": "file_ops", "severity": "medium"},
            {"function": "java.nio.file.Files.delete", "category": "file_ops", "severity": "medium"},
            {"function": "org.springframework.web.client.RestTemplate.exchange", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL"},
            {"function": "org.springframework.web.client.RestTemplate.getForObject", "category": "network_output", "severity": "medium"},
            {"function": "java.lang.Class.forName", "category": "code_eval", "severity": "medium"},
            {"function": "java.lang.reflect.Method.invoke", "category": "code_eval", "severity": "high"},
            {"function": "org.yaml.snakeyaml.Yaml.load", "category": "deserialization", "severity": "high"},
            {"function": "com.fasterxml.jackson.databind.ObjectMapper.readValue", "category": "deserialization", "severity": "medium",
             "note": "dangerous with default typing enabled"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "command-injection",
            "sql-injection",
            "path-traversal",
            "hardcoded-secret",
            "ssrf",
            "deserialization",
            "xxe",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "cli_main",
                "pattern": r"public\s+static\s+void\s+main\s*\(",
                "file_filter": "*.java,*.kt,*.scala",
            },
            {
                "type": "rest_controller",
                "pattern": r"@RestController\b",
                "file_filter": "*.java,*.kt,*.scala",
            },
            {
                "type": "rest_endpoint",
                "pattern": r"@GetMapping\s*\(",
                "file_filter": "*.java,*.kt,*.scala",
            },
            {
                "type": "rest_endpoint",
                "pattern": r"@PostMapping\s*\(",
                "file_filter": "*.java,*.kt,*.scala",
            },
            {
                "type": "rest_endpoint",
                "pattern": r"@PutMapping\s*\(",
                "file_filter": "*.java,*.kt,*.scala",
            },
            {
                "type": "rest_endpoint",
                "pattern": r"@DeleteMapping\s*\(",
                "file_filter": "*.java,*.kt,*.scala",
            },
            {
                "type": "rest_endpoint",
                "pattern": r"@RequestMapping\s*\(",
                "file_filter": "*.java,*.kt,*.scala",
            },
            {
                "type": "jaxrs_endpoint",
                "pattern": r"javax\.ws\.rs\.GET\b",
                "file_filter": "*.java,*.kt",
            },
            {
                "type": "jaxrs_endpoint",
                "pattern": r"javax\.ws\.rs\.POST\b",
                "file_filter": "*.java,*.kt",
            },
            {
                "type": "jaxrs_endpoint",
                "pattern": r"jakarta\.ws\.rs\.GET\b",
                "file_filter": "*.java,*.kt",
            },
            {
                "type": "servlet_handler",
                "pattern": r"doGet\s*\(",
                "file_filter": "*.java",
            },
            {
                "type": "servlet_handler",
                "pattern": r"doPost\s*\(",
                "file_filter": "*.java",
            },
            {
                "type": "servlet_handler",
                "pattern": r"HttpServlet\b",
                "file_filter": "*.java",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "codeql"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        return None

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        harness_template = """\
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class FuzzTarget {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // TODO: Call target function with fuzzer data
    }
}
"""
        return FuzzConfig(
            engine="jazzer",
            harness_template=harness_template,
            extra_flags=["--keep-going"],
        )
